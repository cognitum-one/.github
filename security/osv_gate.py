#!/usr/bin/env python3
"""Fail closed on shippable High/Critical OSV findings.

The only database correction is an organization-owned, expiring exception for
GHSA-qwww-vcr4-c8h2 at React Router 7.18.2. The upstream maintainer advisory
lists 7.18.2 as patched, while the current OSV range incorrectly spans it.
"""

from __future__ import annotations

import datetime as dt
import json
import os
from pathlib import Path
import sys
from typing import Any

ROUTER_ADVISORY = "GHSA-qwww-vcr4-c8h2"
ROUTER_VERSION = "7.18.2"
ROUTER_EXCEPTION_EXPIRES = dt.date(2026, 8, 15)
ROUTER_LOCKS = {
    ("cognitum-one/management", "management-ui/package-lock.json"),
    ("cognitum-one/website", "package-lock.json"),
}


def _relative_source(source: str, root: Path) -> str | None:
    try:
        return Path(source).resolve().relative_to(root.resolve()).as_posix()
    except (OSError, ValueError):
        return None


def _read_lock(source: str) -> dict[str, Any] | None:
    try:
        value = json.loads(Path(source).read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return None
    return value if isinstance(value, dict) else None


def dev_only_pairs(lock_path: str) -> set[tuple[str, str]]:
    lock = _read_lock(lock_path)
    if lock is None:
        return set()
    out: dict[tuple[str, str], bool] = {}
    packages = lock.get("packages")
    if not isinstance(packages, dict):
        return set()
    for package_path, metadata in packages.items():
        if not package_path or not isinstance(metadata, dict):
            continue
        name = metadata.get("name") or package_path.split("node_modules/")[-1]
        version = metadata.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            continue
        dev_only = bool(metadata.get("dev") or metadata.get("devOptional"))
        key = (name, version)
        out[key] = dev_only and out.get(key, True)
    return {key for key, is_dev_only in out.items() if is_dev_only}


def reviewed_router_false_positive(
    *,
    repository: str,
    source: str,
    root: Path,
    package: str,
    version: str,
    advisory: str,
    today: dt.date,
) -> bool:
    relative = _relative_source(source, root)
    if (
        today >= ROUTER_EXCEPTION_EXPIRES
        or (repository, relative or "") not in ROUTER_LOCKS
        or package != "react-router"
        or version != ROUTER_VERSION
        or advisory != ROUTER_ADVISORY
    ):
        return False

    lock = _read_lock(source)
    packages = lock.get("packages") if lock else None
    if not isinstance(packages, dict):
        return False
    root_package = packages.get("")
    router = packages.get("node_modules/react-router")
    router_dom = packages.get("node_modules/react-router-dom")
    if not all(isinstance(item, dict) for item in (root_package, router, router_dom)):
        return False
    dependencies = root_package.get("dependencies")
    return (
        isinstance(dependencies, dict)
        and dependencies.get("react-router-dom") == ROUTER_VERSION
        and router.get("version") == ROUTER_VERSION
        and router_dom.get("version") == ROUTER_VERSION
    )


def evaluate(
    report: dict[str, Any],
    *,
    repository: str,
    root: Path,
    today: dt.date,
) -> tuple[list[tuple[str, str, str, float, str]], ...]:
    results = report.get("results")
    if not isinstance(results, list):
        raise ValueError("OSV JSON does not contain a results array")

    blocking: list[tuple[str, str, str, float, str]] = []
    dev_only: list[tuple[str, str, str, float, str]] = []
    reviewed: list[tuple[str, str, str, float, str]] = []
    for result in results:
        if not isinstance(result, dict):
            raise ValueError("OSV result is not an object")
        source = ((result.get("source") or {}).get("path")) or ""
        if not isinstance(source, str):
            raise ValueError("OSV source path is not a string")
        excused = dev_only_pairs(source) if source.endswith("package-lock.json") else set()
        packages = result.get("packages")
        if not isinstance(packages, list):
            raise ValueError("OSV result packages is not an array")
        for package_record in packages:
            if not isinstance(package_record, dict):
                raise ValueError("OSV package record is not an object")
            package_identity = package_record.get("package")
            if not isinstance(package_identity, dict):
                raise ValueError("OSV package identity is missing")
            name = package_identity.get("name")
            version = package_identity.get("version")
            if not isinstance(name, str) or not isinstance(version, str):
                raise ValueError("OSV package name/version is invalid")
            severity: dict[str, str] = {}
            for group in package_record.get("groups") or []:
                if not isinstance(group, dict):
                    continue
                for advisory in group.get("ids") or []:
                    if isinstance(advisory, str):
                        severity[advisory] = group.get("max_severity") or "0"
            vulnerabilities = package_record.get("vulnerabilities")
            if not isinstance(vulnerabilities, list):
                raise ValueError("OSV vulnerabilities is not an array")
            for vulnerability in vulnerabilities:
                if not isinstance(vulnerability, dict):
                    raise ValueError("OSV vulnerability is not an object")
                advisory = vulnerability.get("id")
                if not isinstance(advisory, str):
                    raise ValueError("OSV advisory id is invalid")
                fixed = any(
                    isinstance(event, dict) and "fixed" in event
                    for affected in vulnerability.get("affected") or []
                    if isinstance(affected, dict)
                    for range_record in affected.get("ranges") or []
                    if isinstance(range_record, dict)
                    for event in range_record.get("events") or []
                )
                try:
                    score = float(severity.get(advisory, "0") or 0)
                except (TypeError, ValueError):
                    score = 0.0
                if not (fixed and score >= 7.0):
                    continue
                row = (name, version, advisory, score, source)
                if reviewed_router_false_positive(
                    repository=repository,
                    source=source,
                    root=root,
                    package=name,
                    version=version,
                    advisory=advisory,
                    today=today,
                ):
                    reviewed.append(row)
                elif (name, version) in excused:
                    dev_only.append(row)
                else:
                    blocking.append(row)
    return blocking, dev_only, reviewed


def _format(rows: list[tuple[str, str, str, float, str]]) -> list[str]:
    return [
        "  CVSS %.1f  %s@%s  %s  (%s)" % (score, name, version, advisory, source or "?")
        for name, version, advisory, score, source in sorted(rows, key=lambda row: -row[3])
    ]


def main() -> int:
    report_path = Path(os.environ.get("OSV_REPORT", "osv.json"))
    root = Path(os.environ.get("OSV_REPOSITORY_ROOT", ".")).resolve()
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
        if not isinstance(report, dict):
            raise ValueError("OSV report root is not an object")
        blocking, dev_only, reviewed = evaluate(
            report,
            repository=repository,
            root=root,
            today=dt.datetime.now(dt.timezone.utc).date(),
        )
    except (OSError, ValueError, TypeError) as error:
        print(f"::error::OSV JSON is missing, malformed, or unsafe: {error}")
        return 2

    if reviewed:
        print(
            "::warning::Reviewed OSV range correction applied to "
            f"{len(reviewed)} exact React Router 7.18.2 finding(s); "
            f"expires {ROUTER_EXCEPTION_EXPIRES.isoformat()}:"
        )
        for line in _format(reviewed):
            print(line)
    if dev_only:
        print(
            "::warning::%d High/Critical fixable vulnerability(ies) in DEV-ONLY "
            "dependencies (not shipped; not blocking):" % len(dev_only)
        )
        for line in _format(dev_only):
            print(line)
    if blocking:
        print(f"::error::{len(blocking)} High/Critical vulnerabilities WITH fixes available:")
        for line in _format(blocking):
            print(line)
        return 1
    print("OK: no unreviewed shippable High/Critical fixable vulnerabilities.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
