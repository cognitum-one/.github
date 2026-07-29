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
import re
import sys
from typing import Any

ROUTER_ADVISORY = "GHSA-qwww-vcr4-c8h2"
ROUTER_VERSION = "7.18.2"
ROUTER_EXCEPTION_EXPIRES = dt.date(2026, 8, 15)
ROUTER_LOCKS = {
    ("cognitum-one/management", "management-ui/package-lock.json"),
    ("cognitum-one/website", "package-lock.json"),
}
ROUTER_PROFILES = {
    ("cognitum-one/management", "management-ui/package-lock.json"): {
        "manifest": "management-ui/package.json",
        "source": ("management-ui/src",),
        "config": ("management-ui/vite.config.ts",),
    },
    ("cognitum-one/website", "package-lock.json"): {
        "manifest": "package.json",
        "source": ("src",),
        "config": ("vite.config.ts",),
    },
}
PROHIBITED_RSC_DEPENDENCIES = {
    "@react-router/dev",
    "@react-router/node",
    "@react-router/serve",
    "react-server-dom-parcel",
    "react-server-dom-turbopack",
    "react-server-dom-webpack",
}
SHIPPED_SOURCE_EXTENSIONS = {
    ".cjs",
    ".cts",
    ".js",
    ".jsx",
    ".mjs",
    ".mts",
    ".ts",
    ".tsx",
}
RSC_SOURCE_PATTERN = re.compile(
    r"(?:\bunstable_(?:matchRSCServerRequest|createCallServer|getRSCStream|RSC[A-Za-z0-9_]*)\b"
    r"|react-router/dom|react-server-dom-[A-Za-z0-9_-]+|[\"']react-server[\"'])"
)
RSC_SCRIPT_PATTERN = re.compile(
    r"(?:--conditions(?:=|\s+)react-server|(?:^|\s)react-router\s+(?:build|dev|serve)(?:\s|$))"
)
MAX_REVIEWED_SOURCE_BYTES = 32 * 1024 * 1024
MAX_REVIEWED_FILE_BYTES = 2 * 1024 * 1024


def _relative_source(source: str, root: Path) -> str | None:
    try:
        return Path(source).resolve().relative_to(root.resolve()).as_posix()
    except (OSError, ValueError):
        return None


def _strict_json_loads(source: str) -> Any:
    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate JSON key: {key}")
            value[key] = item
        return value

    return json.loads(source, object_pairs_hook=object_pairs)


def _read_lock(source: str) -> dict[str, Any] | None:
    try:
        value = _strict_json_loads(Path(source).read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return None
    return value if isinstance(value, dict) else None


def _safe_profile_path(root: Path, relative: str) -> Path | None:
    candidate = root / relative
    try:
        current = root
        for part in Path(relative).parts:
            current /= part
            if current.is_symlink():
                return None
        candidate.resolve().relative_to(root.resolve())
    except (OSError, ValueError):
        return None
    return candidate


def _read_profile_json(root: Path, relative: str) -> dict[str, Any] | None:
    path = _safe_profile_path(root, relative)
    if path is None or not path.is_file():
        return None
    return _read_lock(str(path))


def _has_reviewed_spa_surface(
    *,
    repository: str,
    relative_lock: str,
    root: Path,
) -> bool:
    profile = ROUTER_PROFILES.get((repository, relative_lock))
    if profile is None:
        return False
    manifest = _read_profile_json(root, profile["manifest"])
    lock = _read_profile_json(root, relative_lock)
    if manifest is None or lock is None:
        return False

    dependency_groups = (
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    )
    dependencies = manifest.get("dependencies")
    if (
        not isinstance(dependencies, dict)
        or dependencies.get("react-router-dom") != ROUTER_VERSION
    ):
        return False
    for group_name in dependency_groups:
        group = manifest.get(group_name, {})
        if not isinstance(group, dict):
            return False
        if any(name in group for name in PROHIBITED_RSC_DEPENDENCIES):
            return False
        if "react-router" in group:
            return False
        if group_name != "dependencies" and "react-router-dom" in group:
            return False

    scripts = manifest.get("scripts", {})
    if not isinstance(scripts, dict) or any(
        not isinstance(script, str) or RSC_SCRIPT_PATTERN.search(script)
        for script in scripts.values()
    ):
        return False

    packages = lock.get("packages")
    if not isinstance(packages, dict):
        return False
    root_package = packages.get("")
    router = packages.get("node_modules/react-router")
    router_dom = packages.get("node_modules/react-router-dom")
    if not all(isinstance(item, dict) for item in (root_package, router, router_dom)):
        return False
    root_dependencies = root_package.get("dependencies")
    dom_dependencies = router_dom.get("dependencies")
    if (
        not isinstance(root_dependencies, dict)
        or root_dependencies.get("react-router-dom") != ROUTER_VERSION
        or router.get("version") != ROUTER_VERSION
        or router_dom.get("version") != ROUTER_VERSION
        or not isinstance(dom_dependencies, dict)
        or dom_dependencies.get("react-router") != ROUTER_VERSION
    ):
        return False
    router_nodes = []
    router_dom_nodes = []
    for package_path, metadata in packages.items():
        if not isinstance(package_path, str) or not isinstance(metadata, dict):
            return False
        package_name = metadata.get("name")
        if not isinstance(package_name, str):
            package_name = package_path.split("node_modules/")[-1]
        if package_name in PROHIBITED_RSC_DEPENDENCIES:
            return False
        if package_name == "react-router":
            router_nodes.append(package_path)
        elif package_name == "react-router-dom":
            router_dom_nodes.append(package_path)
    if router_nodes != ["node_modules/react-router"] or router_dom_nodes != [
        "node_modules/react-router-dom"
    ]:
        return False

    files: list[Path] = []
    for relative_source in profile["source"]:
        source_root = _safe_profile_path(root, relative_source)
        if source_root is None or not source_root.is_dir():
            return False
        try:
            for path in source_root.rglob("*"):
                if path.is_symlink():
                    return False
                if path.is_file() and path.suffix in SHIPPED_SOURCE_EXTENSIONS:
                    files.append(path)
        except OSError:
            return False
    for relative_config in profile["config"]:
        config = _safe_profile_path(root, relative_config)
        if config is None or not config.is_file():
            return False
        files.append(config)

    total_bytes = 0
    try:
        for path in files:
            size = path.stat().st_size
            total_bytes += size
            if size > MAX_REVIEWED_FILE_BYTES or total_bytes > MAX_REVIEWED_SOURCE_BYTES:
                return False
            if RSC_SOURCE_PATTERN.search(path.read_text(encoding="utf-8")):
                return False
    except (OSError, UnicodeError):
        return False
    return True


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
        or not _has_reviewed_spa_surface(
            repository=repository,
            relative_lock=relative or "",
            root=root,
        )
    ):
        return False
    return True


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
    reviewed: list[tuple[str, str, str, float, str]] = []
    for result in results:
        if not isinstance(result, dict):
            raise ValueError("OSV result is not an object")
        source = ((result.get("source") or {}).get("path")) or ""
        if not isinstance(source, str):
            raise ValueError("OSV source path is not a string")
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
            severity: dict[str, list[float]] = {}
            for group in package_record.get("groups") or []:
                if not isinstance(group, dict):
                    continue
                for advisory in group.get("ids") or []:
                    if isinstance(advisory, str):
                        try:
                            score = float(group.get("max_severity"))
                        except (TypeError, ValueError):
                            raise ValueError(
                                f"OSV severity is missing or invalid for {advisory}"
                            )
                        severity.setdefault(advisory, []).append(score)
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
                advisory_scores = severity.get(advisory)
                if not advisory_scores:
                    raise ValueError(f"OSV severity is missing for {advisory}")
                score = max(advisory_scores)
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
                else:
                    blocking.append(row)
    return blocking, reviewed


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
        report = _strict_json_loads(report_path.read_text(encoding="utf-8"))
        if not isinstance(report, dict):
            raise ValueError("OSV report root is not an object")
        blocking, reviewed = evaluate(
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
    if blocking:
        print(f"::error::{len(blocking)} High/Critical vulnerabilities WITH fixes available:")
        for line in _format(blocking):
            print(line)
        return 1
    print("OK: no unreviewed shippable High/Critical fixable vulnerabilities.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
