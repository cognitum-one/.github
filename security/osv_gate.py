#!/usr/bin/env python3
"""Fail closed on fixable High/Critical OSV findings.

The sole range exception is organization-owned and expires for
GHSA-qwww-vcr4-c8h2 at React Router 7.18.2.  The maintainer advisory marks
7.18.2 as patched on the 7.x line while the aggregated OSV range currently
reports it as affected.  The exception additionally requires the exact
reviewed package artifacts and static-runtime profile.
"""

from __future__ import annotations

import datetime as dt
import json
import math
import os
from pathlib import Path
import re
import stat
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
    },
    ("cognitum-one/website", "package-lock.json"): {
        "manifest": "package.json",
    },
}
ROUTER_ARTIFACTS = {
    "react-router": {
        "path": "node_modules/react-router",
        "resolved": "https://registry.npmjs.org/react-router/-/react-router-7.18.2.tgz",
        "integrity": (
            "sha512-aUVMjFm3GAPTTZL7oYr5E7ETiqfQCHRLH+B+5afnICvf0r7kkK4eR6SMuwbSTJw/"
            "7t+12khT/Kahij49fqOCIg=="
        ),
    },
    "react-router-dom": {
        "path": "node_modules/react-router-dom",
        "resolved": (
            "https://registry.npmjs.org/react-router-dom/-/react-router-dom-7.18.2.tgz"
        ),
        "integrity": (
            "sha512-AIKJ/jgGlFb3EbfCXk5Gzshiwt+l3mqbCrNjmEWMMjqQxNJ3svBa6bgzFyCC2Sw3"
            "RA0VWF1kg3uQf2OFhxb8hw=="
        ),
    },
}
RUNTIME_RECEIPT_EVIDENCE_ENVIRONMENT = {
    "OSV_RUNTIME_RECEIPT",
    "OSV_RUNTIME_INVENTORY",
    "OSV_RUNTIME_NONCE",
    "OSV_RUNTIME_IMAGE_NAME",
    "OSV_RUNTIME_IMAGE_ID",
}
RUNTIME_RECEIPT_GITHUB_ENVIRONMENT = {
    "GITHUB_REPOSITORY",
    "GITHUB_SHA",
    "GITHUB_RUN_ID",
    "GITHUB_RUN_ATTEMPT",
    "GITHUB_JOB",
    "GITHUB_WORKFLOW_REF",
    "GITHUB_WORKFLOW_SHA",
}
RUNTIME_RECEIPT_ENVIRONMENT = (
    RUNTIME_RECEIPT_EVIDENCE_ENVIRONMENT | RUNTIME_RECEIPT_GITHUB_ENVIRONMENT
)
MAX_RUNTIME_EVIDENCE_BYTES = 512 * 1024 * 1024


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

    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON constant: {value}")

    return json.loads(
        source,
        object_pairs_hook=object_pairs,
        parse_constant=reject_constant,
    )


def _read_lock(source: str) -> dict[str, Any] | None:
    try:
        value = _strict_json_loads(Path(source).read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return None
    return value if isinstance(value, dict) else None


def _external_evidence_file(
    source: str,
    *,
    root: Path,
    label: str,
    maximum_bytes: int,
) -> Path:
    path = Path(source)
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
        resolved.relative_to(root.resolve())
    except ValueError:
        pass
    except OSError as error:
        raise ValueError(f"{label} is unavailable: {error}") from error
    else:
        raise ValueError(f"{label} must be outside the candidate repository")
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"{label} must be a non-symlink regular file")
    if metadata.st_size <= 0 or metadata.st_size > maximum_bytes:
        raise ValueError(f"{label} has an invalid size")
    return resolved


def _read_external_json(
    source: str,
    *,
    root: Path,
    label: str,
) -> dict[str, Any]:
    path = _external_evidence_file(
        source,
        root=root,
        label=label,
        maximum_bytes=MAX_RUNTIME_EVIDENCE_BYTES,
    )
    value = _strict_json_loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{label} root must be an object")
    return value


def _verified_runtime_receipt_from_environment(
    *,
    repository: str,
    root: Path,
) -> bool:
    # GitHub populates its run tuple for every repository. Only the five
    # runtime outputs establish that a caller attempted to supply a receipt.
    evidence_present = {
        name for name in RUNTIME_RECEIPT_EVIDENCE_ENVIRONMENT if os.environ.get(name)
    }
    if not evidence_present:
        return False
    present = {name for name in RUNTIME_RECEIPT_ENVIRONMENT if os.environ.get(name)}
    missing = RUNTIME_RECEIPT_ENVIRONMENT - present
    if missing:
        raise ValueError(
            "runtime receipt environment is incomplete: " + ", ".join(sorted(missing))
        )

    receipt_path = _external_evidence_file(
        os.environ["OSV_RUNTIME_RECEIPT"],
        root=root,
        label="runtime receipt",
        maximum_bytes=MAX_RUNTIME_EVIDENCE_BYTES,
    )
    inventory_path = _external_evidence_file(
        os.environ["OSV_RUNTIME_INVENTORY"],
        root=root,
        label="runtime inventory",
        maximum_bytes=MAX_RUNTIME_EVIDENCE_BYTES,
    )
    nonce_path = _external_evidence_file(
        os.environ["OSV_RUNTIME_NONCE"],
        root=root,
        label="runtime receipt nonce",
        maximum_bytes=128,
    )
    if len({receipt_path, inventory_path, nonce_path}) != 3:
        raise ValueError("runtime receipt evidence paths must be distinct")
    nonce_source = nonce_path.read_text(encoding="ascii")
    if not re.fullmatch(r"[0-9a-f]{64}\n", nonce_source):
        raise ValueError("runtime receipt nonce file is malformed")

    policy_path = Path(__file__).with_name("static-ui-runtime-profiles.json")
    if policy_path.is_symlink() or not policy_path.is_file():
        raise ValueError("immutable runtime profile policy is unavailable")
    try:
        from static_ui_runtime_receipt import (
            load_policy,
            verify_premerge_receipt,
        )
    except ImportError as error:
        raise ValueError("immutable runtime receipt verifier is unavailable") from error

    receipt = _read_external_json(
        str(receipt_path),
        root=root,
        label="runtime receipt",
    )
    inventory = _read_external_json(
        str(inventory_path),
        root=root,
        label="runtime inventory",
    )
    policy = load_policy(policy_path)
    verify_premerge_receipt(
        receipt=receipt,
        inventory=inventory,
        repository=repository,
        policy=policy,
        policy_path=policy_path,
        expected_source_sha=os.environ["GITHUB_SHA"],
        expected_image_name=os.environ["OSV_RUNTIME_IMAGE_NAME"],
        expected_image_id=os.environ["OSV_RUNTIME_IMAGE_ID"],
        expected_run_id=os.environ["GITHUB_RUN_ID"],
        expected_run_attempt=os.environ["GITHUB_RUN_ATTEMPT"],
        expected_job=os.environ["GITHUB_JOB"],
        expected_workflow_ref=os.environ["GITHUB_WORKFLOW_REF"],
        expected_workflow_sha=os.environ["GITHUB_WORKFLOW_SHA"],
        expected_nonce=nonce_source.rstrip("\n"),
    )
    return True


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


def _has_reviewed_router_artifacts(
    *,
    repository: str,
    relative_lock: str,
    root: Path,
    runtime_evidence_verified: bool,
) -> bool:
    profile = ROUTER_PROFILES.get((repository, relative_lock))
    if profile is None or runtime_evidence_verified is not True:
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
        if "react-router" in group:
            return False
        if group_name != "dependencies" and "react-router-dom" in group:
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
    router_nodes: dict[str, str] = {}
    for package_path, metadata in packages.items():
        if not isinstance(package_path, str) or not isinstance(metadata, dict):
            return False
        package_name = package_path.split("node_modules/")[-1]
        expected = ROUTER_ARTIFACTS.get(package_name)
        if expected is not None:
            if package_name in router_nodes:
                return False
            router_nodes[package_name] = package_path
            if (
                package_path != expected["path"]
                or metadata.get("version") != ROUTER_VERSION
                or metadata.get("resolved") != expected["resolved"]
                or metadata.get("integrity") != expected["integrity"]
            ):
                return False
    if router_nodes != {
        name: artifact["path"] for name, artifact in ROUTER_ARTIFACTS.items()
    }:
        return False
    return True


def reviewed_router_patch_exception(
    *,
    repository: str,
    source: str,
    root: Path,
    package: str,
    version: str,
    advisory: str,
    today: dt.date,
    runtime_evidence_verified: bool,
) -> bool:
    relative = _relative_source(source, root)
    if (
        today >= ROUTER_EXCEPTION_EXPIRES
        or (repository, relative or "") not in ROUTER_LOCKS
        or package != "react-router"
        or version != ROUTER_VERSION
        or advisory != ROUTER_ADVISORY
        or not _has_reviewed_router_artifacts(
            repository=repository,
            relative_lock=relative or "",
            root=root,
            runtime_evidence_verified=runtime_evidence_verified,
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
    runtime_evidence_verified: bool = False,
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
            vulnerabilities = package_record.get("vulnerabilities")
            if not isinstance(vulnerabilities, list):
                raise ValueError("OSV vulnerabilities is not an array")
            findings: list[tuple[str, bool]] = []
            for vulnerability in vulnerabilities:
                if not isinstance(vulnerability, dict):
                    raise ValueError("OSV vulnerability is not an object")
                advisory = vulnerability.get("id")
                if not isinstance(advisory, str):
                    raise ValueError("OSV advisory id is invalid")
                affected_records = vulnerability.get("affected")
                if not isinstance(affected_records, list):
                    raise ValueError("OSV affected records is not an array")
                fixed = False
                for affected in affected_records:
                    if not isinstance(affected, dict):
                        raise ValueError("OSV affected record is not an object")
                    ranges = affected.get("ranges", [])
                    if not isinstance(ranges, list):
                        raise ValueError("OSV affected ranges is not an array")
                    for range_record in ranges:
                        if not isinstance(range_record, dict):
                            raise ValueError("OSV affected range is not an object")
                        events = range_record.get("events")
                        if not isinstance(events, list):
                            raise ValueError("OSV affected events is not an array")
                        for event in events:
                            if not isinstance(event, dict):
                                raise ValueError("OSV affected event is not an object")
                            if "fixed" in event:
                                if (
                                    not isinstance(event["fixed"], str)
                                    or not event["fixed"]
                                ):
                                    raise ValueError("OSV fixed version is invalid")
                                fixed = True
                findings.append((advisory, fixed))

            severity: dict[str, list[float]] = {}
            severity_missing: set[str] = set()
            groups = package_record.get("groups")
            if not isinstance(groups, list):
                raise ValueError("OSV package groups is not an array")
            for group in groups:
                if not isinstance(group, dict):
                    raise ValueError("OSV severity group is not an object")
                advisory_ids = group.get("ids")
                if not isinstance(advisory_ids, list):
                    raise ValueError("OSV severity group ids is not an array")
                for advisory in advisory_ids:
                    if not isinstance(advisory, str):
                        raise ValueError("OSV severity advisory id is invalid")
                    raw_score = group.get("max_severity")
                    if raw_score is None or raw_score == "":
                        severity_missing.add(advisory)
                        continue
                    if isinstance(raw_score, bool):
                        raise ValueError(
                            f"OSV severity is missing or invalid for {advisory}"
                        )
                    try:
                        score = float(raw_score)
                    except (TypeError, ValueError):
                        raise ValueError(
                            f"OSV severity is missing or invalid for {advisory}"
                        )
                    if not math.isfinite(score) or not 0.0 <= score <= 10.0:
                        raise ValueError(f"OSV severity is out of range for {advisory}")
                    severity.setdefault(advisory, []).append(score)

            for advisory, fixed in findings:
                if not fixed:
                    continue
                advisory_scores = severity.get(advisory)
                if advisory in severity_missing or not advisory_scores:
                    raise ValueError(f"OSV severity is missing for {advisory}")
                score = max(advisory_scores)
                if score < 7.0:
                    continue
                row = (name, version, advisory, score, source)
                if reviewed_router_patch_exception(
                    repository=repository,
                    source=source,
                    root=root,
                    package=name,
                    version=version,
                    advisory=advisory,
                    today=today,
                    runtime_evidence_verified=runtime_evidence_verified,
                ):
                    reviewed.append(row)
                else:
                    blocking.append(row)
    return blocking, reviewed


def _format(rows: list[tuple[str, str, str, float, str]]) -> list[str]:
    return [
        "  CVSS %.1f  %s@%s  %s  (%s)" % (score, name, version, advisory, source or "?")
        for name, version, advisory, score, source in sorted(
            rows, key=lambda row: -row[3]
        )
    ]


def main() -> int:
    report_path = Path(os.environ.get("OSV_REPORT", "osv.json"))
    root = Path(os.environ.get("OSV_REPOSITORY_ROOT", ".")).resolve()
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    try:
        runtime_evidence_verified = _verified_runtime_receipt_from_environment(
            repository=repository,
            root=root,
        )
        report = _strict_json_loads(report_path.read_text(encoding="utf-8"))
        if not isinstance(report, dict):
            raise ValueError("OSV report root is not an object")
        blocking, reviewed = evaluate(
            report,
            repository=repository,
            root=root,
            today=dt.datetime.now(dt.timezone.utc).date(),
            runtime_evidence_verified=runtime_evidence_verified,
        )
    except (OSError, ValueError, TypeError) as error:
        print(f"::error::OSV JSON is missing, malformed, or unsafe: {error}")
        return 2

    if reviewed:
        print(
            "::warning::Reviewed React Router 7.18.2 range exception "
            f"applied to {len(reviewed)} exact React Router 7.18.2 finding(s); "
            f"expires {ROUTER_EXCEPTION_EXPIRES.isoformat()}:"
        )
        for line in _format(reviewed):
            print(line)
    if blocking:
        print(
            f"::error::{len(blocking)} High/Critical vulnerabilities WITH fixes available:"
        )
        for line in _format(blocking):
            print(line)
        return 1
    print("OK: no unreviewed High/Critical fixable vulnerabilities.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
