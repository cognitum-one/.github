#!/usr/bin/env python3
"""Fail closed on fixable High/Critical OSV findings.

There are two organization-owned exceptions, and each one expires.

GHSA-qwww-vcr4-c8h2 at React Router 7.18.2 is a range exception.  The
maintainer advisory marks 7.18.2 as patched on the 7.x line while the
aggregated OSV range currently reports it as affected.  The exception
additionally requires the exact reviewed package artifacts and static-runtime
profile.

GHSA-mrhx-c7xc-m3w5 at zod 3.25.76 covers Ruflo's own zod 3 copies in
console's Ruflo adapter.  The fix exists only in zod 4.6.6, and every Ruflo
release still requires zod ^3.  Forcing zod 4 breaks Ruflo at runtime:
@claude-flow/security calls z.string().ip(), which zod 4 removed, and
memory_store then fails.  The exception covers only exact zod 3.25.76
artifacts nested under the reviewed @claude-flow packages, and it ends when
Ruflo publishes a zod 4 release and console moves to it, or at expiry.
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
ROUTER_EXCEPTION_EXPIRES = dt.date(2026, 11, 15)
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
ZOD_ADVISORY = "GHSA-mrhx-c7xc-m3w5"
ZOD_VERSION = "3.25.76"
ZOD_EXCEPTION_EXPIRES = dt.date(2026, 11, 27)
ZOD_LOCKS = {
    ("cognitum-one/console", "services/runtime-adapters/ruflo/package-lock.json"),
}
# Only these Ruflo packages may carry a zod 3 copy. Each one declares zod ^3 and
# none has a zod 4 release yet. A zod 3 copy anywhere else, including the
# top-level node_modules/zod, is not covered.
ZOD_REVIEWED_PARENTS = frozenset(
    {
        "@claude-flow/cli",
        "@claude-flow/security",
        "@claude-flow/shared",
    }
)
ZOD_ARTIFACT = {
    "resolved": "https://registry.npmjs.org/zod/-/zod-3.25.76.tgz",
    "integrity": (
        "sha512-gzUt/qt81nXsFGKIFcC3YnfEAx5NkunCfnDlvuBSSFS02bcXu4Lmea0AFIUwbLWx"
        "WPx3d9p8S5QoaujKcNQxcQ=="
    ),
}
ZOD_PARENT_RANGE = re.compile(r"\^3\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
PLAIN_VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
SHA512_INTEGRITY = re.compile(r"sha512-[A-Za-z0-9+/]{86}==")
ZOD_DIGEST = ZOD_ARTIFACT["integrity"].removeprefix("sha512-")
# SemVer: numeric prerelease identifiers have no leading zeros.
_PRERELEASE_ID = r"(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
_BUILD_ID = r"[0-9A-Za-z-]+"
SEMVER = re.compile(
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    rf"(-{_PRERELEASE_ID}(?:\.{_PRERELEASE_ID})*)?(\+{_BUILD_ID}(?:\.{_BUILD_ID})*)?"
)
# npm package names never start with "." or "_", so "." and ".." segments cannot
# appear in an ordinary install path.
_LOCK_NAME = r"[A-Za-z0-9~-][A-Za-z0-9._~-]*"
_LOCK_SEGMENT = rf"(?:@{_LOCK_NAME}/)?{_LOCK_NAME}"
LOCK_PACKAGE_PATH = re.compile(
    rf"node_modules/{_LOCK_SEGMENT}(?:/node_modules/{_LOCK_SEGMENT})*"
)
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

    # The candidate repository owns its static UI profile, so the receipt is
    # BUILT from that file and must be RE-VERIFIED against the same one. This
    # path defaulted to the copy sitting beside this script, which meant the
    # receipt was built from one profile and checked against another: the gate
    # failed with "premerge fixture evidence differs from the profile" for a
    # repository whose profile was entirely self-consistent.
    #
    # The variable is set by the organization-owned workflow, never by the
    # candidate, and the file is still required to be a real regular file.
    policy_override = os.environ.get("STATIC_UI_POLICY_PATH")
    policy_path = (
        Path(policy_override)
        if policy_override
        else Path(__file__).with_name("static-ui-runtime-profiles.json")
    )
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


def _zod_is_fixed(version: str) -> bool:
    """zod is fixed from 4.6.6; a prerelease of 4.6.6 is not."""
    match = SEMVER.fullmatch(version)
    if match is None:
        return False
    base = tuple(int(part) for part in match.group(1, 2, 3))
    return base > (4, 6, 6) or (base == (4, 6, 6) and match.group(4) is None)


def _is_reviewed_zod_parent(packages: dict[str, Any], parent: str) -> bool:
    metadata = packages.get(f"node_modules/{parent}")
    if (
        not isinstance(metadata, dict)
        or metadata.get("link")
        or metadata.get("inBundle")
        or metadata.get("name", parent) != parent
    ):
        return False
    version = metadata.get("version")
    integrity = metadata.get("integrity")
    dependencies = metadata.get("dependencies")
    if (
        not isinstance(version, str)
        or PLAIN_VERSION.fullmatch(version) is None
        or metadata.get("resolved")
        != f"https://registry.npmjs.org/{parent}/-/{parent.split('/')[-1]}-{version}.tgz"
        or not isinstance(integrity, str)
        or SHA512_INTEGRITY.fullmatch(integrity) is None
        or not isinstance(dependencies, dict)
        or not isinstance(dependencies.get("zod"), str)
    ):
        return False
    # A plain caret range on zod 3 that the reviewed 3.25.76 satisfies.
    # "^3.22.0 || >=4" would also admit zod 4, and then the parent no longer
    # needs the exception.
    zod_range = ZOD_PARENT_RANGE.fullmatch(dependencies["zod"])
    if zod_range is None:
        return False
    minor, patch = int(zod_range.group(1)), int(zod_range.group(2))
    return (minor, patch) <= (25, 76)


def _has_reviewed_ruflo_zod_artifacts(*, relative_lock: str, root: Path) -> bool:
    lock = _read_profile_json(root, relative_lock)
    if lock is None:
        return False
    packages = lock.get("packages")
    if not isinstance(packages, dict):
        return False
    reviewed_nodes = 0
    for package_path, metadata in packages.items():
        if not isinstance(package_path, str) or not isinstance(metadata, dict):
            return False
        if package_path == "":
            continue
        # Every entry must be an ordinary npm install path, so a zod copy cannot
        # hide behind a trailing slash, a workspace directory or look-alike
        # characters.
        if LOCK_PACKAGE_PATH.fullmatch(package_path) is None:
            return False
        package_name = package_path.rsplit("node_modules/", 1)[-1]
        resolved = metadata.get("resolved")
        integrity = metadata.get("integrity")
        declared_name = metadata.get("name")
        looks_like_zod = (
            declared_name == "zod"
            # A substring test, so padding or repeating the digest cannot hide it.
            or (isinstance(integrity, str) and ZOD_DIGEST in integrity)
            or (isinstance(resolved, str) and "/zod/-/zod-" in resolved)
        )
        if looks_like_zod and package_name != "zod":
            # An aliased or renamed install would hide a zod copy.
            return False
        if package_name != "zod":
            continue
        version = metadata.get("version")
        # Every zod copy must be a plain registry install whose label, tarball
        # and single sha512 digest agree, so a vulnerable copy cannot pose as a
        # fixed release. Any zod still below the fix outside the reviewed
        # copies ends the exception.
        if (
            not isinstance(version, str)
            or ("name" in metadata and declared_name != "zod")
            or metadata.get("link")
            or metadata.get("inBundle")
            or resolved != f"https://registry.npmjs.org/zod/-/zod-{version}.tgz"
            or not isinstance(integrity, str)
            or SHA512_INTEGRITY.fullmatch(integrity) is None
            or (integrity == ZOD_ARTIFACT["integrity"]) != (version == ZOD_VERSION)
        ):
            return False
        if version != ZOD_VERSION:
            if not _zod_is_fixed(version):
                return False
            continue
        # LOCK_PACKAGE_PATH guarantees node_modules/<parent>/node_modules/zod.
        parent = package_path.removeprefix("node_modules/").removesuffix(
            "/node_modules/zod"
        )
        if (
            parent not in ZOD_REVIEWED_PARENTS
            or not _is_reviewed_zod_parent(packages, parent)
        ):
            return False
        reviewed_nodes += 1
    return reviewed_nodes > 0


def reviewed_ruflo_zod_exception(
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
        today >= ZOD_EXCEPTION_EXPIRES
        or (repository, relative or "") not in ZOD_LOCKS
        or package != "zod"
        or version != ZOD_VERSION
        or advisory != ZOD_ADVISORY
        or not _has_reviewed_ruflo_zod_artifacts(
            relative_lock=relative or "",
            root=root,
        )
    ):
        return False
    return True


REVIEWED_EXCEPTION_EXPIRY = {
    ROUTER_ADVISORY: ROUTER_EXCEPTION_EXPIRES,
    ZOD_ADVISORY: ZOD_EXCEPTION_EXPIRES,
}


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
                    # A fixable advisory that OSV has not scored. This is NOT a
                    # malformed report — OSV genuinely publishes some advisories
                    # with no CVSS, and RustSec routinely does. It still blocks,
                    # because an unrated vulnerability with a fix available is
                    # not something to wave through; it is recorded as a finding
                    # with an unknown score rather than raised as a parse error.
                    #
                    # It used to raise, which aborted the whole scan and printed
                    # "OSV JSON is missing, malformed, or unsafe". That reads as
                    # a scanner fault, so the red was written off as tooling
                    # noise, and three unrated rkyv memory-safety advisories
                    # (RUSTSEC-2026-0233/0234/0235, one a use-after-free, all
                    # fixed in 0.8.17) sat unactioned behind it. Aborting also
                    # meant no other package was evaluated, so nobody could see
                    # what else the scan had found.
                    blocking.append((name, version, advisory, None, source))
                    continue
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
                ) or reviewed_ruflo_zod_exception(
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


def _format(rows: list[tuple[str, str, str, float | None, str]]) -> list[str]:
    # Unrated findings sort first: an unknown score is not a low score, and it
    # is the one an operator most needs to look at by hand.
    return [
        "  %s  %s@%s  %s  (%s)"
        % (
            "CVSS ?.?" if score is None else "CVSS %.1f" % score,
            name,
            version,
            advisory,
            source or "?",
        )
        for name, version, advisory, score, source in sorted(
            rows, key=lambda row: (row[3] is not None, -(row[3] or 0.0))
        )
    ]


def _today() -> dt.date:
    return dt.datetime.now(dt.timezone.utc).date()


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
            today=_today(),
            runtime_evidence_verified=runtime_evidence_verified,
        )
    except (OSError, ValueError, TypeError) as error:
        print(f"::error::OSV JSON is missing, malformed, or unsafe: {error}")
        return 2

    for advisory, expires in REVIEWED_EXCEPTION_EXPIRY.items():
        applied = [row for row in reviewed if row[2] == advisory]
        if not applied:
            continue
        name, version = applied[0][0], applied[0][1]
        print(
            f"::warning::Reviewed {name} {version} exception for {advisory} "
            f"applied to {len(applied)} exact finding(s); "
            f"expires {expires.isoformat()}:"
        )
        for line in _format(applied):
            print(line)
    if blocking:
        unrated = sum(1 for row in blocking if row[3] is None)
        rated = len(blocking) - unrated
        summary = f"{len(blocking)} vulnerabilities WITH fixes available"
        if unrated:
            # Name the unrated ones explicitly. Reporting them as though they
            # were CVSS>=7 would be a different lie from the one this replaced.
            summary += f" ({rated} High/Critical, {unrated} unrated by OSV)"
        else:
            summary += " (High/Critical)"
        print(f"::error::{summary}:")
        for line in _format(blocking):
            print(line)
        if unrated:
            print(
                "::notice::Findings shown as CVSS ?.? have no severity published "
                "by OSV. They are fixable, so they block. This is a real finding, "
                "not a scanner or report fault — upgrade the package, or record "
                "an explicit reviewed exception."
            )
        return 1
    print("OK: no unreviewed High/Critical fixable vulnerabilities.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
