#!/usr/bin/env python3
"""Normalize scanner output into stable, non-secret SecurityPolicy finding IDs.

Dependency findings have two shapes.  Without ``--osv-gate`` every advisory
in the OSV report becomes a finding (the historical shape, still used by the
ratchet baseline fixtures).  With ``--osv-gate`` pointing at the hash-verified
organization ``osv_gate.py``, only the rows that gate classifies as blocking
(fixable High/Critical, plus fixable-but-unrated, minus the reviewed router
correction) become findings, so SecurityPolicy/v1 refuses on exactly the set
the producer already enforces rather than on every Moderate advisory.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
from types import ModuleType
from typing import Any


class FindingsError(ValueError):
    pass


def _load(path: Path) -> Any:
    if path.is_symlink() or not path.is_file():
        raise FindingsError("scanner finding report is missing or unsafe")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise FindingsError("scanner finding report is malformed") from error


def _identifier(control: str, fields: list[str]) -> str:
    encoded = "\0".join(fields).encode("utf-8")
    return f"{control}:{hashlib.sha256(encoded).hexdigest()}"


def _dependency_source_path(source: str, repository_root: Path | None) -> str:
    """Return a workspace-independent lockfile identity.

    OSV reports an absolute source path when it is invoked from a checked-out
    workspace.  Runner-specific prefixes must never become part of a ratchet
    identity: the same lockfile would otherwise look new on the next runner.
    The trusted workflow supplies its checked-out repository root and refuses
    a report that names a source outside that root.
    """

    candidate = Path(source)
    if repository_root is None:
        if candidate.is_absolute():
            raise FindingsError("OSV source requires a repository root for canonicalization")
        return candidate.as_posix()
    try:
        root = repository_root.resolve(strict=True)
        relative = candidate.resolve(strict=False).relative_to(root)
    except (OSError, ValueError) as error:
        raise FindingsError("OSV source is outside the repository root") from error
    if not relative.parts or relative == Path("."):
        raise FindingsError("OSV source is not a lockfile path")
    return relative.as_posix()


def load_osv_gate(path: Path) -> ModuleType:
    """Import the organization OSV gate from an explicit, already-verified path."""
    if path.is_symlink() or not path.is_file():
        raise FindingsError("OSV gate module is missing or unsafe")
    spec = importlib.util.spec_from_file_location("organization_osv_gate", path)
    if spec is None or spec.loader is None:
        raise FindingsError("OSV gate module cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for name in ("evaluate", "_verified_runtime_receipt_from_environment"):
        if not callable(getattr(module, name, None)):
            raise FindingsError(f"OSV gate module lacks {name}")
    return module


def _blocking_dependency_records(
    report: Any,
    *,
    osv_gate: ModuleType,
    repository: str,
    repository_root: Path | None,
    today: dt.date,
    runtime_evidence_verified: bool,
) -> list[list[str]]:
    """Records for exactly the rows the organization OSV gate would block on."""
    if repository_root is None:
        raise FindingsError("OSV gate classification requires a repository root")
    if not isinstance(report, dict):
        raise FindingsError("OSV report is malformed")
    try:
        blocking, _reviewed = osv_gate.evaluate(
            report,
            repository=repository,
            root=repository_root.resolve(strict=True),
            today=today,
            runtime_evidence_verified=runtime_evidence_verified,
        )
    except (OSError, ValueError, TypeError) as error:
        raise FindingsError(f"OSV gate refused the report: {error}") from error
    records: list[list[str]] = []
    for row in blocking:
        if not isinstance(row, tuple) or len(row) != 5:
            raise FindingsError("OSV gate returned a malformed blocking row")
        name, version, advisory, _score, source = row
        if not all(isinstance(value, str) and value for value in (name, version, advisory, source)):
            raise FindingsError("OSV gate returned a malformed blocking row")
        records.append([_dependency_source_path(source, repository_root), name, version, advisory])
    return records


def normalize(
    control: str,
    report: Any,
    *,
    repository_root: Path | None = None,
    osv_gate: ModuleType | None = None,
    repository: str = "",
    today: dt.date | None = None,
    runtime_evidence_verified: bool = False,
) -> list[str]:
    records: list[list[str]] = []
    if osv_gate is not None and control != "dependencies":
        raise FindingsError("OSV gate classification applies to the dependencies control only")
    if control == "secrets":
        if not isinstance(report, list):
            raise FindingsError("gitleaks report is not an array")
        for item in report:
            if not isinstance(item, dict) or not all(
                isinstance(item.get(key), (str, int)) for key in ("RuleID", "File", "StartLine")
            ):
                raise FindingsError("gitleaks finding is malformed")
            records.append([str(item["RuleID"]), str(item["File"]), str(item["StartLine"])])
    elif control == "dependencies" and osv_gate is not None:
        records = _blocking_dependency_records(
            report,
            osv_gate=osv_gate,
            repository=repository,
            repository_root=repository_root,
            today=today or dt.datetime.now(dt.timezone.utc).date(),
            runtime_evidence_verified=runtime_evidence_verified,
        )
    elif control == "dependencies":
        if not isinstance(report, dict) or not isinstance(report.get("results"), list):
            raise FindingsError("OSV report is malformed")
        for result in report["results"]:
            source = result.get("source", {}) if isinstance(result, dict) else {}
            if not isinstance(source, dict) or not isinstance(source.get("path"), str):
                raise FindingsError("OSV source is malformed")
            source_path = _dependency_source_path(source["path"], repository_root)
            packages = result.get("packages")
            if not isinstance(packages, list):
                raise FindingsError("OSV packages are malformed")
            for package in packages:
                identity = package.get("package", {}) if isinstance(package, dict) else {}
                vulnerabilities = package.get("vulnerabilities") if isinstance(package, dict) else None
                if not isinstance(identity, dict) or not isinstance(vulnerabilities, list):
                    raise FindingsError("OSV package finding is malformed")
                if not all(isinstance(identity.get(key), str) for key in ("name", "version")):
                    raise FindingsError("OSV package identity is malformed")
                for vulnerability in vulnerabilities:
                    if not isinstance(vulnerability, dict) or not isinstance(vulnerability.get("id"), str):
                        raise FindingsError("OSV vulnerability is malformed")
                    records.append([source_path, identity["name"], identity["version"], vulnerability["id"]])
    elif control == "workflow_pins":
        if not isinstance(report, list):
            raise FindingsError("workflow finding report is not an array")
        for item in report:
            if not isinstance(item, dict) or not all(
                isinstance(item.get(key), (str, int)) for key in ("kind", "path", "line", "reason")
            ):
                raise FindingsError("workflow finding is malformed")
            records.append([str(item["kind"]), str(item["path"]), str(item["line"]), str(item["reason"])])
    else:
        raise FindingsError("unknown finding control")
    return sorted({_identifier(control, fields) for fields in records})


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--control", choices=("secrets", "dependencies", "workflow_pins"), required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--repository-root", type=Path)
    parser.add_argument(
        "--osv-gate", type=Path,
        help="hash-verified organization osv_gate.py; dependency findings become its blocking rows only",
    )
    args = parser.parse_args()
    osv_gate = None
    repository = ""
    runtime_evidence_verified = False
    if args.osv_gate is not None:
        if args.control != "dependencies":
            parser.error("--osv-gate applies to --control dependencies only")
        if args.repository_root is None:
            parser.error("--osv-gate requires --repository-root")
        osv_gate = load_osv_gate(args.osv_gate)
        repository = os.environ.get("GITHUB_REPOSITORY", "")
        try:
            # Same runtime-receipt gate as the enforcement step: with any
            # OSV_RUNTIME_* evidence present the whole tuple must verify, so
            # the router correction can never be admitted on partial evidence.
            runtime_evidence_verified = osv_gate._verified_runtime_receipt_from_environment(
                repository=repository, root=args.repository_root.resolve(strict=True)
            )
        except (OSError, ValueError, TypeError) as error:
            raise FindingsError(f"runtime receipt evidence is invalid: {error}") from error
    print(json.dumps(
        normalize(
            args.control, _load(args.report), repository_root=args.repository_root,
            osv_gate=osv_gate, repository=repository,
            runtime_evidence_verified=runtime_evidence_verified,
        ),
        separators=(",", ":"),
    ))


if __name__ == "__main__":
    main()
