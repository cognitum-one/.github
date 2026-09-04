#!/usr/bin/env python3
"""Normalize scanner output into stable, non-secret SecurityPolicy finding IDs."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
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


def normalize(
    control: str, report: Any, *, repository_root: Path | None = None
) -> list[str]:
    records: list[list[str]] = []
    if control == "secrets":
        if not isinstance(report, list):
            raise FindingsError("gitleaks report is not an array")
        for item in report:
            if not isinstance(item, dict) or not all(
                isinstance(item.get(key), (str, int)) for key in ("RuleID", "File", "StartLine")
            ):
                raise FindingsError("gitleaks finding is malformed")
            records.append([str(item["RuleID"]), str(item["File"]), str(item["StartLine"])])
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
    args = parser.parse_args()
    print(json.dumps(
        normalize(args.control, _load(args.report), repository_root=args.repository_root),
        separators=(",", ":"),
    ))


if __name__ == "__main__":
    main()
