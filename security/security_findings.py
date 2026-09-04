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


def normalize(control: str, report: Any) -> list[str]:
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
                    records.append([source["path"], identity["name"], identity["version"], vulnerability["id"]])
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
    args = parser.parse_args()
    print(json.dumps(normalize(args.control, _load(args.report)), separators=(",", ":")))


if __name__ == "__main__":
    main()
