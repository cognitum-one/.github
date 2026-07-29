#!/usr/bin/env python3
"""Run OSV-Scanner 2.2.4 across an untrusted repository.

The scanner, organization config, and machine report are deliberately kept
outside the repository being scanned.  Every scan uses the organization config
override and disables candidate-controlled gitignore filtering.  The caller is
responsible for verifying the pinned scanner and config hashes before invoking
this wrapper.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from typing import Any, Callable, Sequence


OSV_SCANNER_VERSION = "2.2.4"
MAX_REPORT_BYTES = 512 * 1024 * 1024
SCAN_PREFIX = (
    "scan",
    "source",
    "--recursive",
    "--no-ignore",
    "--all-vulns",
)
Runner = Callable[..., Any]


class ScanBoundaryError(RuntimeError):
    """Raised when the scanner boundary cannot be proven safe."""


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _repository_root(path: Path) -> Path:
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise ScanBoundaryError(f"repository root is unavailable: {error}") from error
    if not resolved.is_dir():
        raise ScanBoundaryError("repository root is not a directory")
    return resolved


def _external_regular_file(
    path: Path,
    *,
    repository_root: Path,
    label: str,
    executable: bool = False,
) -> Path:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ScanBoundaryError(f"{label} is unavailable: {error}") from error
    if stat.S_ISLNK(metadata.st_mode):
        raise ScanBoundaryError(f"{label} must not be a symlink")
    if not stat.S_ISREG(metadata.st_mode):
        raise ScanBoundaryError(f"{label} must be a regular file")
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise ScanBoundaryError(f"{label} cannot be resolved: {error}") from error
    if _is_within(resolved, repository_root):
        raise ScanBoundaryError(f"{label} must be outside the repository root")
    if executable and not os.access(resolved, os.X_OK):
        raise ScanBoundaryError(f"{label} must be executable")
    return resolved


def _new_external_report_path(path: Path, *, repository_root: Path) -> Path:
    if path.is_symlink():
        raise ScanBoundaryError("OSV report must not be a symlink")
    if path.exists():
        raise ScanBoundaryError("OSV report must not already exist")
    try:
        parent = path.parent.resolve(strict=True)
    except OSError as error:
        raise ScanBoundaryError(f"OSV report directory is unavailable: {error}") from error
    if not parent.is_dir():
        raise ScanBoundaryError("OSV report parent is not a directory")
    resolved = parent / path.name
    if _is_within(resolved, repository_root):
        raise ScanBoundaryError("OSV report must be outside the repository root")
    return resolved


def _expected_scan_command(
    *,
    binary: Path,
    config: Path,
    report: Path | None,
) -> tuple[str, ...]:
    command = (
        str(binary),
        *SCAN_PREFIX,
        "--config",
        str(config),
    )
    if report is not None:
        command += ("--format", "json", "--output", str(report))
    return (*command, ".")


def validate_scan_command(
    command: Sequence[str],
    *,
    binary: Path,
    config: Path,
    report: Path | None,
) -> None:
    """Reject any command that weakens the exact scanner boundary."""

    expected = _expected_scan_command(
        binary=binary,
        config=config,
        report=report,
    )
    if tuple(command) != expected:
        raise ScanBoundaryError(
            "refusing OSV command that omits or changes a required flag or path"
        )


def build_scan_commands(
    *,
    binary: Path,
    config: Path,
    report: Path,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    human = _expected_scan_command(binary=binary, config=config, report=None)
    machine = _expected_scan_command(binary=binary, config=config, report=report)
    validate_scan_command(
        human,
        binary=binary,
        config=config,
        report=None,
    )
    validate_scan_command(
        machine,
        binary=binary,
        config=config,
        report=report,
    )
    return human, machine


def _invoke(
    runner: Runner,
    command: Sequence[str],
    *,
    repository_root: Path,
    label: str,
) -> int:
    try:
        completed = runner(
            list(command),
            cwd=str(repository_root),
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ScanBoundaryError(f"{label} OSV scan could not run: {error}") from error
    status = getattr(completed, "returncode", None)
    if status not in (0, 1):
        raise ScanBoundaryError(
            f"{label} OSV scan failed with unsupported status {status!r}"
        )
    return int(status)


def _load_report(report: Path, *, repository_root: Path) -> dict[str, Any]:
    if report.is_symlink():
        raise ScanBoundaryError("OSV report must not be a symlink")
    try:
        resolved = report.resolve(strict=True)
        metadata = report.lstat()
    except OSError as error:
        raise ScanBoundaryError(f"OSV report is missing: {error}") from error
    if _is_within(resolved, repository_root):
        raise ScanBoundaryError("OSV report resolved inside the repository root")
    if not stat.S_ISREG(metadata.st_mode):
        raise ScanBoundaryError("OSV report is not a regular file")
    if metadata.st_size == 0:
        raise ScanBoundaryError("OSV report is empty")
    if metadata.st_size > MAX_REPORT_BYTES:
        raise ScanBoundaryError("OSV report exceeds the maximum accepted size")

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(report, flags)
        with os.fdopen(descriptor, encoding="utf-8") as stream:
            payload = json.load(stream)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ScanBoundaryError(f"OSV report is not valid JSON: {error}") from error

    if not isinstance(payload, dict):
        raise ScanBoundaryError("OSV report root must be an object")
    if not isinstance(payload.get("results"), list):
        raise ScanBoundaryError("OSV report must contain a results array")
    return payload


def run_osv_scan(
    *,
    binary: Path,
    config: Path,
    report: Path,
    repository_root: Path,
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    """Run the human and JSON scans, returning a minimally validated report."""

    root = _repository_root(repository_root)
    scanner = _external_regular_file(
        binary,
        repository_root=root,
        label="OSV scanner",
        executable=True,
    )
    policy = _external_regular_file(
        config,
        repository_root=root,
        label="OSV organization config",
    )
    machine_report = _new_external_report_path(report, repository_root=root)
    if len({scanner, policy, machine_report}) != 3:
        raise ScanBoundaryError("scanner, config, and report paths must be distinct")

    human, machine = build_scan_commands(
        binary=scanner,
        config=policy,
        report=machine_report,
    )
    _invoke(runner, human, repository_root=root, label="human-readable")
    if machine_report.exists() or machine_report.is_symlink():
        raise ScanBoundaryError("human-readable scan unexpectedly created the report")
    _invoke(runner, machine, repository_root=root, label="machine-readable")
    return _load_report(machine_report, repository_root=root)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run pinned OSV-Scanner 2.2.4 with a fail-closed organization "
            "configuration boundary."
        )
    )
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--repository-root", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        run_osv_scan(
            binary=args.binary,
            config=args.config,
            report=args.report,
            repository_root=args.repository_root,
        )
    except ScanBoundaryError as error:
        print(f"::error::{error}", file=sys.stderr)
        return 2
    print(f"OSV-Scanner {OSV_SCANNER_VERSION} report validated: {args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
