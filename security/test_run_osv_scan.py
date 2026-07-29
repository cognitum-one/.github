#!/usr/bin/env python3

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from run_osv_scan import (
    SCAN_PREFIX,
    ScanBoundaryError,
    build_scan_commands,
    run_osv_scan,
    validate_scan_command,
)


class RecordingRunner:
    def __init__(
        self,
        *,
        report_payload: object = None,
        statuses: tuple[int, ...] = (0, 0),
        report_mode: str = "valid",
    ) -> None:
        self.report_payload = (
            {"results": []} if report_payload is None else report_payload
        )
        self.statuses = statuses
        self.report_mode = report_mode
        self.calls: list[tuple[tuple[str, ...], dict[str, object]]] = []

    def __call__(self, command, **kwargs):
        frozen = tuple(command)
        self.calls.append((frozen, kwargs))
        index = len(self.calls) - 1
        if "--output" in frozen:
            report = Path(frozen[frozen.index("--output") + 1])
            if self.report_mode == "valid":
                report.write_text(json.dumps(self.report_payload), encoding="utf-8")
            elif self.report_mode == "empty":
                report.touch()
            elif self.report_mode == "invalid":
                report.write_text("{not-json", encoding="utf-8")
            elif self.report_mode == "symlink":
                target = report.with_suffix(".target")
                target.write_text(json.dumps(self.report_payload), encoding="utf-8")
                report.symlink_to(target)
            elif self.report_mode != "missing":
                raise AssertionError(f"unknown report mode: {self.report_mode}")
        return SimpleNamespace(returncode=self.statuses[index])


class RunOsvScanTest(unittest.TestCase):
    def setUp(self) -> None:
        self.scratch = tempfile.TemporaryDirectory()
        self.base = Path(self.scratch.name)
        self.repository = self.base / "candidate"
        self.repository.mkdir()
        self.external = self.base / "trusted"
        self.external.mkdir()
        self.binary = self.external / "osv-scanner"
        self.binary.write_bytes(b"pinned scanner fixture")
        self.binary.chmod(0o755)
        self.config = self.external / "osv-scanner.org.toml"
        self.config.write_text(
            "# organization config intentionally has no ignores\n",
            encoding="utf-8",
        )
        self.report = self.external / "osv.json"

    def tearDown(self) -> None:
        self.scratch.cleanup()

    def run_scan(self, runner: RecordingRunner):
        return run_osv_scan(
            binary=self.binary,
            config=self.config,
            report=self.report,
            repository_root=self.repository,
            runner=runner,
        )

    def test_runs_both_exact_hardened_commands(self) -> None:
        runner = RecordingRunner(statuses=(0, 0))
        payload = self.run_scan(runner)
        self.assertEqual(payload, {"results": []})
        self.assertEqual(len(runner.calls), 2)

        scanner = self.binary.resolve()
        policy = self.config.resolve()
        report = self.report.resolve()
        expected_human, expected_machine = build_scan_commands(
            binary=scanner,
            config=policy,
            report=report,
        )
        self.assertEqual(runner.calls[0][0], expected_human)
        self.assertEqual(runner.calls[1][0], expected_machine)
        for command, kwargs in runner.calls:
            self.assertEqual(command[1 : 1 + len(SCAN_PREFIX)], SCAN_PREFIX)
            self.assertEqual(command[command.index("--config") + 1], str(policy))
            self.assertEqual(kwargs, {"cwd": str(self.repository.resolve()), "check": False})
        self.assertNotIn("--output", expected_human)
        self.assertEqual(
            expected_machine[expected_machine.index("--output") + 1],
            str(report),
        )

    def test_every_command_token_is_mandatory(self) -> None:
        scanner = self.binary.resolve()
        policy = self.config.resolve()
        report = self.report.resolve()
        commands = build_scan_commands(
            binary=scanner,
            config=policy,
            report=report,
        )
        for machine, command in enumerate(commands):
            expected_report = report if machine else None
            for index, token in enumerate(command):
                weakened = command[:index] + command[index + 1 :]
                with self.subTest(machine=bool(machine), omitted=token, index=index):
                    with self.assertRaises(ScanBoundaryError):
                        validate_scan_command(
                            weakened,
                            binary=scanner,
                            config=policy,
                            report=expected_report,
                        )

    def test_required_paths_and_target_cannot_be_replaced(self) -> None:
        scanner = self.binary.resolve()
        policy = self.config.resolve()
        report = self.report.resolve()
        human, machine = build_scan_commands(
            binary=scanner,
            config=policy,
            report=report,
        )
        mutations = []
        for command, expected_report in ((human, None), (machine, report)):
            for token in (str(scanner), str(policy), "."):
                index = command.index(token)
                altered = list(command)
                altered[index] = str(self.repository / "attacker-controlled")
                mutations.append((tuple(altered), expected_report))
        output_index = machine.index(str(report))
        altered_output = list(machine)
        altered_output[output_index] = str(self.repository / "osv.json")
        mutations.append((tuple(altered_output), report))

        for command, expected_report in mutations:
            with self.subTest(command=command):
                with self.assertRaises(ScanBoundaryError):
                    validate_scan_command(
                        command,
                        binary=scanner,
                        config=policy,
                        report=expected_report,
                    )

    def test_rejects_each_path_inside_candidate_repository(self) -> None:
        inside_binary = self.repository / "osv-scanner"
        inside_binary.write_bytes(b"attacker")
        inside_binary.chmod(0o755)
        inside_config = self.repository / "osv-scanner.toml"
        inside_config.write_text("[[PackageOverrides]]\nignore = true\n")

        cases = (
            {
                "binary": inside_binary,
                "config": self.config,
                "report": self.report,
            },
            {
                "binary": self.binary,
                "config": inside_config,
                "report": self.report,
            },
            {
                "binary": self.binary,
                "config": self.config,
                "report": self.repository / "osv.json",
            },
        )
        for case in cases:
            with self.subTest(case=case):
                with self.assertRaises(ScanBoundaryError):
                    run_osv_scan(
                        repository_root=self.repository,
                        runner=RecordingRunner(),
                        **case,
                    )

    def test_rejects_binary_config_and_report_symlinks(self) -> None:
        binary_link = self.external / "scanner-link"
        binary_link.symlink_to(self.binary)
        config_link = self.external / "config-link"
        config_link.symlink_to(self.config)
        report_target = self.external / "existing-report"
        report_target.write_text('{"results": []}', encoding="utf-8")
        report_link = self.external / "report-link"
        report_link.symlink_to(report_target)

        cases = (
            (binary_link, self.config, self.report),
            (self.binary, config_link, self.report),
            (self.binary, self.config, report_link),
        )
        for binary, config, report in cases:
            with self.subTest(binary=binary, config=config, report=report):
                with self.assertRaises(ScanBoundaryError):
                    run_osv_scan(
                        binary=binary,
                        config=config,
                        report=report,
                        repository_root=self.repository,
                        runner=RecordingRunner(),
                    )

    def test_rejects_report_parent_resolving_into_repository(self) -> None:
        linked_parent = self.external / "candidate-link"
        linked_parent.symlink_to(self.repository, target_is_directory=True)
        with self.assertRaises(ScanBoundaryError):
            run_osv_scan(
                binary=self.binary,
                config=self.config,
                report=linked_parent / "osv.json",
                repository_root=self.repository,
                runner=RecordingRunner(),
            )

    def test_human_scan_failure_stops_before_json_scan(self) -> None:
        runner = RecordingRunner(statuses=(2,))
        with self.assertRaises(ScanBoundaryError):
            self.run_scan(runner)
        self.assertEqual(len(runner.calls), 1)
        self.assertFalse(self.report.exists())

    def test_machine_scan_accepts_only_status_zero_or_one(self) -> None:
        for status in (-1, 2, 127, None):
            with self.subTest(status=status):
                runner = RecordingRunner(statuses=(0, status))
                with self.assertRaises(ScanBoundaryError):
                    self.run_scan(runner)
                if self.report.exists() or self.report.is_symlink():
                    self.report.unlink()

    def test_rejects_disagreeing_scan_statuses(self) -> None:
        for statuses in ((0, 1), (1, 0)):
            with self.subTest(statuses=statuses):
                runner = RecordingRunner(statuses=statuses)
                with self.assertRaisesRegex(ScanBoundaryError, "statuses disagree"):
                    self.run_scan(runner)
                if self.report.exists() or self.report.is_symlink():
                    self.report.unlink()

    def test_status_must_match_reported_vulnerability_count(self) -> None:
        finding = {
            "results": [
                {
                    "packages": [
                        {
                            "vulnerabilities": [
                                {"id": "GHSA-mh99-v99m-4gvg"}
                            ]
                        }
                    ]
                }
            ]
        }
        cases = (
            ((1, 1), {"results": []}),
            ((0, 0), finding),
        )
        for statuses, payload in cases:
            with self.subTest(statuses=statuses):
                runner = RecordingRunner(
                    statuses=statuses,
                    report_payload=payload,
                )
                with self.assertRaisesRegex(
                    ScanBoundaryError,
                    "status does not match",
                ):
                    self.run_scan(runner)
                if self.report.exists() or self.report.is_symlink():
                    self.report.unlink()

        accepted = RecordingRunner(statuses=(1, 1), report_payload=finding)
        self.assertEqual(self.run_scan(accepted), finding)

    def test_missing_empty_invalid_or_wrong_shape_reports_fail(self) -> None:
        cases = (
            ("missing", {"results": []}),
            ("empty", {"results": []}),
            ("invalid", {"results": []}),
            ("valid", []),
            ("valid", {}),
            ("valid", {"results": {}}),
        )
        for mode, payload in cases:
            with self.subTest(mode=mode, payload=payload):
                runner = RecordingRunner(
                    report_mode=mode,
                    report_payload=payload,
                    statuses=(0, 0),
                )
                with self.assertRaises(ScanBoundaryError):
                    self.run_scan(runner)
                if self.report.exists() or self.report.is_symlink():
                    self.report.unlink()

    def test_scanner_cannot_return_a_symlink_report(self) -> None:
        runner = RecordingRunner(report_mode="symlink", statuses=(0, 0))
        with self.assertRaises(ScanBoundaryError):
            self.run_scan(runner)

    def test_rejects_preexisting_report_and_non_executable_binary(self) -> None:
        self.report.write_text('{"results": []}', encoding="utf-8")
        with self.assertRaises(ScanBoundaryError):
            self.run_scan(RecordingRunner())
        self.report.unlink()
        self.binary.chmod(0o644)
        with self.assertRaises(ScanBoundaryError):
            self.run_scan(RecordingRunner())


if __name__ == "__main__":
    unittest.main()
