#!/usr/bin/env python3
"""Controlled-failure tests for the stable security enforcement context."""

from __future__ import annotations

import unittest

from enforcement_gate import EnforcementError, enforce


class EnforcementGateTests(unittest.TestCase):
    def test_clean_pull_request_passes_with_history_skipped(self) -> None:
        enforce(
            event="pull_request",
            secrets="success",
            dependencies="success",
            workflow_pins="success",
            history="skipped",
        )

    def test_clean_scheduled_run_requires_history_integrity(self) -> None:
        enforce(
            event="schedule",
            secrets="success",
            dependencies="success",
            workflow_pins="success",
            history="success",
        )

    def test_current_tree_secret_failure_blocks(self) -> None:
        self._assert_blocked(secrets="failure")

    def test_fixable_dependency_failure_blocks(self) -> None:
        self._assert_blocked(dependencies="failure")

    def test_mutable_workflow_reference_blocks(self) -> None:
        self._assert_blocked(workflow_pins="failure")

    def test_cancelled_or_missing_control_fails_closed(self) -> None:
        self._assert_blocked(dependencies="cancelled")

    def test_history_integrity_failure_blocks_audit_event(self) -> None:
        self._assert_blocked(event="workflow_dispatch", history="failure")

    def test_unexpected_history_execution_blocks_pull_request(self) -> None:
        self._assert_blocked(history="success")

    def _assert_blocked(self, **overrides: str) -> None:
        results = {
            "event": "pull_request",
            "secrets": "success",
            "dependencies": "success",
            "workflow_pins": "success",
            "history": "skipped",
        }
        results.update(overrides)
        with self.assertRaises(EnforcementError):
            enforce(**results)


if __name__ == "__main__":
    unittest.main()
