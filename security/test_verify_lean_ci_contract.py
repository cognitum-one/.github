#!/usr/bin/env python3
"""Controlled-red tests for the lean CI/CD ownership boundary."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import unittest

from verify_lean_ci_contract import LeanContractError, verify


class LeanContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        root = Path(__file__).resolve().parents[1]
        cls.contract = json.loads((root / "security/lean-ci-contract-v1.json").read_text(encoding="utf-8"))
        cls.template = (root / "workflow-templates/security.yml").read_text(encoding="utf-8")
        cls.documentation = (root / "SECURITY-SCANNING.md").read_text(encoding="utf-8")
        cls.workflows = {
            name: (root / ".github/workflows" / name).read_text(encoding="utf-8")
            for name in (
                "security-scan.yml",
                "security-release.yml",
                "static-ui-release.yml",
                "static-ui-revision.yml",
            )
        }

    def test_committed_contract_is_valid(self) -> None:
        verify(self.contract, self.template, self.documentation, self.workflows)

    def test_pull_request_or_push_trigger_is_rejected(self) -> None:
        for trigger in ("  pull_request:\n", "  push:\n    branches: [main]\n"):
            with self.subTest(trigger=trigger.strip()):
                mutated = self.template.replace("  schedule:\n", trigger + "  schedule:\n", 1)
                with self.assertRaisesRegex(LeanContractError, "hot-path trigger"):
                    verify(self.contract, mutated, self.documentation, self.workflows)

    def test_protected_product_context_is_rejected(self) -> None:
        mutated = self.template.replace("  fleet-audit:", "  security:", 1)
        with self.assertRaisesRegex(LeanContractError, "protected product security context"):
            verify(self.contract, mutated, self.documentation, self.workflows)

    def test_missing_schedule_is_rejected(self) -> None:
        mutated = self.template.replace('  schedule:\n    - cron: "0 6 * * 1" # Mondays 06:00 UTC — weekly drift sweep\n', "", 1)
        with self.assertRaisesRegex(LeanContractError, "lacks schedule"):
            verify(self.contract, mutated, self.documentation, self.workflows)

    def test_central_release_dependency_inventory_is_fail_closed(self) -> None:
        contract = copy.deepcopy(self.contract)
        contract["product_hot_path"]["prohibited_central_dependencies"].pop()
        with self.assertRaisesRegex(LeanContractError, "prohibition inventory"):
            verify(contract, self.template, self.documentation, self.workflows)

    def test_audit_pin_drift_is_rejected(self) -> None:
        mutated = self.template.replace(
            self.contract["central_audit"]["reusable_scanner"]["pin"], "0" * 40, 1
        )
        with self.assertRaisesRegex(LeanContractError, "versioned central pin"):
            verify(self.contract, mutated, self.documentation, self.workflows)

    def test_declared_caller_path_must_match_the_template(self) -> None:
        contract = copy.deepcopy(self.contract)
        contract["central_audit"]["caller_template"]["path"] = ".github/workflows/security-scan.yml"
        with self.assertRaisesRegex(LeanContractError, "caller-template contract"):
            verify(contract, self.template, self.documentation, self.workflows)

    def test_declared_scanner_path_must_match_the_reusable_workflow(self) -> None:
        contract = copy.deepcopy(self.contract)
        contract["central_audit"]["reusable_scanner"]["path"] = "workflow-templates/security.yml"
        with self.assertRaisesRegex(LeanContractError, "reusable-scanner contract"):
            verify(contract, self.template, self.documentation, self.workflows)

    def test_declared_scanner_events_must_match_the_reusable_workflow(self) -> None:
        workflows = dict(self.workflows)
        workflows["security-scan.yml"] = workflows["security-scan.yml"].replace(
            "  workflow_call:\n", "  schedule:\n    - cron: '0 0 * * 0'\n", 1
        )
        with self.assertRaisesRegex(LeanContractError, "scanner events do not match"):
            verify(self.contract, self.template, self.documentation, workflows)

    def test_central_release_instruction_is_rejected(self) -> None:
        documentation = self.documentation + (
            "\nrelease workflow calls the organization `security-release.yml` WRAPPER.\n"
        )
        with self.assertRaisesRegex(LeanContractError, "prohibited central hot-path guidance"):
            verify(self.contract, self.template, documentation, self.workflows)

    def test_central_static_ui_dependency_instruction_is_rejected(self) -> None:
        workflows = dict(self.workflows)
        workflows["static-ui-revision.yml"] += (
            "\n# caller must make its deploy/promotion job depend on trusted-static-ui-release\n"
        )
        with self.assertRaisesRegex(LeanContractError, "prohibited central hot-path guidance"):
            verify(self.contract, self.template, self.documentation, workflows)

    def test_reference_marker_removal_is_rejected(self) -> None:
        workflows = dict(self.workflows)
        workflows["security-release.yml"] = workflows["security-release.yml"].replace(
            "Legacy reference implementation only", "Central release gate", 1
        )
        with self.assertRaisesRegex(LeanContractError, "not explicitly bounded"):
            verify(self.contract, self.template, self.documentation, workflows)


if __name__ == "__main__":
    unittest.main()
