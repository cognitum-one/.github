#!/usr/bin/env python3
"""Fail-closed structural verifier for the local-first lean CI/CD contract."""

from __future__ import annotations

import json
from pathlib import Path
import re


class LeanContractError(ValueError):
    pass


EXPECTED_CONTEXTS = ["ci / enforcement", "security / enforcement"]
EXPECTED_CENTRAL_ROLES = [
    "reference-implementation",
    "optional-template",
    "scheduled-fleet-audit",
    "drift-reporting",
]
EXPECTED_PROHIBITED = [
    ".github/workflows/security-scan.yml",
    ".github/workflows/security-release.yml",
    ".github/workflows/static-ui-release.yml",
    ".github/workflows/static-ui-revision.yml",
]


def fail(message: str) -> None:
    raise LeanContractError(message)


def verify(contract: dict, template: str, documentation: str, workflows: dict[str, str]) -> None:
    if contract.get("schema") != "cognitum-lean-ci-contract/v1":
        fail("contract schema is missing or unsupported")
    hot_path = contract.get("product_hot_path")
    if not isinstance(hot_path, dict) or hot_path.get("owner") != "product-repository":
        fail("product hot-path ownership is not repository-local")
    if hot_path.get("stable_contexts") != EXPECTED_CONTEXTS:
        fail("stable product enforcement contexts changed")
    if hot_path.get("prohibited_central_dependencies") != EXPECTED_PROHIBITED:
        fail("central hot-path prohibition inventory changed")
    if contract.get("central_roles") != EXPECTED_CENTRAL_ROLES:
        fail("central tooling roles changed")
    audit = contract.get("central_audit_workflow")
    if not isinstance(audit, dict) or audit.get("path") != ".github/workflows/security-scan.yml" or audit.get("events") != ["schedule", "workflow_dispatch"]:
        fail("central audit workflow contract changed")
    pin = audit.get("pin")
    if not isinstance(pin, str) or not re.fullmatch(r"[0-9a-f]{40}", pin):
        fail("central audit workflow pin is not immutable")

    trigger = re.search(r"(?ms)^on:\n(?P<body>.*?)(?=^permissions:)", template)
    if not trigger:
        fail("fleet audit template trigger block is missing")
    trigger_body = trigger.group("body")
    for forbidden in ("pull_request:", "pull_request_target:", "push:", "merge_group:"):
        if forbidden in trigger_body:
            fail(f"fleet audit template has product hot-path trigger: {forbidden}")
    for required in ("workflow_dispatch:", "schedule:"):
        if required not in trigger_body:
            fail(f"fleet audit template lacks {required}")
    if re.search(r"(?m)^  security:\s*$", template) or re.search(r"(?m)^    name: security\s*$", template):
        fail("fleet audit template can produce the protected product security context")
    for required in ("  fleet-audit:", "    name: fleet audit"):
        if required not in template:
            fail(f"fleet audit template lacks {required.strip()}")
    if f"security-scan.yml@{pin}" not in template:
        fail("fleet audit template does not match its versioned central pin")

    for phrase in (
        "Product hot-path ownership is local",
        "must not depend on any reusable workflow in this repository",
        "scheduled fleet audits",
        "drift reporting",
        "reference implementation",
    ):
        if phrase not in documentation:
            fail(f"architecture documentation lacks: {phrase}")

    required_markers = {
        "security-scan.yml": "Reference and scheduled fleet-audit scanner",
        "security-release.yml": "Legacy reference implementation only",
        "static-ui-release.yml": "Legacy reference implementation",
        "static-ui-revision.yml": "Reference receipt tooling only",
    }
    for name, marker in required_markers.items():
        if marker not in workflows.get(name, ""):
            fail(f"{name} is not explicitly bounded as reference tooling")


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    contract = json.loads((root / "security/lean-ci-contract-v1.json").read_text(encoding="utf-8"))
    template = (root / "workflow-templates/security.yml").read_text(encoding="utf-8")
    documentation = (root / "SECURITY-SCANNING.md").read_text(encoding="utf-8")
    workflow_dir = root / ".github/workflows"
    workflows = {
        name: (workflow_dir / name).read_text(encoding="utf-8")
        for name in (
            "security-scan.yml",
            "security-release.yml",
            "static-ui-release.yml",
            "static-ui-revision.yml",
        )
    }
    verify(contract, template, documentation, workflows)
    print("Lean CI/CD ownership contract passed.")


if __name__ == "__main__":
    main()
