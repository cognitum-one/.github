#!/usr/bin/env python3
"""Negative controls for the security-scan enforcement mode (advisory on PR).

Three things are pinned here:

1. the shell that resolves the `mode` input inside the `enforcement` job is
   copied verbatim from the workflow and exercised against every event and
   input, including the fail-closed branch for an unknown value;
2. the workflow keeps the grammar that makes the mode safe: the evaluator is
   invoked with the resolved mode, the receipt is published pass or fail, and
   the step exits with the evaluator's status rather than a continue-on-error;
3. the SecurityPolicy/v1 script and test digests embedded in the workflow
   match the committed bytes, because the enforcement job fetches both by
   `job.workflow_sha` and hash-checks them before it evaluates anything.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
import re
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/security-scan.yml"

MODE_CASE = '''
case "${SCAN_MODE_INPUT:-auto}" in
  advisory) SCAN_MODE=advisory ;;
  enforce) SCAN_MODE=enforce ;;
  auto)
    if [ "$GITHUB_EVENT_NAME" = pull_request ]; then
      SCAN_MODE=advisory
    else
      SCAN_MODE=enforce
    fi
    ;;
  *)
    echo "::error::security-scan mode input must be auto, advisory, or enforce; got '${SCAN_MODE_INPUT}'"
    exit 1
    ;;
esac
'''

HASH_PINS = {
    "SECURITY_POLICY_SHA256": "security-policy-v1.json",
    "SECURITY_POLICY_SCRIPT_SHA256": "security_policy.py",
    "SECURITY_POLICY_TEST_SHA256": "test_security_policy.py",
    "SECURITY_FINDINGS_SHA256": "security_findings.py",
}


class ModeResolutionTests(unittest.TestCase):
    def _resolve(self, mode_input: str | None, event: str) -> subprocess.CompletedProcess[str]:
        prelude = "set -euo pipefail\n"
        if mode_input is not None:
            prelude += f"SCAN_MODE_INPUT='{mode_input}'\n"
        script = prelude + f"GITHUB_EVENT_NAME='{event}'\n" + MODE_CASE + 'printf %s "$SCAN_MODE"\n'
        return subprocess.run(["bash", "-c", script], text=True, capture_output=True)

    def test_auto_is_advisory_only_on_pull_request(self) -> None:
        for mode_input in ("auto", "", None):
            with self.subTest(mode_input=mode_input):
                pull = self._resolve(mode_input, "pull_request")
                self.assertEqual((pull.returncode, pull.stdout), (0, "advisory"))
                for event in ("push", "schedule", "workflow_dispatch", "merge_group", "pull_request_target", "release"):
                    with self.subTest(event=event):
                        other = self._resolve(mode_input, event)
                        self.assertEqual((other.returncode, other.stdout), (0, "enforce"))

    def test_explicit_mode_overrides_the_event(self) -> None:
        for event in ("pull_request", "push", "schedule"):
            self.assertEqual(self._resolve("enforce", event).stdout, "enforce")
            self.assertEqual(self._resolve("advisory", event).stdout, "advisory")

    def test_unknown_mode_fails_closed_instead_of_resolving(self) -> None:
        for bogus in ("observe", "Advisory", "ADVISORY", "advisory ", "auto,advisory", "ratchet"):
            with self.subTest(bogus=bogus):
                result = self._resolve(bogus, "pull_request")
                self.assertNotEqual(result.returncode, 0)
                lines = result.stdout.strip().splitlines()
                # Exactly the error line: the resolved mode is never printed.
                self.assertEqual(len(lines), 1, result.stdout)
                self.assertTrue(lines[0].startswith("::error::security-scan mode input must be"), lines[0])


class WorkflowGrammarTests(unittest.TestCase):
    def setUp(self) -> None:
        self.source = WORKFLOW.read_text(encoding="utf-8")

    def test_workflow_embeds_the_tested_mode_resolution_verbatim(self) -> None:
        indented = "\n".join(
            ("          " + line if line else line) for line in MODE_CASE.strip("\n").splitlines()
        )
        self.assertIn(indented, self.source)

    def test_mode_input_is_declared_optional_and_defaults_to_auto(self) -> None:
        block = re.search(r"(?ms)^    inputs:\n      mode:\n(?P<body>.*?)(?=^\S|^    [a-z])", self.source)
        self.assertIsNotNone(block)
        body = block.group("body")
        self.assertIn("required: false", body)
        self.assertIn("type: string", body)
        self.assertIn("default: auto", body)
        self.assertIn("SCAN_MODE_INPUT: ${{ inputs.mode }}", self.source)
        self.assertEqual(self.source.count("${{ inputs.mode }}"), 1)

    def test_evaluator_receives_the_resolved_mode_and_its_status_decides_the_job(self) -> None:
        self.assertIn('--mode "$SCAN_MODE" \\\n            --output "$RECEIPT"', self.source)
        self.assertEqual(self.source.count('--mode "$SCAN_MODE"'), 1)
        self.assertIn("policy_status=$?", self.source)
        self.assertIn('exit "$policy_status"', self.source)
        self.assertNotIn("continue-on-error", self.source)
        self.assertNotIn("|| true", self.source.split("  enforcement:\n", 1)[1])

    def test_receipt_and_advisory_warning_are_published_before_the_exit(self) -> None:
        enforcement = self.source.split("  enforcement:\n", 1)[1]
        for fragment in (
            'if [ -f "$RECEIPT" ]; then',
            'echo "evidence=$(base64 < "$RECEIPT" | tr -d \'\\n\')" >> "$GITHUB_OUTPUT"',
            "::warning::ADVISORY on {event}: SecurityPolicy/v1 verdict is fail and would have FAILED",
            "would have FAILED** in enforce mode",
            'os.environ["GITHUB_STEP_SUMMARY"]',
        ):
            self.assertIn(fragment, enforcement)
        self.assertLess(enforcement.index("::warning::ADVISORY"), enforcement.index('exit "$policy_status"'))

    def test_dependency_findings_are_classified_by_the_same_verified_gate(self) -> None:
        deps = self.source.split("  deps:\n", 1)[1].split("\n  enforcement:\n", 1)[0]
        classify = '--repository-root "$GITHUB_WORKSPACE" --osv-gate "$POLICY_DIR/osv_gate.py")"'
        self.assertEqual(deps.count(classify), 1)
        normalize_step = deps.split("- name: Normalize dependency findings before enforcing", 1)[1]
        normalize_step = normalize_step.split("- name: Enforce OSV dependency policy", 1)[0]
        for name in ("RECEIPT", "INVENTORY", "NONCE", "IMAGE_NAME", "IMAGE_ID"):
            self.assertIn(f"OSV_RUNTIME_{name}: ${{{{ steps.runtime.outputs.{name.lower()} }}}}", normalize_step)
        self.assertLess(deps.index("--osv-gate"), deps.index('python3 "$POLICY_DIR/osv_gate.py"'))

    def test_history_secrets_and_workflow_pin_jobs_have_no_mode_branch(self) -> None:
        for job in ("  secrets:\n", "  workflow-pins:\n", "  deps:\n"):
            start = self.source.index(job)
            end = self.source.index("\n  ", start + len(job))
            body = self.source[start:end]
            self.assertNotIn("SCAN_MODE", body, job)
            self.assertNotIn("inputs.mode", body, job)


class PolicyDigestPinTests(unittest.TestCase):
    def test_embedded_policy_digests_match_the_committed_bytes(self) -> None:
        source = WORKFLOW.read_text(encoding="utf-8")
        for variable, filename in HASH_PINS.items():
            with self.subTest(variable=variable):
                match = re.search(rf'(?m)^  {variable}: "([0-9a-f]{{64}})"$', source)
                self.assertIsNotNone(match, variable)
                actual = hashlib.sha256((ROOT / "security" / filename).read_bytes()).hexdigest()
                self.assertEqual(match.group(1), actual, f"{variable} does not match security/{filename}")


if __name__ == "__main__":
    unittest.main()
