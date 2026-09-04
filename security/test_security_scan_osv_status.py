#!/usr/bin/env python3
"""Shell-level negative controls for OSV finding versus integrity statuses."""

from __future__ import annotations

from pathlib import Path
import subprocess
import unittest


BRANCH = r'''
set -euo pipefail
set +e
fake_osv_gate
gate_status=$?
set -e
if [ "$gate_status" -eq 1 ]; then
  test "$FINDINGS" != '[]'
elif [ "$gate_status" -ne 0 ]; then
  exit "$gate_status"
fi
'''


class OsvStatusBoundaryTests(unittest.TestCase):
    def _run(self, status: int, findings: str) -> subprocess.CompletedProcess[str]:
        script = f"fake_osv_gate() {{ return {status}; }}\nFINDINGS='{findings}'\n{BRANCH}"
        return subprocess.run(["bash", "-c", script], text=True, capture_output=True)

    def test_completed_finding_verdict_is_the_only_delegable_nonzero(self) -> None:
        self.assertEqual(self._run(1, '["dependencies:known"]').returncode, 0)
        self.assertNotEqual(self._run(1, "[]").returncode, 0)

    def test_tamper_status_with_unrelated_findings_still_fails(self) -> None:
        # osv_gate.py uses 2 for malformed reports and runtime receipt/nonce/image
        # tamper. A nonempty OSV report must never suppress that integrity failure.
        self.assertEqual(self._run(2, '["dependencies:unrelated"]').returncode, 2)

    def test_workflow_uses_the_same_explicit_status_boundary(self) -> None:
        source = (Path(__file__).parents[1] / ".github/workflows/security-scan.yml").read_text(encoding="utf-8")
        self.assertIn('if [ "$gate_status" -eq 1 ]; then', source)
        self.assertIn('elif [ "$gate_status" -ne 0 ]; then', source)
        self.assertIn('exit "$gate_status"', source)


if __name__ == "__main__":
    unittest.main()
