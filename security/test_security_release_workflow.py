#!/usr/bin/env python3
"""Static mutation tests for the exact-candidate release security wrapper."""

from __future__ import annotations

from pathlib import Path
import re
import unittest


class SecurityReleaseWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.source = (
            Path(__file__).parents[1] / ".github/workflows/security-release.yml"
        ).read_text(encoding="utf-8")

    def test_calls_the_v1_scan_at_a_full_immutable_sha(self) -> None:
        match = re.search(r"security-scan\.yml@([^\s]+)", self.source)
        self.assertIsNotNone(match)
        self.assertRegex(match.group(1), r"^[0-9a-f]{40}$")
        self.assertNotIn("security-scan.yml@main", self.source)

    def test_release_cannot_accept_a_stale_or_failed_rerun(self) -> None:
        self.assertIn('test "$SECURITY_RESULT" = success', self.source)
        self.assertIn('[[ "$CANDIDATE_SHA" =~ ^[0-9a-f]{40}$ ]]', self.source)
        self.assertIn('test "$CANDIDATE_SHA" = "$GITHUB_SHA"', self.source)
        self.assertIn("needs.security.outputs.evidence", self.source)
        self.assertIn("--release-rerun", self.source)
        self.assertIn('"verdict": "pass"', self.source)

    def test_callers_cannot_supply_a_mode_or_inherit_secrets(self) -> None:
        self.assertNotIn("mode:", self.source)
        self.assertNotIn("secrets: inherit", self.source)
        self.assertNotIn("release_rerun:", self.source)
        scan = (Path(__file__).parents[1] / ".github/workflows/security-scan.yml").read_text(encoding="utf-8")
        self.assertNotIn("release_rerun:", scan)
        self.assertNotIn("--release-rerun", scan)


if __name__ == "__main__":
    unittest.main()
