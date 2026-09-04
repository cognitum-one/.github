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

    def test_callers_cannot_supply_a_mode_or_inherit_secrets(self) -> None:
        self.assertNotIn("mode:", self.source)
        self.assertNotIn("secrets: inherit", self.source)


if __name__ == "__main__":
    unittest.main()
