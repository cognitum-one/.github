#!/usr/bin/env python3
"""No-secret stable-ID tests for scanner finding normalization."""

from __future__ import annotations

import unittest

from security_findings import FindingsError, normalize


class SecurityFindingsTests(unittest.TestCase):
    def test_gitleaks_ids_do_not_disclose_match_bytes(self) -> None:
        findings = normalize("secrets", [{"RuleID": "token", "File": "a.txt", "StartLine": 4, "Secret": "never-emit"}])
        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0].startswith("secrets:"))
        self.assertNotIn("never-emit", findings[0])

    def test_osv_and_workflow_ids_are_stable_and_deduplicated(self) -> None:
        osv = {"results": [{"source": {"path": "package-lock.json"}, "packages": [{"package": {"name": "pkg", "version": "1.0.0"}, "vulnerabilities": [{"id": "GHSA-test"}, {"id": "GHSA-test"}]}]}]}
        self.assertEqual(normalize("dependencies", osv), normalize("dependencies", osv))
        self.assertEqual(len(normalize("dependencies", osv)), 1)
        workflow = [{"kind": "action", "path": ".github/a.yml", "line": 5, "reason": "mutable"}]
        self.assertTrue(normalize("workflow_pins", workflow)[0].startswith("workflow_pins:"))

    def test_missing_or_malformed_reports_fail_closed(self) -> None:
        with self.assertRaises(FindingsError):
            normalize("secrets", {})
        with self.assertRaises(FindingsError):
            normalize("dependencies", {"results": [{}]})
        with self.assertRaises(FindingsError):
            normalize("workflow_pins", [{"kind": "x"}])


if __name__ == "__main__":
    unittest.main()
