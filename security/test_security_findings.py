#!/usr/bin/env python3
"""No-secret stable-ID tests for scanner finding normalization."""

from __future__ import annotations

import datetime as dt
import hashlib
from pathlib import Path
import tempfile
import unittest

import osv_gate
from security_findings import FindingsError, load_osv_gate, normalize


def _vuln(advisory: str, *, fixed: bool) -> dict:
    events = [{"introduced": "0"}]
    if fixed:
        events.append({"fixed": "9.9.9"})
    return {"id": advisory, "affected": [{"ranges": [{"type": "SEMVER", "events": events}]}]}


def _package(name: str, version: str, vulns: list[dict], scores: dict[str, str | None]) -> dict:
    return {
        "package": {"name": name, "version": version},
        "vulnerabilities": vulns,
        "groups": [{"ids": [advisory], "max_severity": score} for advisory, score in scores.items()],
    }


def _identifier(*fields: str) -> str:
    return "dependencies:" + hashlib.sha256("\0".join(fields).encode()).hexdigest()


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

    def test_osv_absolute_workspace_source_is_canonicalized_before_hashing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = {"results": [{"source": {"path": str(root / "functions/package-lock.json")}, "packages": [{"package": {"name": "fast-uri", "version": "3.1.5"}, "vulnerabilities": [{"id": "GHSA-test"}]}]}]}
            expected = "dependencies:" + hashlib.sha256(
                "\0".join(("functions/package-lock.json", "fast-uri", "3.1.5", "GHSA-test")).encode()
            ).hexdigest()
            self.assertEqual(normalize("dependencies", report, repository_root=root), [expected])
            with self.assertRaisesRegex(FindingsError, "repository root"):
                normalize("dependencies", report)

    def test_missing_or_malformed_reports_fail_closed(self) -> None:
        with self.assertRaises(FindingsError):
            normalize("secrets", {})
        with self.assertRaises(FindingsError):
            normalize("dependencies", {"results": [{}]})
        with self.assertRaises(FindingsError):
            normalize("workflow_pins", [{"kind": "x"}])

    # --- gate-classified dependency findings ---------------------------------

    def _gate_report(self, root: Path) -> dict:
        lock = str(root / "package-lock.json")
        return {"results": [{"source": {"path": lock}, "packages": [
            _package("moderate-fixable", "1.0.0", [_vuln("GHSA-mod", fixed=True)], {"GHSA-mod": "5.3"}),
            _package("high-fixable", "2.0.0", [_vuln("GHSA-high", fixed=True)], {"GHSA-high": "8.1"}),
            _package("critical-unfixable", "3.0.0", [_vuln("GHSA-nofix", fixed=False)], {"GHSA-nofix": "9.8"}),
            _package("unrated-fixable", "4.0.0", [_vuln("GHSA-unrated", fixed=True)], {"GHSA-unrated": None}),
        ]}]}

    def test_gate_classification_keeps_only_the_rows_the_gate_would_block(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = self._gate_report(root)
            classified = normalize(
                "dependencies", report, repository_root=root, osv_gate=osv_gate,
                repository="example/unregistered", today=dt.date(2026, 9, 10),
            )
            self.assertEqual(classified, sorted([
                _identifier("package-lock.json", "high-fixable", "2.0.0", "GHSA-high"),
                _identifier("package-lock.json", "unrated-fixable", "4.0.0", "GHSA-unrated"),
            ]))
            # The historical shape is unchanged: every advisory is a finding.
            self.assertEqual(len(normalize("dependencies", report, repository_root=root)), 4)
            # Classified IDs are the same IDs the historical shape would emit
            # for those rows, so ratchet baselines keep matching.
            self.assertTrue(set(classified) <= set(normalize("dependencies", report, repository_root=root)))

    def test_gate_classification_agrees_with_the_gate_exit_verdict(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            moderate_only = {"results": [{"source": {"path": str(root / "package-lock.json")}, "packages": [
                _package("moderate-fixable", "1.0.0", [_vuln("GHSA-mod", fixed=True)], {"GHSA-mod": "5.3"}),
                _package("critical-unfixable", "3.0.0", [_vuln("GHSA-nofix", fixed=False)], {"GHSA-nofix": "9.8"}),
            ]}]}
            blocking, _ = osv_gate.evaluate(moderate_only, repository="example/unregistered", root=root, today=dt.date(2026, 9, 10))
            self.assertEqual(blocking, [])
            self.assertEqual(normalize("dependencies", moderate_only, repository_root=root, osv_gate=osv_gate,
                                       repository="example/unregistered", today=dt.date(2026, 9, 10)), [])

    def test_gate_classification_fails_closed_on_malformed_reports_and_misuse(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            malformed = {"results": [{"source": {"path": str(root / "package-lock.json")}, "packages": [
                _package("bad", "1.0.0", [_vuln("GHSA-bad", fixed=True)], {"GHSA-bad": "not-a-score"}),
            ]}]}
            with self.assertRaisesRegex(FindingsError, "OSV gate refused"):
                normalize("dependencies", malformed, repository_root=root, osv_gate=osv_gate, repository="x/y")
            with self.assertRaisesRegex(FindingsError, "repository root"):
                normalize("dependencies", self._gate_report(root), osv_gate=osv_gate, repository="x/y")
            with self.assertRaisesRegex(FindingsError, "dependencies control only"):
                normalize("secrets", [], osv_gate=osv_gate)
            with self.assertRaisesRegex(FindingsError, "OSV gate module"):
                load_osv_gate(root / "missing.py")
            loaded = load_osv_gate(Path(__file__).with_name("osv_gate.py"))
            self.assertTrue(callable(loaded.evaluate))


if __name__ == "__main__":
    unittest.main()
