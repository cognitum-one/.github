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
from security_policy import apply_enforcement_mode, enforced_blocking, evaluate, load_policy


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


class StrictProfileContractTests(unittest.TestCase):
    """End to end: gate-classified findings -> SecurityPolicy/v1 strict verdict.

    Lives here rather than in test_security_policy.py on purpose: the
    enforcement job fetches and runs test_security_policy.py with only the
    policy, evaluator and findings modules beside it, and this test needs the
    OSV gate as well.
    """

    def setUp(self) -> None:
        self.path = Path(__file__).with_name("security-policy-v1.json")
        self.policy = load_policy(self.path, hashlib.sha256(self.path.read_bytes()).hexdigest())

    def _completions(self, findings: dict[str, list[str]]) -> dict[str, dict[str, object]]:
        return {
            control: {
                "schema": "security-producer-evidence-v1",
                "producer": f"cognitum-one/.github/.github/workflows/security-scan.yml#{control}",
                "control": control, "source_sha": "a" * 40, "workflow_sha": "b" * 40,
                "state": "completed", "findings": sorted(set(values)),
            }
            for control, values in findings.items()
        }

    def _with_findings(self, findings: dict[str, list[str]], **overrides: object) -> dict[str, object]:
        return dict(
            policy=self.policy, source_sha="a" * 40, workflow_sha="b" * 40,
            producer="cognitum-one/.github/.github/workflows/security-scan.yml",
            results={"secrets": "success", "dependencies": "success", "workflow_pins": "success"},
            findings=findings, completions=self._completions(findings), **overrides,
        )

    def _osv_report(self, root: Path, *rows: tuple[str, str, str, bool, str | None]) -> dict[str, object]:
        packages = []
        for name, version, advisory, fixed, score in rows:
            events = [{"introduced": "0"}] + ([{"fixed": "9.9.9"}] if fixed else [])
            packages.append({
                "package": {"name": name, "version": version},
                "vulnerabilities": [{"id": advisory, "affected": [{"ranges": [{"type": "SEMVER", "events": events}]}]}],
                "groups": [{"ids": [advisory], "max_severity": score}],
            })
        return {"results": [{"source": {"path": str(root / "package-lock.json")}, "packages": packages}]}

    def _strict_verdict_for(self, report: dict[str, object], root: Path) -> dict[str, object]:
        today = dt.date(2026, 9, 10)
        counted = normalize("dependencies", report, repository_root=root, osv_gate=osv_gate,
                            repository="example/unregistered", today=today)
        observed = normalize("dependencies", report, repository_root=root)
        findings = {"secrets": [], "dependencies": counted, "workflow_pins": []}
        receipt = evaluate(**self._with_findings(
            findings, repository_id="9999999999", repository="example/unregistered", today=today,
        ), advisories={"dependencies": observed})
        self.assertEqual(receipt["profile"], "strict")
        self.assertEqual(receipt["advisories"]["dependencies"], observed)
        return receipt

    def test_strict_counts_only_fixable_high_critical_dependency_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            # meta-llm shape (#100): one non-fixable adm-zip + Moderates -> pass.
            moderate_only = self._osv_report(
                root,
                ("adm-zip", "0.5.10", "GHSA-vwc7-r8mq-g2x9", False, "5.5"),
                ("pkg-a", "1.0.0", "GHSA-mod-a", True, "5.3"),
                ("pkg-b", "1.0.0", "GHSA-mod-b", True, "6.9"),
            )
            receipt = self._strict_verdict_for(moderate_only, root)
            self.assertEqual(receipt["verdict"], "pass")
            self.assertEqual(receipt["findings"]["dependencies"], [])
            self.assertEqual(len(receipt["advisories"]["dependencies"]), 3)
            # console shape (#98): non-fixable High/Critical only -> pass.
            unfixable_high = self._osv_report(
                root,
                ("rustcrate", "0.1.0", "RUSTSEC-2026-9999", False, "9.8"),
                ("rustcrate2", "0.2.0", "GHSA-high-nofix", False, "7.5"),
            )
            receipt = self._strict_verdict_for(unfixable_high, root)
            self.assertEqual(receipt["verdict"], "pass")
            self.assertEqual(receipt["findings"]["dependencies"], [])
            self.assertEqual(len(receipt["advisories"]["dependencies"]), 2)
            # Negative control: one fixable High among them still fails enforce.
            with_fixable_high = dict(moderate_only)
            with_fixable_high = self._osv_report(
                root,
                ("adm-zip", "0.5.10", "GHSA-vwc7-r8mq-g2x9", False, "5.5"),
                ("pkg-a", "1.0.0", "GHSA-mod-a", True, "5.3"),
                ("pkg-h", "2.0.0", "GHSA-high-fix", True, "8.8"),
            )
            receipt = self._strict_verdict_for(with_fixable_high, root)
            self.assertEqual(receipt["verdict"], "fail")
            self.assertEqual(len(receipt["findings"]["dependencies"]), 1)
            self.assertEqual(len(receipt["advisories"]["dependencies"]), 3)
            self.assertIn("dependencies has finding(s)", receipt["blocking"][0])
            # ...and a fixable advisory OSV has not scored still fails (unrated != low).
            unrated = self._osv_report(root, ("pkg-u", "1.0.0", "GHSA-unrated-fix", True, None))
            self.assertEqual(self._strict_verdict_for(unrated, root)["verdict"], "fail")
            # Advisory mode waives exactly that fixable-High refusal and nothing else.
            annotated = apply_enforcement_mode(receipt, "advisory")
            self.assertEqual(annotated["advisory"], receipt["blocking"])
            self.assertEqual(enforced_blocking(annotated), [])


if __name__ == "__main__":
    unittest.main()
