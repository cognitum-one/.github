#!/usr/bin/env python3
"""Adversarial tests for SecurityPolicy/v1 and its evidence contract."""

from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from security_findings import normalize
from security_policy import PolicyError, evaluate, load_policy


class SecurityPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.path = Path(__file__).with_name("security-policy-v1.json")
        self.digest = hashlib.sha256(self.path.read_bytes()).hexdigest()
        self.policy = load_policy(self.path, self.digest)
        findings = {"secrets": [], "dependencies": [], "workflow_pins": []}
        self.good = dict(
            policy=self.policy, repository_id="1211713708", repository="cognitum-one/cognitum",
            source_sha="a" * 40, workflow_sha="b" * 40,
            producer="cognitum-one/.github/.github/workflows/security-scan.yml",
            results={"secrets": "success", "dependencies": "success", "workflow_pins": "success"},
            findings=findings,
            completions=self._completions(findings), today=dt.date(2026, 9, 4),
        )

    def _completions(self, findings: dict[str, list[str]]) -> dict[str, dict[str, object]]:
        return {
            control: {
                "schema": "security-producer-evidence-v1",
                "producer": f"cognitum-one/.github/.github/workflows/security-scan.yml#{control}",
                "control": control,
                "source_sha": "a" * 40,
                "workflow_sha": "b" * 40,
                "state": "completed",
                "findings": sorted(set(values)),
            }
            for control, values in findings.items()
        }

    def _with_findings(self, findings: dict[str, list[str]], **overrides: object) -> dict[str, object]:
        return dict(self.good, findings=findings, completions=self._completions(findings), **overrides)

    def _baseline(
        self, *, identifier: str = "owned", repository_id: str = "1211713708", finding: str = "GHSA-old",
        expires_at: str = "2026-09-30",
    ) -> dict[str, object]:
        return {
            "id": identifier,
            "repository_id": repository_id,
            "control": "dependencies",
            "owner": "security",
            "expires_at": expires_at,
            "evidence": {
                "repository": "cognitum-one/cognitum",
                "pull_request": 1,
                "run_id": "1",
                "source_sha": "c" * 40,
                "base_sha": "d" * 40,
                "workflow_sha": "e" * 40,
                "lockfile_blobs": {"package-lock.json": "f" * 40},
            },
            "findings": [finding],
        }

    def test_registered_id_selects_mixed_centrally_owned_profile(self) -> None:
        receipt = evaluate(**self.good)
        self.assertEqual(receipt["profile"], "cognitum-pilot")
        self.assertEqual(receipt["controls"]["dependencies"], "ratchet")
        self.assertEqual(receipt["verdict"], "pass")

    def test_unregistered_caller_retains_full_strict_behavior(self) -> None:
        data = dict(self.good, repository_id="9999999999", repository="example/unregistered")
        receipt = evaluate(**data)
        self.assertEqual(receipt["profile"], "strict")
        self.assertEqual(set(receipt["controls"].values()), {"enforce"})

    def test_policy_bytes_are_hash_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            changed = Path(temporary) / "policy.json"
            changed.write_bytes(self.path.read_bytes() + b" ")
            with self.assertRaisesRegex(PolicyError, "policy bytes"):
                load_policy(changed, self.digest)

    def test_mutable_or_stale_shas_are_refused(self) -> None:
        for key, value in (("source_sha", "main"), ("workflow_sha", "v1")):
            with self.subTest(key=key), self.assertRaisesRegex(PolicyError, "full SHA"):
                evaluate(**dict(self.good, **{key: value}))

    def test_wrong_producer_and_repository_id_spoof_are_refused(self) -> None:
        with self.assertRaisesRegex(PolicyError, "producer"):
            evaluate(**dict(self.good, producer="attacker/workflow"))
        with self.assertRaisesRegex(PolicyError, "immutable registry"):
            evaluate(**dict(self.good, repository="cognitum-one/website"))

    def test_missing_skipped_and_mutable_workflow_checks_fail_closed(self) -> None:
        for result in ("skipped", "cancelled", "failure"):
            with self.subTest(result=result):
                receipt = evaluate(**dict(self.good, results={**self.good["results"], "workflow_pins": result}))
                self.assertEqual(receipt["verdict"], "fail")
        with self.assertRaisesRegex(PolicyError, "missing or skipped"):
            evaluate(**dict(self.good, results={"secrets": "success"}))

    def test_ratchet_blocks_a_new_dependency_finding(self) -> None:
        receipt = evaluate(**self._with_findings({"secrets": [], "dependencies": ["GHSA-new"], "workflow_pins": []}))
        self.assertEqual(receipt["verdict"], "fail")
        self.assertIn("GHSA-new", receipt["blocking"][0])
        self.assertEqual(receipt["findings"]["dependencies"], ["GHSA-new"])

    def test_expired_owned_baseline_blocks(self) -> None:
        policy = copy.deepcopy(self.policy)
        policy["baselines"] = [self._baseline(expires_at="2026-09-04")]
        with self.assertRaisesRegex(PolicyError, "expired"):
            evaluate(**self._with_findings({"secrets": [], "dependencies": ["GHSA-old"], "workflow_pins": []}, policy=policy))

    def test_owned_baseline_receipt_records_its_expiry(self) -> None:
        policy = copy.deepcopy(self.policy)
        policy["baselines"] = [self._baseline()]
        receipt = evaluate(**self._with_findings({"secrets": [], "dependencies": ["GHSA-old"], "workflow_pins": []}, policy=policy))
        self.assertEqual(receipt["verdict"], "pass")
        self.assertEqual(receipt["exceptions"][0]["baselines"]["GHSA-old"][0]["expires_at"], "2026-09-30")
        self.assertEqual(receipt["exceptions"][0]["baselines"]["GHSA-old"][0]["evidence"]["run_id"], "1")

    def test_foreign_baseline_cannot_match_a_pilot_finding(self) -> None:
        policy = copy.deepcopy(self.policy)
        policy["baselines"] = [self._baseline(repository_id="1235738436")]
        receipt = evaluate(**self._with_findings({"secrets": [], "dependencies": ["GHSA-old"], "workflow_pins": []}, policy=policy))
        self.assertEqual(receipt["verdict"], "fail")
        self.assertEqual(receipt["baseline_matches"]["dependencies"], [])

    def test_duplicate_baseline_id_fails_closed_before_it_can_merge_findings(self) -> None:
        policy = copy.deepcopy(self.policy)
        first = self._baseline(identifier="duplicate", finding="GHSA-old")
        second = self._baseline(identifier="duplicate", repository_id="1270428105", finding="GHSA-new")
        policy["baselines"] = [first, second]
        with self.assertRaisesRegex(PolicyError, "baseline ID is duplicated"):
            evaluate(**self._with_findings(
                {"secrets": [], "dependencies": ["GHSA-old"], "workflow_pins": []}, policy=policy
            ))

    def test_overlapping_repository_control_baselines_fail_instead_of_unioning_findings(self) -> None:
        policy = copy.deepcopy(self.policy)
        first = self._baseline(identifier="first", finding="GHSA-old")
        second = self._baseline(identifier="second", finding="GHSA-new")
        policy["baselines"] = [first, second]
        # Before this guard the two separately owned records unioned and passed
        # both findings, silently broadening the dependencies ratchet.
        with self.assertRaisesRegex(PolicyError, "baseline ownership overlaps"):
            evaluate(**self._with_findings(
                {"secrets": [], "dependencies": ["GHSA-old", "GHSA-new"], "workflow_pins": []}, policy=policy
            ))

    def test_website_owned_baseline_matches_only_its_exact_finding_set(self) -> None:
        baseline = self.policy["baselines"][0]
        self.assertEqual(baseline["id"], "website-dependencies-20260904")
        self.assertEqual(baseline["repository_id"], "1235738436")
        self.assertEqual(baseline["expires_at"], "2026-10-04")
        self.assertEqual(baseline["evidence"]["run_id"], "33853258319")
        self.assertEqual(baseline["evidence"]["lockfile_blobs"], {
            "package-lock.json": "c03fd819551cfb456058c0833807fe89a1f9ad8b",
            "functions/package-lock.json": "dc10bd277e49e2b8c1a35b2e254c4f5d6bdd7d2b",
            "apps/news/package-lock.json": "69573f4c5b6e3d6f80ab831381762ed2063ab747",
            "management-ui/package-lock.json": "c8be21b55d8da9c165d780be920c997f03899943",
        })
        self.assertEqual(len(baseline["findings"]), 14)
        historic_report = {
            "results": [
                {
                    "source": {"path": source},
                    "packages": [{
                        "package": {"name": "fast-uri", "version": "3.1.5"},
                        "vulnerabilities": [{"id": advisory} for advisory in (
                            "GHSA-5jgf-p345-68v8", "GHSA-f65p-4m7j-42xc",
                            "GHSA-fph4-wmhf-6fwf", "GHSA-jqff-g426-hqxp",
                        )],
                    }],
                }
                for source in ("package-lock.json", "functions/package-lock.json", "apps/news/package-lock.json")
            ] + [{
                "source": {"path": "package-lock.json"},
                "packages": [{
                    "package": {"name": "fflate", "version": version},
                    "vulnerabilities": [{"id": "GHSA-px8p-9vwx-vf98"}],
                } for version in ("0.6.10", "0.8.2")],
            }],
        }
        self.assertEqual(normalize("dependencies", historic_report), baseline["findings"])
        findings = {"secrets": [], "dependencies": baseline["findings"], "workflow_pins": []}
        data = self._with_findings(
            findings, repository_id="1235738436", repository="cognitum-one/website"
        )
        receipt = evaluate(**data)
        self.assertEqual(receipt["verdict"], "pass")
        self.assertEqual(receipt["baseline_matches"]["dependencies"], baseline["findings"])
        receipt = evaluate(**self._with_findings(
            {"secrets": [], "dependencies": [*baseline["findings"], "dependencies:new"], "workflow_pins": []},
            repository_id="1235738436", repository="cognitum-one/website",
        ))
        self.assertEqual(receipt["verdict"], "fail")
        self.assertIn("dependencies:new", receipt["blocking"][0])

    def test_website_baseline_never_downgrades_secrets_or_workflow_pins(self) -> None:
        baseline = self.policy["baselines"][0]["findings"]
        for control, finding in (("secrets", "secrets:known"), ("workflow_pins", "workflow_pins:mutable")):
            with self.subTest(control=control):
                findings = {"secrets": [], "dependencies": baseline, "workflow_pins": []}
                findings[control] = [finding]
                receipt = evaluate(**self._with_findings(
                    findings, repository_id="1235738436", repository="cognitum-one/website",
                ))
                self.assertEqual(receipt["verdict"], "fail")
                self.assertIn(control, receipt["blocking"][0])

    def test_caller_has_no_mode_or_baseline_downgrade_input(self) -> None:
        with self.assertRaises(TypeError):
            evaluate(**dict(self.good, mode="observe"))
        with self.assertRaises(TypeError):
            evaluate(**dict(self.good, baseline=[]))

    def test_missing_finding_evidence_fails_closed(self) -> None:
        with self.assertRaisesRegex(PolicyError, "findings are missing"):
            evaluate(**dict(self.good, findings={"secrets": [], "dependencies": []}, completions={}))

    def test_observe_reports_completed_findings_without_blocking(self) -> None:
        findings = {"secrets": ["secrets:observed"], "dependencies": [], "workflow_pins": []}
        policy = copy.deepcopy(self.policy)
        policy["repositories"]["1270428105"]["profile"] = "university-pilot"
        receipt = evaluate(**self._with_findings(findings, policy=policy, repository_id="1270428105", repository="cognitum-one/university"))
        self.assertEqual(receipt["verdict"], "pass")
        self.assertEqual(receipt["findings"]["secrets"], ["secrets:observed"])

    def test_observe_cannot_swallow_failure_or_partial_evidence(self) -> None:
        findings = {"secrets": ["secrets:observed"], "dependencies": [], "workflow_pins": []}
        policy = copy.deepcopy(self.policy)
        data = self._with_findings(findings, policy=policy, repository_id="1270428105", repository="cognitum-one/university")
        self.assertEqual(evaluate(**dict(data, results={**data["results"], "secrets": "failure"}))["verdict"], "fail")
        partial = copy.deepcopy(data["completions"])
        partial["secrets"]["state"] = "partial"
        with self.assertRaisesRegex(PolicyError, "completion evidence"):
            evaluate(**dict(data, completions=partial))

    def test_enforce_blocks_a_completed_finding(self) -> None:
        findings = {"secrets": ["secrets:known"], "dependencies": [], "workflow_pins": []}
        receipt = evaluate(**self._with_findings(findings, repository_id="9999999999", repository="example/unregistered"))
        self.assertEqual(receipt["verdict"], "fail")

    def test_missing_or_wrong_producer_completion_blocks(self) -> None:
        partial = copy.deepcopy(self.good["completions"])
        del partial["secrets"]
        with self.assertRaisesRegex(PolicyError, "completion evidence"):
            evaluate(**dict(self.good, completions=partial))
        wrong = copy.deepcopy(self.good["completions"])
        wrong["secrets"]["producer"] = "attacker"
        with self.assertRaisesRegex(PolicyError, "wrong-producer"):
            evaluate(**dict(self.good, completions=wrong))

    def test_release_requires_exact_independent_candidate_rerun(self) -> None:
        policy = copy.deepcopy(self.policy)
        policy["repositories"]["1235738436"]["profile"] = "release-candidate"
        data = dict(self.good, policy=policy, repository_id="1235738436", repository="cognitum-one/website")
        self.assertEqual(evaluate(**data)["verdict"], "fail")
        self.assertEqual(evaluate(**dict(data, release_rerun=True, release_candidate_sha="a" * 40))["verdict"], "pass")
        self.assertEqual(evaluate(**dict(data, release_rerun=True, release_candidate_sha="c" * 40))["verdict"], "fail")


if __name__ == "__main__":
    unittest.main()
