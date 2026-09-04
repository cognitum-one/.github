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

from security_policy import PolicyError, evaluate, load_policy


class SecurityPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.path = Path(__file__).with_name("security-policy-v1.json")
        self.digest = hashlib.sha256(self.path.read_bytes()).hexdigest()
        self.policy = load_policy(self.path, self.digest)
        self.good = dict(
            policy=self.policy, repository_id="1211713708", repository="cognitum-one/cognitum",
            source_sha="a" * 40, workflow_sha="b" * 40,
            producer="cognitum-one/.github/.github/workflows/security-scan.yml",
            results={"secrets": "success", "dependencies": "success", "workflow_pins": "success"},
            findings={"secrets": [], "dependencies": [], "workflow_pins": []}, today=dt.date(2026, 9, 4),
        )

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
        receipt = evaluate(**dict(self.good, findings={"secrets": [], "dependencies": ["GHSA-new"], "workflow_pins": []}))
        self.assertEqual(receipt["verdict"], "fail")
        self.assertIn("GHSA-new", receipt["blocking"][0])
        self.assertEqual(receipt["findings"]["dependencies"], ["GHSA-new"])

    def test_expired_owned_baseline_blocks(self) -> None:
        policy = copy.deepcopy(self.policy)
        policy["baselines"] = [{"id": "old", "repository_id": "1211713708", "control": "dependencies", "owner": "security", "expires_at": "2026-09-04", "findings": ["GHSA-old"]}]
        with self.assertRaisesRegex(PolicyError, "expired"):
            evaluate(**dict(self.good, policy=policy, findings={"secrets": [], "dependencies": ["GHSA-old"], "workflow_pins": []}))

    def test_owned_baseline_receipt_records_its_expiry(self) -> None:
        policy = copy.deepcopy(self.policy)
        policy["baselines"] = [{"id": "owned", "repository_id": "1211713708", "control": "dependencies", "owner": "security", "expires_at": "2026-09-30", "findings": ["GHSA-old"]}]
        receipt = evaluate(**dict(self.good, policy=policy, findings={"secrets": [], "dependencies": ["GHSA-old"], "workflow_pins": []}))
        self.assertEqual(receipt["verdict"], "pass")
        self.assertEqual(receipt["exceptions"][0]["baselines"]["GHSA-old"][0]["expires_at"], "2026-09-30")

    def test_foreign_baseline_cannot_match_a_pilot_finding(self) -> None:
        policy = copy.deepcopy(self.policy)
        policy["baselines"] = [{"id": "foreign", "repository_id": "1235738436", "control": "dependencies", "owner": "security", "expires_at": "2026-09-30", "findings": ["GHSA-old"]}]
        receipt = evaluate(**dict(self.good, policy=policy, findings={"secrets": [], "dependencies": ["GHSA-old"], "workflow_pins": []}))
        self.assertEqual(receipt["verdict"], "fail")
        self.assertEqual(receipt["baseline_matches"]["dependencies"], [])

    def test_missing_finding_evidence_fails_closed(self) -> None:
        with self.assertRaisesRegex(PolicyError, "findings are missing"):
            evaluate(**dict(self.good, findings={"secrets": [], "dependencies": []}))

    def test_release_requires_exact_independent_candidate_rerun(self) -> None:
        policy = copy.deepcopy(self.policy)
        policy["repositories"]["1235738436"]["profile"] = "release-candidate"
        data = dict(self.good, policy=policy, repository_id="1235738436", repository="cognitum-one/website")
        self.assertEqual(evaluate(**data)["verdict"], "fail")
        self.assertEqual(evaluate(**dict(data, release_rerun=True, release_candidate_sha="a" * 40))["verdict"], "pass")
        self.assertEqual(evaluate(**dict(data, release_rerun=True, release_candidate_sha="c" * 40))["verdict"], "fail")


if __name__ == "__main__":
    unittest.main()
