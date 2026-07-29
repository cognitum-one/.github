#!/usr/bin/env python3
"""Adversarial tests for the release-only static UI evidence gates."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent))

import static_ui_release_gate as gate


def write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


class StaticUiReleaseGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.policy = Path(__file__).with_name("static-ui-runtime-profiles.json")
        self.repository = "cognitum-one/website"
        self.image_name = (
            "us-central1-docker.pkg.dev/cognitum-20260110/"
            "cloud-run-source-deploy/cognitum-dashboard"
        )
        self.image_digest = "sha256:" + "a" * 64
        self.image = f"{self.image_name}@{self.image_digest}"
        self.image_id = "sha256:" + "b" * 64
        self.source_sha = "c" * 40
        self.signer_sha = "d" * 40
        self.nonce = self.root / "nonce"
        self.nonce.write_text("e" * 64 + "\n", encoding="ascii")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_exact_digest_inventory_must_equal_builder_inventory(self) -> None:
        inventory = {"kind": "inventory"}
        expected = self.root / "expected.json"
        output = self.root / "output.json"
        write_json(expected, inventory)
        with (
            mock.patch.object(gate.subprocess, "run") as docker_pull,
            mock.patch.object(
                gate, "_docker_image_inspect", return_value=[{"Id": self.image_id}]
            ),
            mock.patch.object(gate, "_docker_rootfs_inventory", return_value=inventory),
            mock.patch.object(gate, "_validate_inventory_document"),
        ):
            actual = gate.verify_exact_digest_inventory(
                repository=self.repository,
                policy_path=self.policy,
                image_name=self.image_name,
                image_digest=self.image_digest,
                expected_image_id=self.image_id,
                expected_inventory_path=expected,
                output=output,
            )
        self.assertEqual(actual, inventory)
        self.assertEqual(json.loads(output.read_text()), inventory)
        command = docker_pull.call_args.args[0]
        self.assertEqual(command[-1], self.image)
        self.assertIn("--platform", command)

    def test_inventory_rejects_digest_image_config_or_rootfs_drift(self) -> None:
        expected = self.root / "expected.json"
        write_json(expected, {"kind": "expected"})
        cases = (
            ([{"Id": "sha256:" + "f" * 64}], {"kind": "expected"}, "config"),
            ([{"Id": self.image_id}], {"kind": "actual"}, "rootfs"),
        )
        for index, (inspect, inventory, error) in enumerate(cases):
            with self.subTest(error=error):
                with (
                    mock.patch.object(gate.subprocess, "run"),
                    mock.patch.object(
                        gate, "_docker_image_inspect", return_value=inspect
                    ),
                    mock.patch.object(
                        gate, "_docker_rootfs_inventory", return_value=inventory
                    ),
                    mock.patch.object(gate, "_validate_inventory_document"),
                ):
                    with self.assertRaises(gate.PolicyError):
                        gate.verify_exact_digest_inventory(
                            repository=self.repository,
                            policy_path=self.policy,
                            image_name=self.image_name,
                            image_digest=self.image_digest,
                            expected_image_id=self.image_id,
                            expected_inventory_path=expected,
                            output=self.root / f"out-{index}.json",
                        )

    def _attestation_fixture(self) -> tuple[Path, Path, Path]:
        receipt = {
            "schemaVersion": 1,
            "predicateType": gate.PREDICATE_TYPE,
            "receiptDigest": "sha256:" + "1" * 64,
        }
        inventory = {
            "inventoryDigest": "sha256:" + "2" * 64,
        }
        statement = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [
                {
                    "name": self.image_name,
                    "digest": {"sha256": self.image_digest.removeprefix("sha256:")},
                }
            ],
            "predicateType": gate.PREDICATE_TYPE,
            "predicate": receipt,
        }
        verification = [
            {
                "attestation": {"bundle": "present"},
                "verificationResult": {
                    "statement": statement,
                    "signature": {"certificate": {"issuer": "github"}},
                    "verifiedTimestamps": [{"type": "rekor"}],
                },
            }
        ]
        receipt_path = self.root / "receipt.json"
        inventory_path = self.root / "inventory.json"
        verification_path = self.root / "verification.json"
        write_json(receipt_path, receipt)
        write_json(inventory_path, inventory)
        write_json(verification_path, verification)
        return verification_path, receipt_path, inventory_path

    def _verify_attestation(
        self,
        verification_path: Path,
        receipt_path: Path,
        inventory_path: Path,
        output_name: str = "verified.json",
    ) -> dict[str, object]:
        with mock.patch.object(gate, "verify_receipt") as receipt_gate:
            result = gate.verify_attestation_statement(
                verification_path=verification_path,
                receipt_path=receipt_path,
                inventory_path=inventory_path,
                policy_path=self.policy,
                repository=self.repository,
                image_name=self.image_name,
                image_digest=self.image_digest,
                source_sha=self.source_sha,
                run_id="1234",
                run_attempt="2",
                job="staging",
                caller_workflow_ref=(
                    "cognitum-one/website/.github/workflows/cd.yml@refs/heads/main"
                ),
                caller_workflow_sha=self.source_sha,
                nonce_path=self.nonce,
                signer_workflow=(
                    "cognitum-one/.github/.github/workflows/static-ui-release.yml"
                ),
                signer_digest=self.signer_sha,
                output=self.root / output_name,
            )
        receipt_gate.assert_called_once()
        return result

    def test_attestation_binds_exact_statement_and_release_verifier(self) -> None:
        paths = self._attestation_fixture()
        result = self._verify_attestation(*paths)
        self.assertEqual(result["subject"]["digest"]["sha256"], "a" * 64)
        self.assertEqual(result["signerDigest"], self.signer_sha)
        self.assertRegex(str(result["evidenceDigest"]), r"^sha256:[0-9a-f]{64}$")

    def test_attestation_rejects_predicate_subject_signature_or_count_drift(
        self,
    ) -> None:
        verification_path, receipt_path, inventory_path = self._attestation_fixture()
        baseline = json.loads(verification_path.read_text())
        mutations = []

        value = copy.deepcopy(baseline)
        value[0]["verificationResult"]["statement"]["predicate"]["extra"] = True
        mutations.append(("predicate", value))
        value = copy.deepcopy(baseline)
        value[0]["verificationResult"]["statement"]["subject"][0]["digest"][
            "sha256"
        ] = ("f" * 64)
        mutations.append(("subject", value))
        value = copy.deepcopy(baseline)
        value[0]["verificationResult"]["signature"] = {}
        mutations.append(("signature", value))
        value = copy.deepcopy(baseline)
        value[0]["verificationResult"]["verifiedTimestamps"] = []
        mutations.append(("timestamp", value))
        mutations.append(("count", baseline + copy.deepcopy(baseline)))

        for index, (name, mutation) in enumerate(mutations):
            with self.subTest(name=name):
                path = self.root / f"verification-{index}.json"
                write_json(path, mutation)
                with self.assertRaises(gate.PolicyError):
                    self._verify_attestation(
                        path,
                        receipt_path,
                        inventory_path,
                        output_name=f"verified-{index}.json",
                    )

    def _service_fixture(
        self,
    ) -> tuple[dict[str, object], dict[str, object], list[dict[str, str]], str]:
        profile = gate.profile_for(self.repository, gate.load_policy(self.policy))
        configured_names = profile["deployment"]["configuredEnvironmentAllowlist"]
        literal_environment = [
            {
                "name": name,
                "value": f"fixture-{name.lower()}",
            }
            for name in configured_names
        ]
        environment = [
            {
                "name": item["name"],
                "source": "value",
                "valueDigest": (
                    "sha256:" + hashlib.sha256(item["value"].encode()).hexdigest()
                ),
            }
            for item in literal_environment
        ]
        spec = {
            "serviceAccountName": (
                "website-runtime-stg@cognitum-20260110.iam.gserviceaccount.com"
            ),
            "containers": [
                {
                    "image": self.image,
                    "ports": [{"name": "http1", "containerPort": 8080}],
                    "env": literal_environment,
                }
            ],
        }
        revision_spec = copy.deepcopy(spec)
        revision_spec["containers"][0]["name"] = "website-1"
        spec_digest = (
            "sha256:" + hashlib.sha256(gate._canonical_bytes(revision_spec)).hexdigest()
        )
        revision_name = "cognitum-dashboard-staging-00042-test"
        revision = {
            "metadata": {"name": revision_name},
            "spec": revision_spec,
            "status": {
                "conditions": [{"type": "Ready", "status": "True"}],
                "imageDigest": self.image,
            },
        }
        service = {
            "metadata": {
                "name": "cognitum-dashboard-staging",
                "annotations": {"run.googleapis.com/ingress": "all"},
            },
            "spec": {
                "template": {"spec": copy.deepcopy(spec)},
                "traffic": [{"percent": 100, "revisionName": revision_name}],
            },
            "status": {
                "conditions": [{"type": "Ready", "status": "True"}],
                "latestCreatedRevisionName": revision_name,
                "latestReadyRevisionName": revision_name,
                "traffic": [{"percent": 100, "revisionName": revision_name}],
            },
        }
        return revision, service, environment, spec_digest

    def _verify_service(
        self,
        revision: dict[str, object],
        service: dict[str, object],
        environment: list[dict[str, str]],
        spec_digest: str,
        name: str,
    ) -> None:
        revision_path = self.root / f"revision-{name}.json"
        service_path = self.root / f"service-{name}.json"
        environment_path = self.root / f"environment-{name}.json"
        write_json(revision_path, revision)
        write_json(service_path, service)
        write_json(environment_path, environment)
        gate.verify_cloud_run_service(
            repository=self.repository,
            policy_path=self.policy,
            revision_path=revision_path,
            service_path=service_path,
            expected_environment_path=environment_path,
            expected_revision="cognitum-dashboard-staging-00042-test",
            expected_service="cognitum-dashboard-staging",
            expected_image=self.image,
            expected_service_account=(
                "website-runtime-stg@cognitum-20260110.iam.gserviceaccount.com"
            ),
            expected_spec_digest=spec_digest,
            expected_ingress="all",
            output=self.root / f"service-evidence-{name}.json",
        )

    def test_cloud_run_service_binds_revision_status_ingress_and_traffic(
        self,
    ) -> None:
        fixture = self._service_fixture()
        self._verify_service(*fixture, name="valid")

    def test_cloud_run_service_rejects_release_boundary_mutations(self) -> None:
        revision, service, environment, spec_digest = self._service_fixture()
        mutations = []

        changed_revision = copy.deepcopy(revision)
        changed_revision["spec"]["volumes"] = [{"name": "secret"}]
        mutations.append(("volume", changed_revision, service, environment))
        changed_revision = copy.deepcopy(revision)
        changed_revision["spec"]["containers"][0]["volumeMounts"] = [
            {"name": "secret", "mountPath": "/secrets"}
        ]
        mutations.append(("mount", changed_revision, service, environment))
        changed_revision = copy.deepcopy(revision)
        changed_revision["status"]["imageDigest"] = (
            self.image_name + "@sha256:" + "f" * 64
        )
        mutations.append(("status-image", changed_revision, service, environment))
        changed_revision = copy.deepcopy(revision)
        changed_revision["status"]["conditions"][0]["status"] = "False"
        mutations.append(("revision-ready", changed_revision, service, environment))
        changed_service = copy.deepcopy(service)
        changed_service["metadata"]["annotations"][
            "run.googleapis.com/ingress"
        ] = "internal"
        mutations.append(("ingress", revision, changed_service, environment))
        changed_service = copy.deepcopy(service)
        changed_service["status"]["traffic"][0]["percent"] = 99
        mutations.append(("status-traffic", revision, changed_service, environment))
        changed_service = copy.deepcopy(service)
        changed_service["spec"]["traffic"][0]["revisionName"] = "other"
        mutations.append(("spec-traffic", revision, changed_service, environment))
        changed_service = copy.deepcopy(service)
        changed_service["status"]["latestReadyRevisionName"] = "other"
        mutations.append(("latest-ready", revision, changed_service, environment))
        changed_environment = copy.deepcopy(environment)
        changed_environment[0]["valueDigest"] = "sha256:" + "f" * 64
        mutations.append(("environment", revision, service, changed_environment))

        for index, (name, changed_revision, changed_service, changed_env) in enumerate(
            mutations
        ):
            with self.subTest(name=name):
                with self.assertRaises(gate.PolicyError):
                    self._verify_service(
                        changed_revision,
                        changed_service,
                        changed_env,
                        spec_digest,
                        name=f"{index}-{name}",
                    )

    def test_duplicate_json_keys_fail_closed(self) -> None:
        path = self.root / "duplicate.json"
        path.write_text('{"a": 1, "a": 2}\\n', encoding="utf-8")
        with self.assertRaisesRegex(gate.PolicyError, "duplicate JSON key"):
            gate._read_json(path, "fixture")


if __name__ == "__main__":
    unittest.main()
