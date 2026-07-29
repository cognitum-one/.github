#!/usr/bin/env python3
"""Mutation tests for the org-owned static UI workflow policy."""

from __future__ import annotations

import copy
from pathlib import Path
import re
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).parent))

from verify_static_ui_workflows import WorkflowPolicyError, verify


class StaticUiWorkflowPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.root = Path(__file__).resolve().parents[1]
        cls.sources = {
            "security": (cls.root / ".github/workflows/security-scan.yml").read_text(
                encoding="utf-8"
            ),
            "release": (cls.root / ".github/workflows/static-ui-release.yml").read_text(
                encoding="utf-8"
            ),
            "revision": (
                cls.root / ".github/workflows/static-ui-revision.yml"
            ).read_text(encoding="utf-8"),
            "selftest": (
                cls.root / ".github/workflows/static-ui-policy-selftest.yml"
            ).read_text(encoding="utf-8"),
            "template": (cls.root / "workflow-templates/security.yml").read_text(
                encoding="utf-8"
            ),
            "gate": (cls.root / "security/static_ui_release_gate.py").read_text(
                encoding="utf-8"
            ),
            "gate_test": (
                cls.root / "security/test_static_ui_release_gate.py"
            ).read_text(encoding="utf-8"),
        }

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write(self, sources: dict[str, str]) -> dict[str, Path]:
        paths = {
            "security": self.directory / "security-scan.yml",
            "release": self.directory / "static-ui-release.yml",
            "revision": self.directory / "static-ui-revision.yml",
            "selftest": self.directory / "static-ui-policy-selftest.yml",
            "template": self.directory / "security-template.yml",
            "gate": self.directory / "static_ui_release_gate.py",
            "gate_test": self.directory / "test_static_ui_release_gate.py",
        }
        for name, path in paths.items():
            path.write_text(sources[name], encoding="utf-8")
        return paths

    def _verify(
        self,
        sources: dict[str, str] | None = None,
        *,
        allow_unresolved_self_pin: bool = True,
    ) -> None:
        paths = self._write(sources or self.sources)
        verify(
            security_path=paths["security"],
            release_path=paths["release"],
            revision_path=paths["revision"],
            selftest_path=paths["selftest"],
            template_path=paths["template"],
            release_gate_path=paths["gate"],
            release_gate_test_path=paths["gate_test"],
            allow_unresolved_self_pin=allow_unresolved_self_pin,
        )

    def _mutate(self, target: str, old: str, new: str) -> dict[str, str]:
        sources = copy.deepcopy(self.sources)
        self.assertIn(old, sources[target])
        sources[target] = sources[target].replace(old, new, 1)
        self.assertNotEqual(sources[target], self.sources[target])
        return sources

    def test_current_workflows_accept_only_the_valid_bootstrap_or_resolved_phase(
        self,
    ) -> None:
        self._verify()
        bootstrap_pin = f'STATIC_UI_WORKFLOW_COMMIT: "{"0" * 40}"'
        if bootstrap_pin in self.sources["release"]:
            with self.assertRaisesRegex(WorkflowPolicyError, "self-pin is unresolved"):
                self._verify(allow_unresolved_self_pin=False)
        else:
            self._verify(allow_unresolved_self_pin=False)

    def test_organization_policy_cannot_be_rolled_back_as_a_quorum(self) -> None:
        sources = copy.deepcopy(self.sources)
        for target in ("security", "release", "revision"):
            sources[target] = sources[target].replace(
                "16eb59995aa7378380c9b471ecd164cef42f8a87",
                "1" * 40,
                1,
            )
        with self.assertRaisesRegex(
            WorkflowPolicyError, "approved organization policy"
        ):
            self._verify(sources)

        sources = copy.deepcopy(self.sources)
        for target in ("security", "release", "revision"):
            sources[target] = sources[target].replace(
                "b31a9d95a7547ab5471cf6901b878ccaf2e2abe5dca89f086b0f6e9f41e18b25",
                "2" * 64,
                1,
            )
        with self.assertRaisesRegex(
            WorkflowPolicyError, "approved organization policy"
        ):
            self._verify(sources)

    def test_release_companion_hashes_must_match_committed_bytes(self) -> None:
        sources = copy.deepcopy(self.sources)
        for target in ("release", "revision"):
            sources[target] = sources[target].replace(
                "bfe974d10883013f843c59a2f025f0c6b7d64f4f18bc7edb2e66b650fb30b7a8",
                "3" * 64,
                1,
            )
        with self.assertRaisesRegex(WorkflowPolicyError, "committed bytes"):
            self._verify(sources)

    def test_every_downloaded_policy_artifact_is_hash_checked(self) -> None:
        mutations = (
            (
                "security",
                'echo "${OSV_GATE_TEST_SHA256}  ${POLICY_DIR}/test_osv_gate.py" | sha256sum -c -',
            ),
            (
                "release",
                'echo "${STATIC_UI_RELEASE_GATE_TEST_SHA256}  ${POLICY_DIR}/test_static_ui_release_gate.py" | sha256sum -c -',
            ),
            (
                "revision",
                'echo "${STATIC_UI_RECEIPT_SHA256}  ${POLICY_DIR}/static_ui_runtime_receipt.py" | sha256sum -c -',
            ),
        )
        for target, assertion in mutations:
            with self.subTest(target=target):
                sources = self._mutate(
                    target,
                    assertion,
                    f'echo "hash assertion removed from {target}"',
                )
                with self.assertRaisesRegex(WorkflowPolicyError, "hash-check"):
                    self._verify(sources)

    def test_security_runtime_evidence_and_org_tests_are_mandatory(self) -> None:
        mutations = (
            (
                'python3 "$POLICY_DIR/test_static_ui_runtime_receipt.py"',
                'echo "runtime receipt tests omitted"',
            ),
            (
                'OSV_RUNTIME_RECEIPT="${{ steps.runtime.outputs.receipt }}"',
                'OSV_RUNTIME_RECEIPT=""',
            ),
            (
                'OSV_RUNTIME_INVENTORY="${{ steps.runtime.outputs.inventory }}"',
                'OSV_RUNTIME_INVENTORY=""',
            ),
            (
                'OSV_RUNTIME_NONCE="${{ steps.runtime.outputs.nonce }}"',
                'OSV_RUNTIME_NONCE=""',
            ),
            (
                'OSV_RUNTIME_IMAGE_ID="${{ steps.runtime.outputs.image_id }}"',
                'OSV_RUNTIME_IMAGE_ID=""',
            ),
            ("--mode premerge", "--mode release"),
            (
                '--receipt-nonce-file "$NONCE_DIR/nonce"',
                '--receipt-nonce-file "$OUTPUT_DIR/nonce"',
            ),
            (
                'GITHUB_WORKFLOW_SHA="$GITHUB_WORKFLOW_SHA"',
                'GITHUB_WORKFLOW_SHA=""',
            ),
            (
                'GITHUB_REPOSITORY_VISIBILITY="$REPOSITORY_VISIBILITY"',
                'GITHUB_REPOSITORY_VISIBILITY=""',
            ),
            (
                'GH_TOKEN="$STATIC_UI_IDENTITY_TOKEN"',
                'GH_TOKEN=""',
            ),
        )
        for old, new in mutations:
            with self.subTest(old=old):
                with self.assertRaises(WorkflowPolicyError):
                    self._verify(self._mutate("security", old, new))

    def test_release_attestation_and_exact_digest_gates_are_mandatory(self) -> None:
        mutations = (
            (
                "uses: actions/attest@f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6",
                "uses: actions/attest@v4",
            ),
            (
                "predicate-path: ${{ steps.build.outputs.output }}/static-ui-runtime-receipt.json",
                "predicate-path: candidate.json",
            ),
            ('--bundle "$BUNDLE"', "--bundle candidate.json"),
            (
                '--signer-workflow "$SIGNER_WORKFLOW"',
                "--signer-workflow candidate/workflow.yml",
            ),
            (
                '--signer-digest "$SIGNER_DIGEST"',
                "--signer-digest $GITHUB_SHA",
            ),
            ('--source-digest "$GITHUB_SHA"', "--source-digest deadbeef"),
            ("--deny-self-hosted-runners", "--allow-self-hosted-runners"),
            (
                '--expected-inventory "$OUTPUT_DIR/rootfs-inventory.json"',
                '--expected-inventory "$GITHUB_WORKSPACE/inventory.json"',
            ),
            (
                '--inventory "$OUTPUT_DIR/exact-digest-rootfs-inventory.json"',
                '--inventory "$OUTPUT_DIR/rootfs-inventory.json"',
            ),
            ("--mode release", "--mode premerge"),
            (
                'python3 "$POLICY_DIR/test_static_ui_release_gate.py"',
                'echo "release gate tests omitted"',
            ),
            (
                'test "$BUILDER_SERVICE_ACCOUNT" = "$EXPECTED_BUILDER_SERVICE_ACCOUNT"',
                "true # builder identity unchecked",
            ),
            (
                'payload.get("workflow_sha") != os.environ["GITHUB_WORKFLOW_SHA"]',
                "False",
            ),
            (
                'payload.get("runner_environment") != "github-hosted"',
                "False",
            ),
            (
                "permissions:\n  attestations: write",
                "permissions:\n  attestations: write\n  packages: write",
            ),
            (
                'GH_TOKEN="$STATIC_UI_IDENTITY_TOKEN"',
                'GH_TOKEN=""',
            ),
        )
        for old, new in mutations:
            with self.subTest(old=old):
                with self.assertRaises(WorkflowPolicyError):
                    self._verify(self._mutate("release", old, new))

        sources = copy.deepcopy(self.sources)
        sources["release"] += "\n# mutation\ngcloud run deploy compromised\n"
        with self.assertRaisesRegex(WorkflowPolicyError, "forbidden mutation"):
            self._verify(sources)

    def test_revision_read_only_and_runtime_contract_are_mandatory(self) -> None:
        mutations = (
            (
                'gcloud run revisions describe "$REVISION"',
                'gcloud run revisions delete "$REVISION"',
            ),
            (
                'gcloud run services describe "$SERVICE"',
                'gcloud run services update "$SERVICE"',
            ),
            (
                '--expected-environment "$EVIDENCE_DIR/expected-environment.json"',
                "--expected-environment candidate.json",
            ),
            (
                '--expected-service-account "$SERVICE_ACCOUNT"',
                "--expected-service-account default",
            ),
            ('--expected-ingress "$INGRESS"', "--expected-ingress all"),
            (
                "management-runtime-stg@cognitum-20260110.iam.gserviceaccount.com",
                "186366152200-compute@developer.gserviceaccount.com",
            ),
            (
                'test "$VERIFIER_SERVICE_ACCOUNT" = "$EXPECTED_VERIFIER_SERVICE_ACCOUNT"',
                "true # verifier identity unchecked",
            ),
        )
        for old, new in mutations:
            with self.subTest(old=old):
                with self.assertRaises(WorkflowPolicyError):
                    self._verify(self._mutate("revision", old, new))

    def test_release_gate_semantic_checks_cannot_be_removed(self) -> None:
        mutations = (
            (
                '["docker", "image", "pull", "--platform", "linux/amd64", image_ref]',
                '["docker", "image", "pull", image_tag]',
            ),
            (
                "_docker_rootfs_inventory(image_ref, profile)",
                "_docker_rootfs_inventory(image_tag, profile)",
            ),
            (
                'statement.get("predicate") != receipt',
                "False",
            ),
            (
                'revision.get("status", {}).get("imageDigest") != expected_image',
                "False",
            ),
            (
                "Cloud Run ingress differs",
                "ingress ignored",
            ),
            (
                "Cloud Run serving traffic differs from the exact revision",
                "traffic ignored",
            ),
        )
        for old, new in mutations:
            with self.subTest(old=old):
                with self.assertRaises(WorkflowPolicyError):
                    self._verify(self._mutate("gate", old, new))

    def test_all_third_party_actions_remain_full_sha_pinned(self) -> None:
        sources = self._mutate(
            "security",
            "actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
            "actions/checkout@main",
        )
        with self.assertRaisesRegex(WorkflowPolicyError, "full SHA"):
            self._verify(sources)

    def test_security_caller_template_cannot_float_or_omit_beacon_token(self) -> None:
        pin_match = re.search(
            r"security-scan\.yml@([0-9a-f]{40})",
            self.sources["template"],
        )
        self.assertIsNotNone(pin_match)
        with self.assertRaises(WorkflowPolicyError):
            self._verify(
                self._mutate(
                    "template",
                    f"security-scan.yml@{pin_match.group(1)}",
                    "security-scan.yml@main",
                )
            )
        with self.assertRaises(WorkflowPolicyError):
            self._verify(
                self._mutate(
                    "template",
                    "static_ui_beacon_read_token: ${{ secrets.STATIC_UI_BEACON_READ_TOKEN }}",
                    "secrets: inherit",
                )
            )

    def test_branch_selftest_cannot_omit_policy_or_actionlint_checks(self) -> None:
        mutations = (
            (
                "python3 security/test_static_ui_runtime_receipt.py",
                'echo "runtime tests omitted"',
            ),
            (
                "python3 security/test_static_ui_release_gate.py",
                'echo "release tests omitted"',
            ),
            (
                "python3 security/test_verify_static_ui_workflows.py",
                'echo "mutation tests omitted"',
            ),
            (
                "python3 security/verify_static_ui_workflows.py",
                'echo "static verifier omitted"',
            ),
            (
                "python3 -m json.tool workflow-templates/security.properties.json >/dev/null",
                'echo "template metadata check omitted"',
            ),
            (
                '      - "workflow-templates/security.yml"',
                '      - "workflow-templates/security-omitted.yml"',
            ),
            (
                'ACTIONLINT_SHA256: "8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8"',
                'ACTIONLINT_SHA256: "' + "0" * 64 + '"',
            ),
            ("runs-on: ubuntu-24.04", "runs-on: ubuntu-latest"),
        )
        for old, new in mutations:
            with self.subTest(old=old):
                with self.assertRaises(WorkflowPolicyError):
                    self._verify(self._mutate("selftest", old, new))


if __name__ == "__main__":
    unittest.main()
