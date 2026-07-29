#!/usr/bin/env python3

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from osv_gate import (
    ROUTER_EXCEPTION_EXPIRES,
    ROUTER_PROFILES,
    _verified_runtime_receipt_from_environment,
    evaluate,
)


def lock(version: str = "7.18.2") -> dict:
    return {
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"react-router-dom": version}},
            "node_modules/react-router": {
                "version": version,
                "resolved": (
                    "https://registry.npmjs.org/react-router/"
                    "-/react-router-7.18.2.tgz"
                ),
                "integrity": (
                    "sha512-aUVMjFm3GAPTTZL7oYr5E7ETiqfQCHRLH+B+5afnICvf0r7kkK4eR6SMuwbSTJw/"
                    "7t+12khT/Kahij49fqOCIg=="
                ),
            },
            "node_modules/react-router-dom": {
                "version": version,
                "resolved": (
                    "https://registry.npmjs.org/react-router-dom/"
                    "-/react-router-dom-7.18.2.tgz"
                ),
                "integrity": (
                    "sha512-AIKJ/jgGlFb3EbfCXk5Gzshiwt+l3mqbCrNjmEWMMjqQxNJ3svBa6bgzFyCC2Sw3"
                    "RA0VWF1kg3uQf2OFhxb8hw=="
                ),
                "dependencies": {"react-router": version},
            },
        },
    }


def report(source: str, *, package: str = "react-router", version: str = "7.18.2", advisory: str = "GHSA-qwww-vcr4-c8h2") -> dict:
    return {
        "results": [
            {
                "source": {"path": source},
                "packages": [
                    {
                        "package": {"name": package, "version": version},
                        "groups": [{"ids": [advisory], "max_severity": "7.1"}],
                        "vulnerabilities": [
                            {
                                "id": advisory,
                                "affected": [{"ranges": [{"events": [{"fixed": "8.3.0"}]}]}],
                            }
                        ],
                    }
                ],
            }
        ]
    }


class OsvGateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.scratch = tempfile.TemporaryDirectory()
        self.root = Path(self.scratch.name)
        self.management_lock = self.root / "management-ui" / "package-lock.json"
        self.management_lock.parent.mkdir(parents=True)
        self.management_lock.write_text(json.dumps(lock()), encoding="utf-8")
        self.management_manifest = self.root / "management-ui" / "package.json"
        self.management_manifest.write_text(
            json.dumps(
                {
                    "dependencies": {"react-router-dom": "7.18.2"},
                    "scripts": {"build": "vite build"},
                }
            ),
            encoding="utf-8",
        )
        profile = {
            "manifest": "management-ui/package.json",
        }
        self.profile_patch = patch.dict(
            ROUTER_PROFILES,
            {("cognitum-one/management", "management-ui/package-lock.json"): profile},
        )
        self.profile_patch.start()
        self.today = ROUTER_EXCEPTION_EXPIRES - dt.timedelta(days=1)

    def tearDown(self) -> None:
        self.profile_patch.stop()
        self.scratch.cleanup()

    def evaluate(self, payload: dict, repository: str = "cognitum-one/management"):
        return evaluate(
            payload,
            repository=repository,
            root=self.root,
            today=self.today,
            runtime_evidence_verified=True,
        )

    def test_accepts_only_the_exact_patched_static_runtime_record(self) -> None:
        blocking, reviewed = self.evaluate(report(str(self.management_lock)))
        self.assertEqual(blocking, [])
        self.assertEqual(len(reviewed), 1)

    def test_wrong_repository_is_not_excused(self) -> None:
        blocking, reviewed = self.evaluate(
            report(str(self.management_lock)),
            repository="attacker/fork",
        )
        self.assertEqual(len(blocking), 1)
        self.assertEqual(reviewed, [])

    def test_version_or_lock_drift_is_not_excused(self) -> None:
        self.management_lock.write_text(json.dumps(lock("7.18.3")), encoding="utf-8")
        blocking, reviewed = self.evaluate(report(str(self.management_lock)))
        self.assertEqual(len(blocking), 1)
        self.assertEqual(reviewed, [])

    def test_dependency_range_does_not_broaden_exception(self) -> None:
        manifest = json.loads(self.management_manifest.read_text(encoding="utf-8"))
        manifest["dependencies"]["react-router-dom"] = "^7.18.2"
        self.management_manifest.write_text(json.dumps(manifest), encoding="utf-8")
        blocking, reviewed = self.evaluate(report(str(self.management_lock)))
        self.assertEqual(len(blocking), 1)
        self.assertEqual(reviewed, [])

    def test_duplicate_manifest_keys_do_not_broaden_exception(self) -> None:
        self.management_manifest.write_text(
            '{"dependencies":{"react-router-dom":"7.18.2"},'
            '"dependencies":{"react-router-dom":"7.18.2"}}',
            encoding="utf-8",
        )
        blocking, reviewed = self.evaluate(report(str(self.management_lock)))
        self.assertEqual(len(blocking), 1)
        self.assertEqual(reviewed, [])

    def test_exception_expires_fail_closed(self) -> None:
        blocking, reviewed = evaluate(
            report(str(self.management_lock)),
            repository="cognitum-one/management",
            root=self.root,
            today=ROUTER_EXCEPTION_EXPIRES,
            runtime_evidence_verified=True,
        )
        self.assertEqual(len(blocking), 1)
        self.assertEqual(reviewed, [])

    def test_other_high_advisory_remains_blocking(self) -> None:
        blocking, reviewed = self.evaluate(
            report(
                str(self.management_lock),
                package="brace-expansion",
                version="2.1.2",
                advisory="GHSA-mh99-v99m-4gvg",
            )
        )
        self.assertEqual(len(blocking), 1)
        self.assertEqual(reviewed, [])

    def test_registry_artifact_integrity_drift_is_not_excused(self) -> None:
        payload = json.loads(self.management_lock.read_text(encoding="utf-8"))
        payload["packages"]["node_modules/react-router"]["integrity"] = "sha512-attacker"
        self.management_lock.write_text(json.dumps(payload), encoding="utf-8")
        blocking, reviewed = self.evaluate(report(str(self.management_lock)))
        self.assertEqual(len(blocking), 1)
        self.assertEqual(reviewed, [])

    def test_registry_artifact_url_drift_is_not_excused(self) -> None:
        payload = json.loads(self.management_lock.read_text(encoding="utf-8"))
        payload["packages"]["node_modules/react-router"]["resolved"] = (
            "https://attacker.invalid/react-router.tgz"
        )
        self.management_lock.write_text(json.dumps(payload), encoding="utf-8")
        blocking, reviewed = self.evaluate(report(str(self.management_lock)))
        self.assertEqual(len(blocking), 1)
        self.assertEqual(reviewed, [])

    def test_missing_runtime_receipt_is_not_excused(self) -> None:
        blocking, reviewed = evaluate(
            report(str(self.management_lock)),
            repository="cognitum-one/management",
            root=self.root,
            today=self.today,
            runtime_evidence_verified=False,
        )
        self.assertEqual(len(blocking), 1)
        self.assertEqual(reviewed, [])

    def test_runtime_receipt_environment_is_all_or_nothing(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            self.assertFalse(
                _verified_runtime_receipt_from_environment(
                    repository="cognitum-one/management",
                    root=self.root,
                )
            )
        with patch.dict(
            "os.environ",
            {"OSV_RUNTIME_RECEIPT": "/tmp/incomplete-receipt.json"},
            clear=True,
        ):
            with self.assertRaisesRegex(ValueError, "environment is incomplete"):
                _verified_runtime_receipt_from_environment(
                    repository="cognitum-one/management",
                    root=self.root,
                )

    def test_runtime_receipt_is_external_and_tuple_bound(self) -> None:
        with tempfile.TemporaryDirectory() as evidence_directory:
            evidence_root = Path(evidence_directory)
            receipt_path = evidence_root / "receipt.json"
            inventory_path = evidence_root / "inventory.json"
            nonce_path = evidence_root / "nonce.txt"
            receipt_path.write_text("{}\n", encoding="utf-8")
            inventory_path.write_text("{}\n", encoding="utf-8")
            nonce_path.write_text("a" * 64 + "\n", encoding="ascii")
            environment = {
                "OSV_RUNTIME_RECEIPT": str(receipt_path),
                "OSV_RUNTIME_INVENTORY": str(inventory_path),
                "OSV_RUNTIME_NONCE": str(nonce_path),
                "OSV_RUNTIME_IMAGE_NAME": "registry.example/cognitum-management",
                "OSV_RUNTIME_IMAGE_ID": "sha256:" + "b" * 64,
                "GITHUB_REPOSITORY": "cognitum-one/management",
                "GITHUB_SHA": "c" * 40,
                "GITHUB_RUN_ID": "303",
                "GITHUB_RUN_ATTEMPT": "2",
                "GITHUB_JOB": "runtime-proof",
                "GITHUB_WORKFLOW_REF": (
                    "cognitum-one/management/.github/workflows/security.yml@"
                    "refs/pull/1/merge"
                ),
                "GITHUB_WORKFLOW_SHA": "d" * 40,
            }
            with (
                patch.dict("os.environ", environment, clear=True),
                patch(
                    "static_ui_runtime_receipt.load_policy",
                    return_value={"profiles": {}},
                ) as load_policy,
                patch(
                    "static_ui_runtime_receipt.verify_premerge_receipt"
                ) as verifier,
            ):
                self.assertTrue(
                    _verified_runtime_receipt_from_environment(
                        repository="cognitum-one/management",
                        root=self.root,
                    )
                )
            load_policy.assert_called_once()
            call = verifier.call_args.kwargs
            self.assertEqual(call["expected_source_sha"], "c" * 40)
            self.assertEqual(call["expected_image_id"], "sha256:" + "b" * 64)
            self.assertEqual(call["expected_nonce"], "a" * 64)
            self.assertEqual(call["expected_run_attempt"], "2")

    def test_nested_router_copy_is_not_excused(self) -> None:
        payload = json.loads(self.management_lock.read_text(encoding="utf-8"))
        payload["packages"]["node_modules/other/node_modules/react-router"] = {
            "version": "7.18.2"
        }
        self.management_lock.write_text(json.dumps(payload), encoding="utf-8")
        blocking, reviewed = self.evaluate(report(str(self.management_lock)))
        self.assertEqual(len(blocking), 1)
        self.assertEqual(reviewed, [])

    def test_nested_router_metadata_name_cannot_hide_copy(self) -> None:
        payload = json.loads(self.management_lock.read_text(encoding="utf-8"))
        payload["packages"]["node_modules/other/node_modules/react-router"] = {
            "name": "innocent",
            "version": "7.18.2",
        }
        self.management_lock.write_text(json.dumps(payload), encoding="utf-8")
        blocking, reviewed = self.evaluate(report(str(self.management_lock)))
        self.assertEqual(len(blocking), 1)
        self.assertEqual(reviewed, [])

    def test_candidate_dev_flags_cannot_downgrade_a_finding(self) -> None:
        payload = lock()
        payload["packages"]["node_modules/prod-pkg"] = {
            "name": "prod-pkg",
            "version": "1.0.0",
            "dev": "false",
        }
        self.management_lock.write_text(json.dumps(payload), encoding="utf-8")
        blocking, reviewed = self.evaluate(
            report(
                str(self.management_lock),
                package="prod-pkg",
                version="1.0.0",
                advisory="GHSA-mh99-v99m-4gvg",
            )
        )
        self.assertEqual(len(blocking), 1)
        self.assertEqual(reviewed, [])

    def test_missing_severity_fails_closed(self) -> None:
        payload = report(str(self.management_lock))
        payload["results"][0]["packages"][0]["groups"] = []
        with self.assertRaisesRegex(ValueError, "severity is missing"):
            self.evaluate(payload)

    def test_nonfinite_or_out_of_range_severity_fails_closed(self) -> None:
        for score in ("NaN", "Infinity", "-1", "10.1"):
            payload = report(str(self.management_lock))
            payload["results"][0]["packages"][0]["groups"][0]["max_severity"] = score
            with self.subTest(score=score):
                with self.assertRaisesRegex(ValueError, "severity is out of range"):
                    self.evaluate(payload)

    def test_malformed_affected_shape_fails_closed(self) -> None:
        payload = report(str(self.management_lock))
        payload["results"][0]["packages"][0]["vulnerabilities"][0]["affected"] = (
            "malformed-not-an-array"
        )
        with self.assertRaisesRegex(ValueError, "affected records is not an array"):
            self.evaluate(payload)

    def test_introduced_only_unfixable_record_is_informational(self) -> None:
        payload = report(str(self.management_lock))
        payload["results"][0]["packages"][0]["vulnerabilities"][0]["affected"] = [
            {"ranges": [{"events": [{"introduced": "0"}]}]}
        ]
        blocking, reviewed = self.evaluate(payload)
        self.assertEqual(blocking, [])
        self.assertEqual(reviewed, [])

    def test_malformed_report_fails_closed(self) -> None:
        with self.assertRaises(ValueError):
            self.evaluate({"results": [{"source": {"path": "x"}}]})


if __name__ == "__main__":
    unittest.main()
