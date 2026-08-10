#!/usr/bin/env python3

from __future__ import annotations

import copy
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
    RUNTIME_RECEIPT_EVIDENCE_ENVIRONMENT,
    RUNTIME_RECEIPT_GITHUB_ENVIRONMENT,
    _format,
    _verified_runtime_receipt_from_environment,
    evaluate,
    main,
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


def report(
    source: str,
    *,
    package: str = "react-router",
    version: str = "7.18.2",
    advisory: str = "GHSA-qwww-vcr4-c8h2",
) -> dict:
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
                                "affected": [
                                    {"ranges": [{"events": [{"fixed": "8.3.0"}]}]}
                                ],
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

    @staticmethod
    def github_environment(
        repository: str = "cognitum-one/management",
    ) -> dict[str, str]:
        return {
            "GITHUB_REPOSITORY": repository,
            "GITHUB_SHA": "c" * 40,
            "GITHUB_RUN_ID": "303",
            "GITHUB_RUN_ATTEMPT": "2",
            "GITHUB_JOB": "deps",
            "GITHUB_WORKFLOW_REF": (
                f"{repository}/.github/workflows/security.yml@refs/pull/69/merge"
            ),
            "GITHUB_WORKFLOW_SHA": "d" * 40,
        }

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
        payload["packages"]["node_modules/react-router"][
            "integrity"
        ] = "sha512-attacker"
        self.management_lock.write_text(json.dumps(payload), encoding="utf-8")
        blocking, reviewed = self.evaluate(report(str(self.management_lock)))
        self.assertEqual(len(blocking), 1)
        self.assertEqual(reviewed, [])

    def test_registry_artifact_url_drift_is_not_excused(self) -> None:
        payload = json.loads(self.management_lock.read_text(encoding="utf-8"))
        payload["packages"]["node_modules/react-router"][
            "resolved"
        ] = "https://attacker.invalid/react-router.tgz"
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

        evidence = {
            "OSV_RUNTIME_RECEIPT": "/tmp/receipt.json",
            "OSV_RUNTIME_INVENTORY": "/tmp/inventory.json",
            "OSV_RUNTIME_NONCE": "/tmp/nonce.txt",
            "OSV_RUNTIME_IMAGE_NAME": "registry.example/cognitum-management",
            "OSV_RUNTIME_IMAGE_ID": "sha256:" + "b" * 64,
        }
        github = self.github_environment()
        for missing_name in sorted(RUNTIME_RECEIPT_EVIDENCE_ENVIRONMENT):
            partial = evidence | github
            partial[missing_name] = ""
            with (
                self.subTest(missing_runtime_evidence=missing_name),
                patch.dict("os.environ", partial, clear=True),
                self.assertRaisesRegex(ValueError, "environment is incomplete"),
            ):
                _verified_runtime_receipt_from_environment(
                    repository="cognitum-one/management",
                    root=self.root,
                )

        for missing_name in sorted(RUNTIME_RECEIPT_GITHUB_ENVIRONMENT):
            incomplete_context = evidence | github
            incomplete_context[missing_name] = ""
            with (
                self.subTest(missing_github_context=missing_name),
                patch.dict("os.environ", incomplete_context, clear=True),
                self.assertRaisesRegex(ValueError, "environment is incomplete"),
            ):
                _verified_runtime_receipt_from_environment(
                    repository="cognitum-one/management",
                    root=self.root,
                )

    def test_cogs_github_context_without_runtime_evidence_runs_ordinary_gate(
        self,
    ) -> None:
        report_path = self.root / "cogs-osv.json"
        report_path.write_text('{"results":[]}\n', encoding="utf-8")
        environment = self.github_environment("cognitum-one/cogs") | {
            name: "" for name in RUNTIME_RECEIPT_EVIDENCE_ENVIRONMENT
        }
        environment.update(
            {
                "OSV_REPORT": str(report_path),
                "OSV_REPOSITORY_ROOT": str(self.root),
            }
        )
        with patch.dict("os.environ", environment, clear=True):
            runtime_verified = _verified_runtime_receipt_from_environment(
                repository="cognitum-one/cogs",
                root=self.root,
            )
            self.assertFalse(runtime_verified)
            self.assertEqual(main(), 0)

    def test_runtime_receipt_is_external_and_tuple_bound(self) -> None:
        with tempfile.TemporaryDirectory() as evidence_directory:
            evidence_root = Path(evidence_directory)
            receipt_path = evidence_root / "receipt.json"
            inventory_path = evidence_root / "inventory.json"
            nonce_path = evidence_root / "nonce.txt"
            receipt_path.write_text("{}\n", encoding="utf-8")
            inventory_path.write_text("{}\n", encoding="utf-8")
            nonce_path.write_text("a" * 64 + "\n", encoding="ascii")
            environment = self.github_environment() | {
                "OSV_RUNTIME_RECEIPT": str(receipt_path),
                "OSV_RUNTIME_INVENTORY": str(inventory_path),
                "OSV_RUNTIME_NONCE": str(nonce_path),
                "OSV_RUNTIME_IMAGE_NAME": "registry.example/cognitum-management",
                "OSV_RUNTIME_IMAGE_ID": "sha256:" + "b" * 64,
            }
            with (
                patch.dict("os.environ", environment, clear=True),
                patch(
                    "static_ui_runtime_receipt.load_policy",
                    return_value={"profiles": {}},
                ) as load_policy,
                patch("static_ui_runtime_receipt.verify_premerge_receipt") as verifier,
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
            self.assertEqual(call["expected_job"], "deps")
            self.assertEqual(
                call["expected_workflow_ref"],
                (
                    "cognitum-one/management/.github/workflows/security.yml@"
                    "refs/pull/69/merge"
                ),
            )

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

    def test_no_fix_missing_severity_is_informational(self) -> None:
        advisory = "RUSTSEC-2025-0119"
        severityless_groups = (
            [],
            [{"ids": [advisory]}],
            [{"ids": [advisory], "max_severity": ""}],
            [{"ids": [advisory], "max_severity": None}],
        )
        for groups in severityless_groups:
            payload = report(
                str(self.management_lock),
                package="number_prefix",
                version="0.4.0",
                advisory=advisory,
            )
            package_record = payload["results"][0]["packages"][0]
            package_record["groups"] = groups
            package_record["vulnerabilities"][0]["affected"] = [
                {"ranges": [{"events": [{"introduced": "0.0.0-0"}]}]}
            ]
            with self.subTest(groups=groups):
                blocking, reviewed = self.evaluate(payload)
                self.assertEqual(blocking, [])
                self.assertEqual(reviewed, [])

    def test_fixable_missing_severity_blocks_as_an_unrated_finding(self) -> None:
        # A fixable advisory OSV has not scored still blocks, but it is a
        # FINDING, not a malformed report. It used to raise, which aborted the
        # whole scan under the banner "OSV JSON is missing, malformed, or
        # unsafe" — so the red was dismissed as tooling noise and three unrated
        # rkyv memory-safety advisories went unactioned behind it.
        advisory = "RUSTSEC-2026-0190"
        severityless_groups = (
            [],
            [{"ids": [advisory]}],
            [{"ids": [advisory], "max_severity": ""}],
            [{"ids": [advisory], "max_severity": None}],
        )
        for groups in severityless_groups:
            payload = report(
                str(self.management_lock),
                package="anyhow",
                version="1.0.100",
                advisory=advisory,
            )
            payload["results"][0]["packages"][0]["groups"] = groups
            with self.subTest(groups=groups):
                blocking, reviewed = self.evaluate(payload)
                self.assertEqual(len(blocking), 1)
                self.assertEqual(blocking[0][2], advisory)
                self.assertIsNone(blocking[0][3], "unrated score must be None")
                self.assertEqual(reviewed, [])

    def test_one_unrated_advisory_does_not_hide_the_rest_of_the_scan(self) -> None:
        # The abort this replaces stopped evaluation at the first unrated
        # advisory, so nothing after it was ever reported. Every package must
        # still be evaluated.
        payload = report(
            str(self.management_lock),
            package="rkyv",
            version="0.8.16",
            advisory="RUSTSEC-2026-0233",
        )
        results_packages = payload["results"][0]["packages"]
        results_packages[0]["groups"] = [
            {"ids": ["RUSTSEC-2026-0233"], "max_severity": ""}
        ]
        rated = copy.deepcopy(results_packages[0])
        rated["package"]["name"] = "scored-package"
        rated["package"]["version"] = "1.0.0"
        rated["vulnerabilities"][0]["id"] = "GHSA-scored-0001"
        rated["groups"] = [{"ids": ["GHSA-scored-0001"], "max_severity": "9.8"}]
        results_packages.append(rated)

        blocking, reviewed = self.evaluate(payload)

        self.assertEqual(reviewed, [])
        advisories = {row[2] for row in blocking}
        self.assertEqual(advisories, {"RUSTSEC-2026-0233", "GHSA-scored-0001"})
        scores = {row[2]: row[3] for row in blocking}
        self.assertIsNone(scores["RUSTSEC-2026-0233"])
        self.assertEqual(scores["GHSA-scored-0001"], 9.8)

    def test_unrated_findings_sort_first_and_render_without_a_score(self) -> None:
        rows = [
            ("scored", "1.0.0", "GHSA-low", 7.5, "Cargo.lock"),
            ("unrated", "0.8.16", "RUSTSEC-2026-0233", None, "Cargo.lock"),
            ("scored", "2.0.0", "GHSA-high", 9.8, "Cargo.lock"),
        ]

        lines = _format(rows)

        self.assertIn("CVSS ?.?", lines[0])
        self.assertIn("RUSTSEC-2026-0233", lines[0])
        self.assertIn("CVSS 9.8", lines[1])
        self.assertIn("CVSS 7.5", lines[2])

    def test_malformed_severity_fails_closed_even_without_a_fix(self) -> None:
        for fixed, raw_score in (
            (True, "not-a-score"),
            (False, "not-a-score"),
            (True, {}),
            (False, []),
            (True, True),
            (False, False),
        ):
            payload = report(str(self.management_lock))
            package_record = payload["results"][0]["packages"][0]
            package_record["groups"][0]["max_severity"] = raw_score
            if not fixed:
                package_record["vulnerabilities"][0]["affected"] = [
                    {"ranges": [{"events": [{"introduced": "0"}]}]}
                ]
            with (
                self.subTest(fixed=fixed, raw_score=raw_score),
                self.assertRaisesRegex(ValueError, "severity is missing or invalid"),
            ):
                self.evaluate(payload)

    def test_fixable_high_blocks_and_medium_is_informational(self) -> None:
        for score, expected_blocking in (("6.9", 0), ("7.0", 1), ("10.0", 1)):
            payload = report(
                str(self.management_lock),
                package="example",
                version="1.0.0",
                advisory="GHSA-2222-3333-4444",
            )
            payload["results"][0]["packages"][0]["groups"][0]["max_severity"] = score
            with self.subTest(score=score):
                blocking, reviewed = self.evaluate(payload)
                self.assertEqual(len(blocking), expected_blocking)
                self.assertEqual(reviewed, [])

    def test_nonfinite_or_out_of_range_severity_fails_closed(self) -> None:
        for score in ("NaN", "Infinity", "-1", "10.1"):
            payload = report(str(self.management_lock))
            payload["results"][0]["packages"][0]["groups"][0]["max_severity"] = score
            with self.subTest(score=score):
                with self.assertRaisesRegex(ValueError, "severity is out of range"):
                    self.evaluate(payload)

    def test_malformed_affected_shape_fails_closed(self) -> None:
        payload = report(str(self.management_lock))
        payload["results"][0]["packages"][0]["groups"] = []
        payload["results"][0]["packages"][0]["vulnerabilities"][0][
            "affected"
        ] = "malformed-not-an-array"
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
