#!/usr/bin/env python3

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from osv_gate import ROUTER_EXCEPTION_EXPIRES, evaluate


def lock(version: str = "7.18.2") -> dict:
    return {
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"react-router-dom": version}},
            "node_modules/react-router": {"version": version},
            "node_modules/react-router-dom": {
                "version": version,
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
        self.management_source = self.root / "management-ui" / "src"
        self.management_source.mkdir()
        (self.management_source / "App.tsx").write_text(
            'import { BrowserRouter } from "react-router-dom";',
            encoding="utf-8",
        )
        (self.root / "management-ui" / "vite.config.ts").write_text(
            'import { defineConfig } from "vite"; export default defineConfig({});',
            encoding="utf-8",
        )
        self.today = ROUTER_EXCEPTION_EXPIRES - dt.timedelta(days=1)

    def tearDown(self) -> None:
        self.scratch.cleanup()

    def evaluate(self, payload: dict, repository: str = "cognitum-one/management"):
        return evaluate(payload, repository=repository, root=self.root, today=self.today)

    def test_accepts_only_the_exact_patched_router_record(self) -> None:
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

    def test_rsc_dependency_is_not_excused(self) -> None:
        manifest = json.loads(self.management_manifest.read_text(encoding="utf-8"))
        manifest.setdefault("devDependencies", {})["@react-router/dev"] = "7.18.2"
        self.management_manifest.write_text(json.dumps(manifest), encoding="utf-8")
        blocking, reviewed = self.evaluate(report(str(self.management_lock)))
        self.assertEqual(len(blocking), 1)
        self.assertEqual(reviewed, [])

    def test_transitive_rsc_dependency_is_not_excused(self) -> None:
        payload = json.loads(self.management_lock.read_text(encoding="utf-8"))
        payload["packages"]["node_modules/react-server-dom-webpack"] = {
            "version": "19.0.0"
        }
        self.management_lock.write_text(json.dumps(payload), encoding="utf-8")
        blocking, reviewed = self.evaluate(report(str(self.management_lock)))
        self.assertEqual(len(blocking), 1)
        self.assertEqual(reviewed, [])

    def test_nested_router_copy_is_not_excused(self) -> None:
        payload = json.loads(self.management_lock.read_text(encoding="utf-8"))
        payload["packages"]["node_modules/other/node_modules/react-router"] = {
            "version": "7.18.2"
        }
        self.management_lock.write_text(json.dumps(payload), encoding="utf-8")
        blocking, reviewed = self.evaluate(report(str(self.management_lock)))
        self.assertEqual(len(blocking), 1)
        self.assertEqual(reviewed, [])

    def test_rsc_import_is_not_excused(self) -> None:
        (self.management_source / "server.ts").write_text(
            'import { unstable_matchRSCServerRequest } from "react-router";',
            encoding="utf-8",
        )
        blocking, reviewed = self.evaluate(report(str(self.management_lock)))
        self.assertEqual(len(blocking), 1)
        self.assertEqual(reviewed, [])

    def test_rsc_condition_is_not_excused(self) -> None:
        manifest = json.loads(self.management_manifest.read_text(encoding="utf-8"))
        manifest["scripts"]["build"] = "node --conditions=react-server build.mjs"
        self.management_manifest.write_text(json.dumps(manifest), encoding="utf-8")
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

    def test_malformed_report_fails_closed(self) -> None:
        with self.assertRaises(ValueError):
            self.evaluate({"results": [{"source": {"path": "x"}}]})


if __name__ == "__main__":
    unittest.main()
