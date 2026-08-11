#!/usr/bin/env python3

from __future__ import annotations

import copy
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import static_ui_runtime_receipt as receipt

HEX64 = "a" * 64
IMAGE_ID = f"sha256:{HEX64}"
SOURCE_SHA = "b" * 40
WORKFLOW_SHA = "c" * 40
NONCE = "d" * 64
BASE_IMAGE = (
    "nginx:alpine@sha256:"
    "4a73073bd557c65b759505da037898b61f1be6cbcc3c2c3aeac22d2a470c1752"
)


def sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def profile(*, repository: str = "example/static-ui") -> dict:
    dockerfile = f"FROM {BASE_IMAGE}\nUSER nginx\n"
    dockerignore = "node_modules\n"
    package_manifest = '{"dependencies":{"react-router":"7.18.2"}}\n'
    package_lock = '{"lockfileVersion":3}\n'
    return {
        "status": "approved",
        "pendingReason": None,
        "repositoryIdentity": {
            "repositoryId": "101",
            "ownerId": "202",
            "visibility": "private",
        },
        "exception": {
            **receipt.APPLICABILITY_EXCEPTION,
            "packageManifestPath": "package.json",
            "lockfilePath": "package-lock.json",
        },
        "contextSubdirectory": ".",
        "dockerfile": "Dockerfile",
        "dockerignore": ".dockerignore",
        "packagingFiles": {
            ".dockerignore": sha(dockerignore.encode()),
            "Dockerfile": sha(dockerfile.encode()),
            "package-lock.json": sha(package_lock.encode()),
            "package.json": sha(package_manifest.encode()),
        },
        "submodules": {},
        "buildSecret": None,
        "baseImage": BASE_IMAGE,
        "platform": {"os": "linux", "architecture": "amd64"},
        "imageConfig": {
            "user": "nginx",
            "workingDirectory": "/",
            "entrypoint": ["/entrypoint.sh"],
            "command": ["nginx", "-g", "daemon off;"],
            "environment": {
                "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
            },
            "exposedPorts": ["8080/tcp"],
            "stopSignal": "SIGQUIT",
        },
        "runtime": {
            "staticRoot": "/usr/share/nginx/html",
            "indexPath": "/usr/share/nginx/html/index.html",
            "nodeBinary": None,
            "nodeEntrypoints": [],
            "allowedPackageJsonPaths": [],
            "allowedRuntimeScriptRoots": ["/entrypoint.sh"],
        },
        "deployment": {
            "configuredEnvironmentAllowlist": ["APP_ENV"],
            "systemEnvironmentAllowlist": [
                "K_CONFIGURATION",
                "K_REVISION",
                "K_SERVICE",
                "PORT",
            ],
            "forbiddenEnvironment": [
                "BASH_ENV",
                "LD_PRELOAD",
                "NODE_OPTIONS",
            ],
        },
        "release": {
            "registryRepository": "registry.example/static-ui",
            "sourceRef": "refs/heads/main",
            "events": ["push"],
            "job": "staging",
            "workflowRef": (
                "example/static-ui/.github/workflows/cd.yml@refs/heads/main"
            ),
        },
    }


def policy(profile_value: dict | None = None) -> dict:
    return {
        "schemaVersion": 1,
        "profiles": {"example/static-ui": profile_value or profile()},
    }


def write_policy(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")


def run(*args: str, cwd: Path) -> str:
    result = subprocess.run(
        list(args),
        cwd=cwd,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return result.stdout.strip()


def init_repository(root: Path, files: dict[str, bytes]) -> str:
    run("git", "init", "-q", cwd=root)
    run("git", "config", "user.email", "test@example.invalid", cwd=root)
    run("git", "config", "user.name", "Test", cwd=root)
    run(
        "git",
        "remote",
        "add",
        "origin",
        "https://github.com/example/static-ui.git",
        cwd=root,
    )
    for relative, value in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value)
    run("git", "add", ".", cwd=root)
    run("git", "commit", "-qm", "fixture", cwd=root)
    return run("git", "rev-parse", "HEAD", cwd=root)


def tar_bytes(entries: list[tuple[str, bytes | None, int]]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for path, content, mode in entries:
            item = tarfile.TarInfo(path)
            item.mode = mode
            item.uid = 101
            item.gid = 101
            if content is None:
                item.type = tarfile.DIRTYPE
                item.size = 0
                archive.addfile(item)
            else:
                item.size = len(content)
                archive.addfile(item, io.BytesIO(content))
    return output.getvalue()


def good_tar(extra: list[tuple[str, bytes | None, int]] | None = None) -> bytes:
    entries = [
        ("usr", None, 0o755),
        ("usr/share", None, 0o755),
        ("usr/share/nginx", None, 0o755),
        ("usr/share/nginx/html", None, 0o755),
        ("usr/share/nginx/html/index.html", b"<html></html>", 0o644),
        ("usr/share/nginx/html/assets", None, 0o755),
        ("usr/share/nginx/html/assets/app.js", b"window.app=true;", 0o644),
        ("entrypoint.sh", b"#!/bin/sh\nexec nginx -g 'daemon off;'\n", 0o755),
    ]
    entries.extend(extra or [])
    return tar_bytes(entries)


def image_inspect(profile_value: dict | None = None) -> list[dict]:
    expected = (profile_value or profile())["imageConfig"]
    return [
        {
            "Id": IMAGE_ID,
            "Os": "linux",
            "Architecture": "amd64",
            "Config": {
                "User": expected["user"],
                "WorkingDir": expected["workingDirectory"],
                "Entrypoint": expected["entrypoint"],
                "Cmd": expected["command"],
                "Env": [
                    f"{key}={value}" for key, value in expected["environment"].items()
                ],
                "ExposedPorts": {port: {} for port in expected["exposedPorts"]},
                "StopSignal": expected["stopSignal"],
            },
            "RootFS": {"Type": "layers", "Layers": [f"sha256:{'e' * 64}"]},
        }
    ]


def context_manifest(profile_value: dict) -> dict:
    return {
        "schemaVersion": 1,
        "kind": "cognitum.static-ui.committed-context.v1",
        "repository": "example/static-ui",
        "sourceSha": SOURCE_SHA,
        "sourceTreeSha": "f" * 40,
        "contextSubdirectory": ".",
        "contextDigest": f"sha256:{'1' * 64}",
        "profileDigest": (
            f"sha256:{receipt.profile_digest('example/static-ui', profile_value)}"
        ),
        "packagingFileDigests": profile_value["packagingFiles"],
        "submodules": [],
        "fileCount": 4,
        "totalBytes": 10,
        "files": [],
    }


def github_context() -> dict:
    return {
        "repository": "example/static-ui",
        "repositoryId": "101",
        "repositoryOwnerId": "202",
        "repositoryVisibility": "private",
        "sourceSha": SOURCE_SHA,
        "sourceRef": "refs/pull/1/merge",
        "callerWorkflowRef": (
            "example/static-ui/.github/workflows/security.yml@refs/pull/1/merge"
        ),
        "callerWorkflowSha": WORKFLOW_SHA,
        "runId": "303",
        "runAttempt": "1",
        "job": "runtime-proof",
        "event": "pull_request",
    }


class ProfileAndContextTest(unittest.TestCase):
    def test_checked_in_profiles_are_strict_and_website_is_approved(self) -> None:
        loaded = receipt.load_policy(
            Path(__file__).with_name("static-ui-runtime-profiles.json")
        )
        self.assertEqual(
            {item["status"] for item in loaded["profiles"].values()},
            {"approved"},
        )
        receipt.profile_for("cognitum-one/website", loaded)
        receipt.profile_for("cognitum-one/management", loaded)
        self.assertEqual(
            loaded["profiles"]["cognitum-one/website"]["packagingFiles"][
                ".dockerignore"
            ],
            "7439be2d499aabfa11782c2ceb24b159b188e13f9ffced8b14a42e4feea4e29b",
        )

    def test_approved_profile_cannot_have_missing_digest(self) -> None:
        value = policy()
        value["profiles"]["example/static-ui"]["packagingFiles"]["Dockerfile"] = None
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "profiles.json"
            write_policy(path, value)
            with self.assertRaisesRegex(receipt.PolicyError, "digest is invalid"):
                receipt.load_policy(path)

    def test_committed_archive_ignores_dirty_and_untracked_files(self) -> None:
        dockerfile = f"FROM {BASE_IMAGE}\nUSER nginx\n".encode()
        dockerignore = b"node_modules\n"
        with tempfile.TemporaryDirectory() as directory:
            scratch = Path(directory)
            source = scratch / "source"
            source.mkdir()
            source_sha = init_repository(
                source,
                {
                    "Dockerfile": dockerfile,
                    ".dockerignore": dockerignore,
                    "package.json": b'{"dependencies":{"react-router":"7.18.2"}}\n',
                    "package-lock.json": b'{"lockfileVersion":3}\n',
                },
            )
            (source / "Dockerfile").write_text(
                "attacker dirty file\n", encoding="utf-8"
            )
            (source / "untracked").write_text("attacker\n", encoding="utf-8")
            output = scratch / "context"
            manifest = receipt.prepare_context(
                repository="example/static-ui",
                repository_root=source,
                source_sha=source_sha,
                destination=output,
                policy=policy(),
                identity_lookup=lambda _: {
                    "repositoryId": "101",
                    "ownerId": "202",
                    "visibility": "private",
                },
            )
            self.assertEqual((output / "Dockerfile").read_bytes(), dockerfile)
            self.assertFalse((output / "untracked").exists())
            self.assertEqual(manifest["sourceSha"], source_sha)
            self.assertEqual(manifest["fileCount"], 4)

    def test_repository_id_recreation_is_rejected(self) -> None:
        dockerfile = f"FROM {BASE_IMAGE}\nUSER nginx\n".encode()
        with tempfile.TemporaryDirectory() as directory:
            scratch = Path(directory)
            source = scratch / "source"
            source.mkdir()
            source_sha = init_repository(
                source,
                {
                    "Dockerfile": dockerfile,
                    ".dockerignore": b"node_modules\n",
                    "package.json": b'{"dependencies":{"react-router":"7.18.2"}}\n',
                    "package-lock.json": b'{"lockfileVersion":3}\n',
                },
            )
            with self.assertRaisesRegex(receipt.PolicyError, "identity differs"):
                receipt.prepare_context(
                    repository="example/static-ui",
                    repository_root=source,
                    source_sha=source_sha,
                    destination=scratch / "context",
                    policy=policy(),
                    identity_lookup=lambda _: {
                        "repositoryId": "999",
                        "ownerId": "202",
                        "visibility": "private",
                    },
                )

    def test_main_and_submodule_tree_bindings_are_not_confused(self) -> None:
        dockerfile = f"FROM {BASE_IMAGE}\nUSER nginx\n".encode()
        gitmodules = (
            b'[submodule "beacon"]\n'
            b"\tpath = beacon\n"
            b"\turl = https://github.com/cognitum-one/beacon.git\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            scratch = Path(directory)
            beacon = scratch / "beacon-source"
            beacon.mkdir()
            beacon_sha = init_repository(beacon, {"ui.js": b"export {};\n"})
            run(
                "git",
                "remote",
                "set-url",
                "origin",
                "https://github.com/cognitum-one/beacon.git",
                cwd=beacon,
            )
            beacon_tree = run("git", "rev-parse", f"{beacon_sha}^{{tree}}", cwd=beacon)

            source = scratch / "source"
            source.mkdir()
            init_repository(
                source,
                {
                    "Dockerfile": dockerfile,
                    ".dockerignore": b"node_modules\n",
                    ".gitmodules": gitmodules,
                    "package.json": b'{"dependencies":{"react-router":"7.18.2"}}\n',
                    "package-lock.json": b'{"lockfileVersion":3}\n',
                },
            )
            run(
                "git",
                "update-index",
                "--add",
                "--cacheinfo",
                f"160000,{beacon_sha},beacon",
                cwd=source,
            )
            run("git", "commit", "-qm", "pin beacon", cwd=source)
            source_sha = run("git", "rev-parse", "HEAD", cwd=source)
            source_tree = run("git", "rev-parse", f"{source_sha}^{{tree}}", cwd=source)
            value = profile()
            value["packagingFiles"][".gitmodules"] = sha(gitmodules)
            value["submodules"] = {
                "beacon": {
                    "repository": "cognitum-one/beacon",
                    "remote": "https://github.com/cognitum-one/beacon.git",
                    "repositoryId": "303",
                    "ownerId": "202",
                    "visibility": "private",
                    "commitSha": beacon_sha,
                    "treeSha": beacon_tree,
                }
            }

            manifest = receipt.prepare_context(
                repository="example/static-ui",
                repository_root=source,
                source_sha=source_sha,
                destination=scratch / "context",
                policy=policy(value),
                beacon_repository_root=beacon,
                identity_lookup=lambda repository: (
                    {
                        "repositoryId": "303",
                        "ownerId": "202",
                        "visibility": "private",
                    }
                    if repository == "cognitum-one/beacon"
                    else {
                        "repositoryId": "101",
                        "ownerId": "202",
                        "visibility": "private",
                    }
                ),
            )
            self.assertEqual(manifest["sourceTreeSha"], source_tree)
            self.assertEqual(manifest["submodules"][0]["treeSha"], beacon_tree)
            self.assertNotEqual(source_tree, beacon_tree)

    def test_parser_directive_is_rejected_even_when_hash_is_profiled(self) -> None:
        source_text = f"# syntax=docker/dockerfile:1\nFROM {BASE_IMAGE}\nUSER nginx\n"
        value = profile()
        value["packagingFiles"]["Dockerfile"] = sha(source_text.encode())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Dockerfile").write_text(source_text, encoding="utf-8")
            (root / ".dockerignore").write_text("node_modules\n", encoding="utf-8")
            (root / "package.json").write_text(
                '{"dependencies":{"react-router":"7.18.2"}}\n',
                encoding="utf-8",
            )
            (root / "package-lock.json").write_text(
                '{"lockfileVersion":3}\n', encoding="utf-8"
            )
            with self.assertRaisesRegex(receipt.PolicyError, "parser directives"):
                receipt._validate_packaging_files(root, value)

    def test_add_instruction_is_rejected_even_when_hash_is_profiled(self) -> None:
        source_text = f"FROM {BASE_IMAGE}\nADD https://attacker.invalid/x /x\n"
        value = profile()
        value["packagingFiles"]["Dockerfile"] = sha(source_text.encode())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Dockerfile").write_text(source_text, encoding="utf-8")
            (root / ".dockerignore").write_text("node_modules\n", encoding="utf-8")
            (root / "package.json").write_text(
                '{"dependencies":{"react-router":"7.18.2"}}\n',
                encoding="utf-8",
            )
            (root / "package-lock.json").write_text(
                '{"lockfileVersion":3}\n', encoding="utf-8"
            )
            with self.assertRaisesRegex(receipt.PolicyError, "ADD"):
                receipt._validate_packaging_files(root, value)


class BuildSecretTest(unittest.TestCase):
    def release_secret_value(self, secret: str) -> bytes:
        values = {
            "FIREBASE_WEB_API_KEY": ("AIzaSyDummyPlaceholderStaticUiReceiptFixture"),
            "FIREBASE_APP_CHECK_MANAGEMENT_SITE_KEY": (
                "6LcognitumStaticUiReceiptFixture123456789"
            ),
            "FIREBASE_APP_ID": "1:186366152200:web:abcdef0123456789",
            "FIREBASE_AUTH_DOMAIN": "project-12345.firebaseapp.com",
            "FIREBASE_MESSAGING_SENDER_ID": "186366152200",
            "FIREBASE_PROJECT_ID": "project-12345",
        }
        return values[secret].encode()

    def secret_profile(self) -> dict:
        value = profile()
        fixture_variables = {
            "VITE_FIREBASE_API_KEY": "premerge-fixture-api-key",
            "VITE_FIREBASE_PROJECT_ID": "premerge-fixture-project-id",
        }
        fixture_content = "".join(
            f"{key}={fixture_variables[key]}\n" for key in sorted(fixture_variables)
        ).encode()
        value["packagingFiles"]["config/frontend-build-secret-versions.json"] = "1" * 64
        value["buildSecret"] = {
            "id": "management_vite_env",
            "target": "/app/.env.production",
            "versionContractPath": "config/frontend-build-secret-versions.json",
            "project": "project-1",
            "premergeFixture": {
                "kind": "premerge-fixture",
                "mode": "premerge",
                "source": "organization-profile",
                "classification": "public-nonrelease",
                "variables": fixture_variables,
                "contentDigest": f"sha256:{sha(fixture_content)}",
            },
            "variables": {
                "VITE_FIREBASE_API_KEY": "FIREBASE_WEB_API_KEY",
                "VITE_FIREBASE_PROJECT_ID": "FIREBASE_PROJECT_ID",
            },
            "versions": {
                "VITE_FIREBASE_API_KEY": 11,
                "VITE_FIREBASE_PROJECT_ID": 12,
            },
        }
        return value

    def contract(self) -> dict:
        return {
            "schemaVersion": 1,
            "project": "project-1",
            "variables": {
                "VITE_FIREBASE_API_KEY": {
                    "secret": "FIREBASE_WEB_API_KEY",
                    "version": 11,
                },
                "VITE_FIREBASE_PROJECT_ID": {
                    "secret": "FIREBASE_PROJECT_ID",
                    "version": 12,
                },
            },
        }

    def test_numeric_versions_materialize_0600_without_values_in_metadata(self) -> None:
        calls = []

        def access(name: str, version: int, project: str) -> bytes:
            calls.append((name, version, project))
            return self.release_secret_value(name)

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "build.env"
            metadata = receipt.materialize_management_environment(
                profile=self.secret_profile(),
                contract=self.contract(),
                output_path=output,
                access_secret=access,
            )
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertEqual([call[1] for call in calls], [11, 12])
            for name, *_ in calls:
                self.assertNotIn(
                    self.release_secret_value(name).decode(),
                    json.dumps(metadata),
                )
            self.assertRegex(metadata["contentDigest"], r"^sha256:[0-9a-f]{64}$")
            self.assertEqual(metadata["kind"], "secret-manager")
            self.assertEqual(metadata["mode"], "release")
            self.assertEqual(metadata["source"], "gcloud-numeric-version")

    def test_latest_and_boolean_versions_are_rejected(self) -> None:
        for invalid in ("latest", True, 0, -1):
            contract = self.contract()
            contract["variables"]["VITE_FIREBASE_API_KEY"]["version"] = invalid
            with self.assertRaisesRegex(receipt.PolicyError, "positive numeric"):
                receipt._validated_version_contract(contract, self.secret_profile())

    def test_positive_numeric_version_drift_is_rejected(self) -> None:
        contract = self.contract()
        contract["variables"]["VITE_FIREBASE_API_KEY"]["version"] = 13
        with self.assertRaisesRegex(receipt.PolicyError, "numeric version drift"):
            receipt._validated_version_contract(contract, self.secret_profile())

    def test_control_character_secret_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(receipt.PolicyError, "control characters"):
                receipt.materialize_management_environment(
                    profile=self.secret_profile(),
                    contract=self.contract(),
                    output_path=Path(directory) / "build.env",
                    access_secret=lambda *_: b"bad\nvalue",
                )

    def test_dotenv_metacharacters_and_field_alphabet_drift_are_rejected(
        self,
    ) -> None:
        unsafe_values = (
            b"AIzaSyValidPrefix1234567890#truncated",
            b"$VITE_FIREBASE_PROJECT_ID",
            b"${VITE_FIREBASE_PROJECT_ID}",
            b"'AIzaSyQuoted12345678901234567890'",
            b'"AIzaSyQuoted12345678901234567890"',
            b"`AIzaSyQuoted12345678901234567890`",
            b"AIzaSyBackslash\\Value123456789012345",
            b"AIzaSyEquals=Value123456789012345678",
        )
        for index, unsafe in enumerate(unsafe_values):
            with self.subTest(value=unsafe):
                with tempfile.TemporaryDirectory() as directory:
                    output = Path(directory) / f"release-{index}.env"

                    def access(secret: str, *_: object) -> bytes:
                        if secret == "FIREBASE_WEB_API_KEY":
                            return unsafe
                        return self.release_secret_value(secret)

                    with self.assertRaisesRegex(
                        receipt.PolicyError,
                        "canonical Vite env alphabet",
                    ):
                        receipt.materialize_management_environment(
                            profile=self.secret_profile(),
                            contract=self.contract(),
                            output_path=output,
                            access_secret=access,
                        )
                    self.assertFalse(output.exists())

        invalid_fields = {
            "VITE_FIREBASE_AUTH_DOMAIN": b"https://project-12345.firebaseapp.com",
            "VITE_FIREBASE_MESSAGING_SENDER_ID": b"sender-186366152200",
            "VITE_FIREBASE_PROJECT_ID": b"Project_12345",
        }
        for name, value in invalid_fields.items():
            with self.subTest(name=name):
                with self.assertRaises(receipt.PolicyError):
                    receipt._validate_secret_value(name, value)

    def test_premerge_fixture_rejects_dotenv_comment_even_with_matching_digest(
        self,
    ) -> None:
        profile_value = self.secret_profile()
        fixture = profile_value["buildSecret"]["premergeFixture"]
        fixture["variables"]["VITE_FIREBASE_API_KEY"] = "premerge-fixture-api#truncated"
        content = "".join(
            f"{key}={fixture['variables'][key]}\n"
            for key in sorted(fixture["variables"])
        ).encode()
        fixture["contentDigest"] = f"sha256:{sha(content)}"
        with self.assertRaisesRegex(receipt.PolicyError, "unsafe for a Vite env"):
            receipt._validate_profile("example/static-ui", profile_value)

    def test_premerge_fixture_is_exact_public_nonrelease_profile_material(self) -> None:
        profile_value = self.secret_profile()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "build.env"
            metadata = receipt.materialize_premerge_fixture(
                profile=profile_value,
                contract=self.contract(),
                output_path=output,
            )
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertEqual(
                output.read_text(encoding="utf-8"),
                (
                    "VITE_FIREBASE_API_KEY=premerge-fixture-api-key\n"
                    "VITE_FIREBASE_PROJECT_ID=premerge-fixture-project-id\n"
                ),
            )
            self.assertEqual(metadata["kind"], "premerge-fixture")
            self.assertEqual(metadata["mode"], "premerge")
            self.assertEqual(metadata["source"], "organization-profile")
            self.assertEqual(metadata["classification"], "public-nonrelease")
            serialized = json.dumps(metadata, sort_keys=True)
            self.assertNotIn("FIREBASE_WEB_API_KEY", serialized)
            self.assertNotIn("project-1", serialized)
            self.assertNotIn("premerge-fixture-api-key", serialized)

    def test_premerge_never_calls_gcloud_but_release_calls_every_exact_version(
        self,
    ) -> None:
        profile_value = self.secret_profile()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with mock.patch.object(
                receipt,
                "_gcloud_secret_accessor",
                side_effect=AssertionError("premerge must not access Secret Manager"),
            ):
                evidence = receipt._materialize_profile_build_environment(
                    profile=profile_value,
                    contract=self.contract(),
                    output_path=root / "premerge.env",
                    mode="premerge",
                )
            self.assertEqual(evidence["kind"], "premerge-fixture")

            calls = []

            def access(secret: str, version: int, project: str) -> bytes:
                calls.append((secret, version, project))
                return self.release_secret_value(secret)

            with mock.patch.object(
                receipt, "_gcloud_secret_accessor", side_effect=access
            ):
                evidence = receipt._materialize_profile_build_environment(
                    profile=profile_value,
                    contract=self.contract(),
                    output_path=root / "release.env",
                    mode="release",
                )
            self.assertEqual(evidence["kind"], "secret-manager")
            self.assertEqual(
                calls,
                [
                    ("FIREBASE_WEB_API_KEY", 11, "project-1"),
                    ("FIREBASE_PROJECT_ID", 12, "project-1"),
                ],
            )

    def test_missing_release_secret_fails_without_writing_environment(self) -> None:
        profile_value = self.secret_profile()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "release.env"

            def access(secret: str, *_: object) -> bytes:
                if secret == "FIREBASE_PROJECT_ID":
                    raise receipt.PolicyError("missing exact numeric secret")
                return self.release_secret_value(secret)

            with self.assertRaisesRegex(receipt.PolicyError, "missing exact numeric"):
                receipt.materialize_management_environment(
                    profile=profile_value,
                    contract=self.contract(),
                    output_path=output,
                    access_secret=access,
                )
            self.assertFalse(output.exists())

        loaded = receipt.load_policy(
            Path(__file__).with_name("static-ui-runtime-profiles.json")
        )
        management = receipt.profile_for("cognitum-one/management", loaded)
        build_secret = management["buildSecret"]
        contract = {
            "schemaVersion": 1,
            "project": build_secret["project"],
            "variables": {
                environment_name: {
                    "secret": secret_name,
                    "version": build_secret["versions"][environment_name],
                }
                for environment_name, secret_name in build_secret["variables"].items()
            },
        }
        missing_secrets = (
            "FIREBASE_WEB_API_KEY",
            "FIREBASE_MESSAGING_SENDER_ID",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index, missing in enumerate(missing_secrets):
                with self.subTest(missing=missing):
                    output = root / f"release-{index}.env"

                    def access_exact(secret: str, *_: object) -> bytes:
                        if secret == missing:
                            raise receipt.PolicyError(
                                "missing exact numeric secret version"
                            )
                        return self.release_secret_value(secret)

                    with self.assertRaisesRegex(
                        receipt.PolicyError, "missing exact numeric"
                    ):
                        receipt.materialize_management_environment(
                            profile=management,
                            contract=contract,
                            output_path=output,
                            access_secret=access_exact,
                        )
                    self.assertFalse(output.exists())

    def test_cross_mode_materialization_claims_are_rejected(self) -> None:
        profile_value = self.secret_profile()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = receipt.materialize_premerge_fixture(
                profile=profile_value,
                contract=self.contract(),
                output_path=root / "premerge.env",
            )
            release = receipt.materialize_management_environment(
                profile=profile_value,
                contract=self.contract(),
                output_path=root / "release.env",
                access_secret=lambda secret, *_: self.release_secret_value(secret),
            )
        with self.assertRaisesRegex(receipt.PolicyError, "secret-manager"):
            receipt._validate_build_materialization_evidence(
                profile=profile_value,
                mode="release",
                evidence=fixture,
            )
        with self.assertRaisesRegex(receipt.PolicyError, "premerge fixture"):
            receipt._validate_build_materialization_evidence(
                profile=profile_value,
                mode="premerge",
                evidence=release,
            )

    def test_receipt_verifier_binds_premerge_fixture_and_profile(self) -> None:
        profile_value = self.secret_profile()
        policy_value = policy(profile_value)
        inventory = receipt.inventory_rootfs(io.BytesIO(good_tar()), profile_value)
        context = context_manifest(profile_value)
        metadata = {
            "containerimage.config.digest": IMAGE_ID,
            "containerimage.digest": f"sha256:{'9' * 64}",
            "buildx.build.ref": "builder/ref",
            "buildx.build.provenance": {"mode": "max"},
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_path = root / "profiles.json"
            write_policy(policy_path, policy_value)
            fixture = receipt.materialize_premerge_fixture(
                profile=profile_value,
                contract=self.contract(),
                output_path=root / "premerge.env",
            )
            value = receipt.build_receipt(
                repository="example/static-ui",
                policy=policy_value,
                policy_path=policy_path,
                context_manifest=context,
                image_inspect=image_inspect(profile_value),
                inventory=inventory,
                build_metadata=metadata,
                mode="premerge",
                image_name="registry.example/static-ui",
                registry_digest=None,
                github_context=github_context(),
                receipt_nonce=NONCE,
                build_invocation=receipt._exact_build_invocation(
                    profile_value, context
                ),
                build_secret_metadata=fixture,
            )
            receipt.verify_premerge_receipt(
                receipt=value,
                inventory=inventory,
                repository="example/static-ui",
                policy=policy_value,
                policy_path=policy_path,
                expected_source_sha=SOURCE_SHA,
                expected_image_name="registry.example/static-ui",
                expected_image_id=IMAGE_ID,
                expected_run_id="303",
                expected_run_attempt="1",
                expected_job="runtime-proof",
                expected_workflow_ref=github_context()["callerWorkflowRef"],
                expected_workflow_sha=WORKFLOW_SHA,
                expected_nonce=NONCE,
            )

            for mutation in (
                "source",
                "content-digest",
                "value-digest",
                "extra-metadata",
            ):
                with self.subTest(mutation=mutation):
                    forged = copy.deepcopy(value)
                    materialization = forged["build"]["buildSecret"]
                    if mutation == "source":
                        materialization["source"] = "secret-manager"
                    elif mutation == "content-digest":
                        materialization["contentDigest"] = f"sha256:{'0' * 64}"
                    elif mutation == "value-digest":
                        materialization["variables"][0][
                            "valueDigest"
                        ] = f"sha256:{'0' * 64}"
                    else:
                        materialization["attacker"] = True
                    unsigned = dict(forged)
                    unsigned.pop("receiptDigest")
                    forged["receiptDigest"] = (
                        f"sha256:{sha(receipt._canonical_bytes(unsigned))}"
                    )
                    with self.assertRaisesRegex(
                        receipt.PolicyError, "premerge fixture"
                    ):
                        receipt.verify_premerge_receipt(
                            receipt=forged,
                            inventory=inventory,
                            repository="example/static-ui",
                            policy=policy_value,
                            policy_path=policy_path,
                            expected_source_sha=SOURCE_SHA,
                            expected_image_name="registry.example/static-ui",
                            expected_image_id=IMAGE_ID,
                            expected_run_id="303",
                            expected_run_attempt="1",
                            expected_job="runtime-proof",
                            expected_workflow_ref=github_context()["callerWorkflowRef"],
                            expected_workflow_sha=WORKFLOW_SHA,
                            expected_nonce=NONCE,
                        )

            changed_profile = copy.deepcopy(profile_value)
            changed_fixture = changed_profile["buildSecret"]["premergeFixture"]
            changed_fixture["variables"][
                "VITE_FIREBASE_API_KEY"
            ] = "premerge-fixture-other-api-key"
            changed_content = "".join(
                f"{key}={changed_fixture['variables'][key]}\n"
                for key in sorted(changed_fixture["variables"])
            ).encode()
            changed_fixture["contentDigest"] = f"sha256:{sha(changed_content)}"
            with self.assertRaises(receipt.PolicyError):
                receipt.verify_premerge_receipt(
                    receipt=value,
                    inventory=inventory,
                    repository="example/static-ui",
                    policy=policy(changed_profile),
                    policy_path=policy_path,
                    expected_source_sha=SOURCE_SHA,
                    expected_image_name="registry.example/static-ui",
                    expected_image_id=IMAGE_ID,
                    expected_run_id="303",
                    expected_run_attempt="1",
                    expected_job="runtime-proof",
                    expected_workflow_ref=github_context()["callerWorkflowRef"],
                    expected_workflow_sha=WORKFLOW_SHA,
                    expected_nonce=NONCE,
                )

    def test_fixture_source_mode_extra_value_and_digest_drift_fail_closed(
        self,
    ) -> None:
        mutations = [
            ("source", "caller"),
            ("mode", "release"),
            ("contentDigest", f"sha256:{'0' * 64}"),
        ]
        for key, changed in mutations:
            with self.subTest(key=key):
                profile_value = self.secret_profile()
                profile_value["buildSecret"]["premergeFixture"][key] = changed
                with self.assertRaises(receipt.PolicyError):
                    receipt._validate_profile("example/static-ui", profile_value)

        profile_value = self.secret_profile()
        profile_value["buildSecret"]["premergeFixture"]["attacker"] = True
        with self.assertRaisesRegex(receipt.PolicyError, "keys differ"):
            receipt._validate_profile("example/static-ui", profile_value)

        profile_value = self.secret_profile()
        profile_value["buildSecret"]["premergeFixture"]["variables"][
            "VITE_FIREBASE_API_KEY"
        ] = "premerge-fixture-altered"
        with self.assertRaisesRegex(receipt.PolicyError, "content digest differs"):
            receipt._validate_profile("example/static-ui", profile_value)

        profile_value = self.secret_profile()
        profile_value["buildSecret"]["premergeFixture"]["variables"][
            "VITE_ATTACKER"
        ] = "premerge-fixture-attacker"
        with self.assertRaisesRegex(receipt.PolicyError, "variable set differs"):
            receipt._validate_profile("example/static-ui", profile_value)


class RuntimeInventoryTest(unittest.TestCase):
    def test_image_inspect_uses_portable_cli_shape(self) -> None:
        inspect_value = image_inspect()
        with mock.patch.object(
            receipt,
            "_run",
            return_value=json.dumps(inspect_value).encode("utf-8"),
        ) as runner:
            self.assertEqual(
                receipt._docker_image_inspect("example.invalid/app:immutable"),
                inspect_value,
            )
        runner.assert_called_once_with(
            [
                "docker",
                "image",
                "inspect",
                "example.invalid/app:immutable",
            ],
            timeout=120,
        )

    def test_static_nginx_runtime_passes(self) -> None:
        inventory = receipt.inventory_rootfs(io.BytesIO(good_tar()), profile())
        self.assertEqual(inventory["findings"], [])
        self.assertGreater(inventory["policyEvidence"]["staticEntryCount"], 1)

    def test_node_modules_and_renamed_router_paths_are_rejected(self) -> None:
        additions = [
            ("srv", None, 0o755),
            ("srv/node_modules", None, 0o755),
            ("srv/node_modules/react-router", None, 0o755),
            ("srv/node_modules/react-router/index.js", b"module.exports={}", 0o644),
        ]
        inventory = receipt.inventory_rootfs(io.BytesIO(good_tar(additions)), profile())
        self.assertTrue(
            any(
                "forbidden runtime package path" in item
                for item in inventory["findings"]
            )
        )

    def test_package_manager_and_lockfile_are_rejected(self) -> None:
        additions = [
            ("usr/local/bin/npm", b"#!/bin/sh\n", 0o755),
            ("app/package-lock.json", b"{}", 0o644),
        ]
        inventory = receipt.inventory_rootfs(io.BytesIO(good_tar(additions)), profile())
        self.assertTrue(
            any("package manager" in item for item in inventory["findings"])
        )
        self.assertTrue(any("lockfile" in item for item in inventory["findings"]))

    def test_executable_or_link_in_static_root_is_rejected(self) -> None:
        executable = tar_bytes(
            [
                ("usr/share/nginx/html", None, 0o755),
                ("usr/share/nginx/html/index.html", b"x", 0o755),
            ]
        )
        inventory = receipt.inventory_rootfs(io.BytesIO(executable), profile())
        self.assertTrue(any("executable" in item for item in inventory["findings"]))

    def test_rsc_and_dynamic_import_in_server_script_are_rejected(self) -> None:
        additions = [
            (
                "entrypoint.sh",
                b"const x='unstable_matchRSCServerRequest'; import(x);",
                0o755,
            )
        ]
        # Duplicate tar paths fail before content policy, which is also fail-closed.
        with self.assertRaisesRegex(receipt.PolicyError, "duplicate path"):
            receipt.inventory_rootfs(io.BytesIO(good_tar(additions)), profile())
        alternate = copy.deepcopy(profile())
        alternate["runtime"]["allowedRuntimeScriptRoots"] = ["/server.js"]
        rsc_tar = good_tar(
            [
                (
                    "server.js",
                    b"const x='unstable_matchRSCServerRequest'; import(x);",
                    0o644,
                )
            ]
        )
        inventory = receipt.inventory_rootfs(io.BytesIO(rsc_tar), alternate)
        self.assertTrue(any("RSC surface" in item for item in inventory["findings"]))
        self.assertTrue(any("dynamic code" in item for item in inventory["findings"]))

    def test_image_command_environment_and_platform_drift_are_rejected(self) -> None:
        value = image_inspect()
        value[0]["Architecture"] = "arm64"
        value[0]["Config"]["Cmd"] = ["node", "server.js"]
        value[0]["Config"]["Env"].append("NODE_OPTIONS=--require=/tmp/x")
        _, findings = receipt.validate_image_inspect(value, profile())
        self.assertTrue(any("platform" in item for item in findings))
        self.assertTrue(any("command" in item for item in findings))
        self.assertTrue(any("environment" in item for item in findings))


class ReceiptAndRevisionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.scratch = tempfile.TemporaryDirectory()
        self.root = Path(self.scratch.name)
        self.profile = profile()
        self.policy = policy(self.profile)
        self.policy_path = self.root / "profiles.json"
        write_policy(self.policy_path, self.policy)
        self.inventory = receipt.inventory_rootfs(io.BytesIO(good_tar()), self.profile)
        self.context = context_manifest(self.profile)
        self.metadata = {
            "containerimage.config.digest": IMAGE_ID,
            "containerimage.digest": f"sha256:{'9' * 64}",
            "buildx.build.ref": "builder/ref",
            "buildx.build.provenance": {"mode": "max"},
        }
        self.invocation = receipt._exact_build_invocation(self.profile, self.context)

    def tearDown(self) -> None:
        self.scratch.cleanup()

    def make_receipt(self, mode: str = "premerge") -> dict:
        invocation_context = github_context()
        if mode == "release":
            invocation_context.update(
                {
                    "sourceRef": "refs/heads/main",
                    "callerWorkflowRef": (
                        "example/static-ui/.github/workflows/" "cd.yml@refs/heads/main"
                    ),
                    "callerWorkflowSha": SOURCE_SHA,
                    "job": "staging",
                    "event": "push",
                }
            )
        return receipt.build_receipt(
            repository="example/static-ui",
            policy=self.policy,
            policy_path=self.policy_path,
            context_manifest=self.context,
            image_inspect=image_inspect(self.profile),
            inventory=self.inventory,
            build_metadata=self.metadata,
            mode=mode,
            image_name="registry.example/static-ui",
            registry_digest=(None if mode == "premerge" else f"sha256:{'8' * 64}"),
            github_context=invocation_context,
            receipt_nonce=NONCE,
            build_invocation=self.invocation,
        )

    def verify_premerge(self, value: dict, **overrides: str) -> None:
        arguments = {
            "receipt": value,
            "inventory": self.inventory,
            "repository": "example/static-ui",
            "policy": self.policy,
            "policy_path": self.policy_path,
            "expected_source_sha": SOURCE_SHA,
            "expected_image_name": "registry.example/static-ui",
            "expected_image_id": IMAGE_ID,
            "expected_run_id": "303",
            "expected_run_attempt": "1",
            "expected_job": "runtime-proof",
            "expected_workflow_ref": (
                "example/static-ui/.github/workflows/security.yml@refs/pull/1/merge"
            ),
            "expected_workflow_sha": WORKFLOW_SHA,
            "expected_nonce": NONCE,
        }
        arguments.update(overrides)
        receipt.verify_premerge_receipt(**arguments)

    def test_premerge_receipt_binds_local_image_and_same_job_nonce(self) -> None:
        value = self.make_receipt()
        self.verify_premerge(value)
        self.assertEqual(value["mode"], "premerge")
        self.assertIsNone(value["image"]["registryDigest"])
        self.assertEqual(value["subject"]["kind"], "local-image-config")

    def test_premerge_receipt_cannot_satisfy_release(self) -> None:
        value = self.make_receipt()
        with self.assertRaisesRegex(receipt.PolicyError, "replay-binding tuple"):
            receipt.verify_receipt(
                receipt=value,
                inventory=self.inventory,
                repository="example/static-ui",
                policy=self.policy,
                policy_path=self.policy_path,
                expected_mode="release",
                expected_source_sha=SOURCE_SHA,
                expected_image_name="registry.example/static-ui",
                expected_subject_digest=f"sha256:{'8' * 64}",
                expected_run_id="303",
                expected_run_attempt="1",
                expected_job="runtime-proof",
                expected_workflow_ref=github_context()["callerWorkflowRef"],
                expected_workflow_sha=WORKFLOW_SHA,
                expected_nonce=NONCE,
            )

    def test_nonce_job_source_and_image_replay_mutations_fail(self) -> None:
        value = self.make_receipt()
        mutations = [
            {"expected_nonce": "0" * 64},
            {"expected_job": "other-job"},
            {"expected_source_sha": "0" * 40},
            {"expected_image_id": f"sha256:{'0' * 64}"},
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                with self.assertRaises(receipt.PolicyError):
                    self.verify_premerge(value, **mutation)

    def test_replay_mismatch_reports_names_without_values(self) -> None:
        value = self.make_receipt()
        with self.assertRaisesRegex(
            receipt.PolicyError,
            r"tuple differs: job, nonce",
        ) as raised:
            self.verify_premerge(
                value,
                expected_job="private-job-value",
                expected_nonce="0" * 64,
            )
        self.assertNotIn("private-job-value", str(raised.exception))
        self.assertNotIn("0" * 64, str(raised.exception))

    def test_forged_generator_digest_fails_even_with_recomputed_receipt_hash(
        self,
    ) -> None:
        value = self.make_receipt()
        value["policy"]["generatorDigest"] = f"sha256:{'0' * 64}"
        unsigned = dict(value)
        unsigned.pop("receiptDigest")
        value["receiptDigest"] = f"sha256:{sha(receipt._canonical_bytes(unsigned))}"
        with self.assertRaisesRegex(receipt.PolicyError, "replay-binding tuple"):
            self.verify_premerge(value)

    def test_numeric_repository_identity_drift_fails(self) -> None:
        value = self.make_receipt()
        value["invocation"]["repositoryId"] = "999"
        unsigned = dict(value)
        unsigned.pop("receiptDigest")
        value["receiptDigest"] = f"sha256:{sha(receipt._canonical_bytes(unsigned))}"
        with self.assertRaisesRegex(receipt.PolicyError, "replay-binding tuple"):
            self.verify_premerge(value)

    def test_inventory_digest_is_recomputed_from_exact_entries(self) -> None:
        value = self.make_receipt()
        forged_inventory = copy.deepcopy(self.inventory)
        forged_inventory["entries"][0]["mode"] ^= 0o001
        forged_inventory["findings"] = []
        with self.assertRaisesRegex(receipt.PolicyError, "inventory content digest"):
            receipt.verify_premerge_receipt(
                receipt=value,
                inventory=forged_inventory,
                repository="example/static-ui",
                policy=self.policy,
                policy_path=self.policy_path,
                expected_source_sha=SOURCE_SHA,
                expected_image_name="registry.example/static-ui",
                expected_image_id=IMAGE_ID,
                expected_run_id="303",
                expected_run_attempt="1",
                expected_job="runtime-proof",
                expected_workflow_ref=github_context()["callerWorkflowRef"],
                expected_workflow_sha=WORKFLOW_SHA,
                expected_nonce=NONCE,
            )

    def test_semantic_inventory_forgery_is_recomputed_and_rejected(self) -> None:
        value = self.make_receipt()
        forged_inventory = copy.deepcopy(self.inventory)
        payload = b"#!/bin/sh\n"
        forged_inventory["entries"].extend(
            [
                {
                    "path": "/srv/node_modules/react-router/index.js",
                    "type": "file",
                    "mode": 0o644,
                    "uid": 101,
                    "gid": 101,
                    "size": len(payload),
                    "sha256": sha(payload),
                },
                {
                    "path": "/usr/local/bin/npm",
                    "type": "file",
                    "mode": 0o755,
                    "uid": 101,
                    "gid": 101,
                    "size": len(payload),
                    "sha256": sha(payload),
                },
            ]
        )
        forged_inventory["entries"].sort(key=lambda item: item["path"])
        forged_inventory["entryCount"] = len(forged_inventory["entries"])
        forged_inventory["regularFileCount"] += 2
        forged_inventory["totalRegularFileBytes"] += len(payload) * 2
        forged_inventory["inventoryDigest"] = "sha256:" + sha(
            receipt._canonical_bytes(
                {
                    "entries": forged_inventory["entries"],
                    "policyInputs": forged_inventory["policyInputs"],
                }
            )
        )
        with self.assertRaisesRegex(receipt.PolicyError, "semantic evidence"):
            receipt.verify_premerge_receipt(
                receipt=value,
                inventory=forged_inventory,
                repository="example/static-ui",
                policy=self.policy,
                policy_path=self.policy_path,
                expected_source_sha=SOURCE_SHA,
                expected_image_name="registry.example/static-ui",
                expected_image_id=IMAGE_ID,
                expected_run_id="303",
                expected_run_attempt="1",
                expected_job="runtime-proof",
                expected_workflow_ref=github_context()["callerWorkflowRef"],
                expected_workflow_sha=WORKFLOW_SHA,
                expected_nonce=NONCE,
            )

    def test_extra_assertion_is_rejected_even_when_receipt_is_rehashed(self) -> None:
        value = self.make_receipt()
        value["assertions"]["attackerClaim"] = True
        unsigned = dict(value)
        unsigned.pop("receiptDigest")
        value["receiptDigest"] = f"sha256:{sha(receipt._canonical_bytes(unsigned))}"
        with self.assertRaisesRegex(receipt.PolicyError, "assertions"):
            self.verify_premerge(value)

    def test_release_receipt_binds_registry_digest(self) -> None:
        value = self.make_receipt("release")
        receipt.verify_receipt(
            receipt=value,
            inventory=self.inventory,
            repository="example/static-ui",
            policy=self.policy,
            policy_path=self.policy_path,
            expected_mode="release",
            expected_source_sha=SOURCE_SHA,
            expected_image_name="registry.example/static-ui",
            expected_subject_digest=f"sha256:{'8' * 64}",
            expected_run_id="303",
            expected_run_attempt="1",
            expected_job="staging",
            expected_workflow_ref=(
                "example/static-ui/.github/workflows/cd.yml@refs/heads/main"
            ),
            expected_workflow_sha=SOURCE_SHA,
            expected_nonce=NONCE,
        )

    def good_revision(self) -> dict:
        return {
            "spec": {
                "serviceAccountName": (
                    "website-runtime@project-1.iam.gserviceaccount.com"
                ),
                "containers": [
                    {
                        "image": f"registry.example/static-ui@sha256:{'8' * 64}",
                        "ports": [{"name": "http1", "containerPort": 8080}],
                        "env": [{"name": "APP_ENV", "value": "staging"}],
                    }
                ],
            }
        }

    def validate_good_revision(self, value: dict | None = None) -> dict[str, object]:
        revision = value or self.good_revision()
        spec_digest = f"sha256:{sha(receipt._canonical_bytes(revision['spec']))}"
        return receipt.validate_revision(
            revision=revision,
            profile=self.profile,
            expected_image=f"registry.example/static-ui@sha256:{'8' * 64}",
            expected_service_account=(
                "website-runtime@project-1.iam.gserviceaccount.com"
            ),
            expected_spec_digest=spec_digest,
        )

    def test_cloud_run_revision_exact_single_container_passes(self) -> None:
        evidence = self.validate_good_revision()
        self.assertEqual(evidence["containerCount"], 1)
        self.assertEqual(evidence["port"], 8080)
        self.assertRegex(evidence["evidenceDigest"], r"^sha256:[0-9a-f]{64}$")

    def test_cloud_run_sidecar_command_volume_and_env_mutations_fail(self) -> None:
        cases = []
        sidecar = self.good_revision()
        sidecar["spec"]["containers"].append({"image": "attacker"})
        cases.append(sidecar)
        command = self.good_revision()
        command["spec"]["containers"][0]["command"] = ["node"]
        cases.append(command)
        volume = self.good_revision()
        volume["spec"]["volumes"] = [{"name": "code"}]
        cases.append(volume)
        environment = self.good_revision()
        environment["spec"]["containers"][0]["env"].append(
            {"name": "NODE_OPTIONS", "value": "--require=x"}
        )
        cases.append(environment)
        for value in cases:
            with self.subTest(value=value):
                with self.assertRaises(receipt.PolicyError):
                    self.validate_good_revision(value)

    def test_cloud_run_service_account_port_and_secret_version_fail_closed(
        self,
    ) -> None:
        cases = []
        service_account = self.good_revision()
        service_account["spec"][
            "serviceAccountName"
        ] = "attacker@project-1.iam.gserviceaccount.com"
        cases.append(service_account)
        port = self.good_revision()
        port["spec"]["containers"][0]["ports"][0]["containerPort"] = 80
        cases.append(port)
        latest = self.good_revision()
        latest["spec"]["containers"][0]["env"] = [
            {
                "name": "APP_ENV",
                "valueSource": {
                    "secretKeyRef": {
                        "secret": "APP_ENV",
                        "version": "latest",
                    }
                },
            }
        ]
        cases.append(latest)
        dependency = self.good_revision()
        dependency["metadata"] = {
            "annotations": {
                "run.googleapis.com/container-dependencies": '{"app":["proxy"]}'
            }
        }
        cases.append(dependency)
        for value in cases:
            with self.subTest(value=value):
                with self.assertRaises(receipt.PolicyError):
                    self.validate_good_revision(value)


if __name__ == "__main__":
    unittest.main()
