#!/usr/bin/env python3
"""Build and attest the reviewed static-UI runtime boundary.

This module is organization policy.  It is intended to be fetched from an
immutable cognitum-one/.github commit and run outside the candidate checkout.
It deliberately does not accept caller-selected Dockerfiles, contexts, build
arguments, commands, targets, platforms, or runtime policy.

The defensible security claim is narrow: React Router may execute in the
browser bundle under the static root, but no React Router or React Server
Components package, package manager, or server entrypoint is present in the
container runtime.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from typing import Any, Callable, Iterable

SCHEMA_VERSION = 1
PREDICATE_TYPE = "https://cognitum.one/attestations/static-ui-runtime/v1"
DEFAULT_POLICY = Path(__file__).with_name("static-ui-runtime-profiles.json")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
IMAGE_DIGEST_RE = re.compile(r"^sha256:([0-9a-f]{64})$")
IMAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
LOCAL_TAG_RE = re.compile(
    r"^(?:[a-z0-9.-]+(?::[0-9]+)?/)?"
    r"[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*"
    r":[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$"
)
PARSER_DIRECTIVE_RE = re.compile(
    r"^\s*#\s*(?:syntax|escape|check)\s*=", re.IGNORECASE | re.MULTILINE
)
FORBIDDEN_RUNTIME_COMPONENTS = {
    "node_modules",
    "react-router",
    "react-router-dom",
    "react-server-dom-parcel",
    "react-server-dom-turbopack",
    "react-server-dom-webpack",
}
FORBIDDEN_PACKAGE_FILES = {
    "npm-shrinkwrap.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
}
FORBIDDEN_PACKAGE_MANAGERS = {
    "corepack",
    "npm",
    "npx",
    "pnpm",
    "yarn",
    "yarnpkg",
}
RUNTIME_RSC_RE = re.compile(
    r"(?:unstable_(?:matchRSCServerRequest|createCallServer|getRSCStream)"
    r"|react-server-dom|[\"']use server[\"']|[\"']react-server[\"'])"
)
DYNAMIC_CODE_RE = re.compile(
    r"(?:\bimport\s*\(|\brequire\s*\(\s*[^\"']|\beval\s*\(|\bnew\s+Function\s*\()"
)
STATIC_MAX_ENTRIES = 100_000
STATIC_MAX_BYTES = 4 * 1024 * 1024 * 1024
MAX_POLICY_TEXT = 2 * 1024 * 1024
MAX_POLICY_CAPTURE_BYTES = 16 * 1024 * 1024
MAX_SECRET_VALUE = 16 * 1024
MAX_BUILD_ENV_BYTES = 16 * 1024
PREMERGE_ENV_VALUE_RE = re.compile(r"^premerge-fixture-[a-z0-9.-]+$")
RELEASE_ENV_VALUE_RES = {
    "VITE_FIREBASE_API_KEY": re.compile(r"^[A-Za-z0-9_-]{20,256}$"),
    "VITE_FIREBASE_APP_CHECK_SITE_KEY": re.compile(r"^[A-Za-z0-9_-]{20,256}$"),
    "VITE_FIREBASE_APP_ID": re.compile(r"^[A-Za-z0-9:._-]{8,256}$"),
    "VITE_FIREBASE_AUTH_DOMAIN": re.compile(r"^[A-Za-z0-9.-]{1,253}$"),
    "VITE_FIREBASE_MESSAGING_SENDER_ID": re.compile(r"^[0-9]{1,32}$"),
    "VITE_FIREBASE_PROJECT_ID": re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$"),
}
PREMERGE_FIXTURE_KIND = "premerge-fixture"
PREMERGE_FIXTURE_SOURCE = "organization-profile"
PREMERGE_FIXTURE_CLASSIFICATION = "public-nonrelease"
RELEASE_SECRET_KIND = "secret-manager"
RELEASE_SECRET_SOURCE = "gcloud-numeric-version"
APPLICABILITY_EXCEPTION = {
    "advisory": "GHSA-qwww-vcr4-c8h2",
    "package": "react-router",
    "version": "7.18.2",
    "expiresExclusiveUtc": "2026-11-15",
    "maintainerAdvisoryUrl": (
        "https://github.com/remix-run/react-router/security/advisories/"
        "GHSA-qwww-vcr4-c8h2"
    ),
}
ASSERTION_KEYS = {
    "committedOnlyContext",
    "exactPackagingPolicy",
    "exactBuildInvocation",
    "sameImageConfigDigest",
    "linuxAmd64",
    "defaultCommandApproved",
    "bakedEnvironmentAllowlisted",
    "runtimePackageManagerAbsent",
    "serverSideReactRouterPackageAbsent",
    "reactServerRuntimeAbsent",
    "browserAssetsConfinedToStaticRoot",
}


class PolicyError(ValueError):
    """A fail-closed policy violation."""


def _strict_json_loads(source: str) -> Any:
    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise PolicyError(f"duplicate JSON key: {key}")
            value[key] = item
        return value

    try:
        return json.loads(source, object_pairs_hook=object_pairs)
    except json.JSONDecodeError as error:
        raise PolicyError(f"malformed JSON: {error}") from error


def _read_json(path: Path) -> Any:
    try:
        if path.is_symlink() or not path.is_file():
            raise PolicyError(f"JSON input is not a regular file: {path}")
        return _strict_json_loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise PolicyError(f"cannot read JSON input {path}: {error}") from error


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        raise PolicyError(f"cannot hash {path}: {error}") from error
    return digest.hexdigest()


def _require_exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        raise PolicyError(
            f"{label} keys differ: missing={sorted(expected - actual)}, "
            f"extra={sorted(actual - expected)}"
        )


def _safe_relative(value: str, label: str, *, dot_allowed: bool = False) -> str:
    if value == "." and dot_allowed:
        return value
    path = PurePosixPath(value)
    if (
        not value
        or path.is_absolute()
        or "\\" in value
        or "\x00" in value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise PolicyError(f"{label} is not a safe relative path: {value!r}")
    return path.as_posix()


def _safe_absolute(value: str, label: str) -> str:
    path = PurePosixPath(value)
    if (
        not value
        or not path.is_absolute()
        or "\\" in value
        or "\x00" in value
        or any(part in {"", ".", ".."} for part in path.parts[1:])
    ):
        raise PolicyError(f"{label} is not a canonical absolute path: {value!r}")
    return path.as_posix()


def _validate_profile(repository: str, profile: dict[str, Any]) -> None:
    required = {
        "status",
        "pendingReason",
        "repositoryIdentity",
        "exception",
        "contextSubdirectory",
        "dockerfile",
        "dockerignore",
        "packagingFiles",
        "submodules",
        "buildSecret",
        "baseImage",
        "platform",
        "imageConfig",
        "runtime",
        "deployment",
        "release",
    }
    _require_exact_keys(profile, required, f"profile {repository}")
    if profile["status"] not in {"approved", "pending-final-source-hashes"}:
        raise PolicyError(f"profile {repository} has an invalid status")
    if profile["status"] == "approved" and profile["pendingReason"] is not None:
        raise PolicyError(f"approved profile {repository} must clear pendingReason")
    if profile["status"] != "approved" and not isinstance(
        profile["pendingReason"], str
    ):
        raise PolicyError(f"pending profile {repository} needs a reason")
    identity = profile["repositoryIdentity"]
    _require_exact_keys(
        identity,
        {"repositoryId", "ownerId", "visibility"},
        f"{repository} repositoryIdentity",
    )
    if (
        not isinstance(identity["repositoryId"], str)
        or not identity["repositoryId"].isdigit()
        or int(identity["repositoryId"]) <= 0
        or not isinstance(identity["ownerId"], str)
        or not identity["ownerId"].isdigit()
        or int(identity["ownerId"]) <= 0
        or identity["visibility"] not in {"private", "internal", "public"}
    ):
        raise PolicyError(f"{repository} immutable repository identity is invalid")
    _safe_relative(
        profile["contextSubdirectory"],
        f"{repository} contextSubdirectory",
        dot_allowed=True,
    )
    _safe_relative(profile["dockerfile"], f"{repository} dockerfile")
    _safe_relative(profile["dockerignore"], f"{repository} dockerignore")
    packaging = profile["packagingFiles"]
    if not isinstance(packaging, dict) or not packaging:
        raise PolicyError(f"profile {repository} has no packaging file policy")
    for path, digest in packaging.items():
        _safe_relative(path, f"{repository} packaging file")
        if digest is None and profile["status"] != "approved":
            continue
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise PolicyError(f"{repository} packaging digest is invalid for {path}")
    if profile["dockerfile"] not in packaging:
        raise PolicyError(f"profile {repository} does not hash its Dockerfile")
    if profile["dockerignore"] not in packaging:
        raise PolicyError(f"profile {repository} does not hash its .dockerignore")

    exception = profile["exception"]
    _require_exact_keys(
        exception,
        {
            *APPLICABILITY_EXCEPTION,
            "packageManifestPath",
            "lockfilePath",
        },
        f"{repository} exception",
    )
    for key, expected in APPLICABILITY_EXCEPTION.items():
        if exception[key] != expected:
            raise PolicyError(f"{repository} applicability exception {key} differs")
    manifest_path = _safe_relative(
        exception["packageManifestPath"],
        f"{repository} exception package manifest",
    )
    lockfile_path = _safe_relative(
        exception["lockfilePath"],
        f"{repository} exception lockfile",
    )
    if (
        manifest_path not in packaging
        or lockfile_path not in packaging
        or (
            profile["status"] == "approved"
            and (packaging[manifest_path] is None or packaging[lockfile_path] is None)
        )
    ):
        raise PolicyError(
            f"{repository} exception manifest and lockfile must be digest-pinned"
        )

    submodules = profile["submodules"]
    if not isinstance(submodules, dict):
        raise PolicyError(f"profile {repository} submodules must be an object")
    for path, submodule in submodules.items():
        _safe_relative(path, f"{repository} submodule")
        _require_exact_keys(
            submodule,
            {
                "repository",
                "remote",
                "repositoryId",
                "ownerId",
                "visibility",
                "commitSha",
                "treeSha",
            },
            f"{repository} submodule {path}",
        )
        if not REPOSITORY_RE.fullmatch(submodule["repository"]):
            raise PolicyError(f"{repository} submodule repository is invalid")
        expected_remote = f"https://github.com/{submodule['repository']}.git"
        if submodule["remote"] != expected_remote:
            raise PolicyError(f"{repository} submodule remote is not canonical")
        if (
            not str(submodule["repositoryId"]).isdigit()
            or not str(submodule["ownerId"]).isdigit()
            or submodule["visibility"] not in {"private", "internal", "public"}
        ):
            raise PolicyError(f"{repository} submodule identity is invalid")
        if not SHA1_RE.fullmatch(submodule["commitSha"]) or not SHA1_RE.fullmatch(
            submodule["treeSha"]
        ):
            raise PolicyError(f"{repository} submodule commit or tree SHA is invalid")

    build_secret = profile["buildSecret"]
    if build_secret is not None:
        _require_exact_keys(
            build_secret,
            {
                "id",
                "target",
                "versionContractPath",
                "project",
                "premergeFixture",
                "variables",
                "versions",
            },
            f"{repository} buildSecret",
        )
        if not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", build_secret["id"]):
            raise PolicyError(f"{repository} build secret id is invalid")
        _safe_absolute(build_secret["target"], f"{repository} build secret target")
        _safe_relative(
            build_secret["versionContractPath"],
            f"{repository} version contract",
        )
        variables = build_secret["variables"]
        if not isinstance(variables, dict) or not variables:
            raise PolicyError(f"{repository} build secret variables are empty")
        for env_name, secret_name in variables.items():
            if not re.fullmatch(r"VITE_[A-Z0-9_]+", env_name):
                raise PolicyError(f"{repository} build environment name is invalid")
            if not re.fullmatch(r"[A-Z][A-Z0-9_]+", secret_name):
                raise PolicyError(f"{repository} secret name is invalid")
        versions = build_secret["versions"]
        if not isinstance(versions, dict) or set(versions) != set(variables):
            raise PolicyError(f"{repository} build secret numeric version set differs")
        if any(
            isinstance(version, bool) or not isinstance(version, int) or version <= 0
            for version in versions.values()
        ):
            raise PolicyError(
                f"{repository} build secret versions must be positive numeric"
            )
        contract_path = build_secret["versionContractPath"]
        if contract_path not in packaging:
            raise PolicyError(
                f"{repository} build secret version contract is not digest-pinned"
            )
        _validated_premerge_fixture(profile, repository=repository)

    if not re.fullmatch(r"[^@\s]+@sha256:[0-9a-f]{64}", profile["baseImage"]):
        raise PolicyError(f"{repository} base image is not digest-pinned")
    _require_exact_keys(profile["platform"], {"os", "architecture"}, "platform")
    if profile["platform"] != {"os": "linux", "architecture": "amd64"}:
        raise PolicyError(f"{repository} must use linux/amd64")
    _require_exact_keys(
        profile["imageConfig"],
        {
            "user",
            "workingDirectory",
            "entrypoint",
            "command",
            "environment",
            "exposedPorts",
            "stopSignal",
        },
        f"{repository} imageConfig",
    )
    image_config = profile["imageConfig"]
    if image_config["user"] != "nginx":
        raise PolicyError(f"{repository} final image must run as nginx")
    _safe_absolute(image_config["workingDirectory"], "workingDirectory")
    if not all(
        isinstance(item, str) and item
        for item in image_config["entrypoint"] + image_config["command"]
    ):
        raise PolicyError(f"{repository} entrypoint/command is invalid")
    env = image_config["environment"]
    if not isinstance(env, dict) or any(
        not isinstance(key, str) or not isinstance(item, str)
        for key, item in env.items()
    ):
        raise PolicyError(f"{repository} image environment is invalid")
    if sorted(image_config["exposedPorts"]) != image_config["exposedPorts"]:
        raise PolicyError(f"{repository} exposed ports must be sorted")

    runtime = profile["runtime"]
    _require_exact_keys(
        runtime,
        {
            "staticRoot",
            "indexPath",
            "nodeBinary",
            "nodeEntrypoints",
            "allowedPackageJsonPaths",
            "allowedRuntimeScriptRoots",
        },
        f"{repository} runtime",
    )
    for key in ("staticRoot", "indexPath"):
        _safe_absolute(runtime[key], f"{repository} {key}")
    if not runtime["indexPath"].startswith(runtime["staticRoot"] + "/"):
        raise PolicyError(f"{repository} indexPath is outside staticRoot")
    if runtime["nodeBinary"] is not None:
        _safe_absolute(runtime["nodeBinary"], f"{repository} nodeBinary")
    for key in (
        "nodeEntrypoints",
        "allowedPackageJsonPaths",
        "allowedRuntimeScriptRoots",
    ):
        if not isinstance(runtime[key], list) or len(runtime[key]) != len(
            set(runtime[key])
        ):
            raise PolicyError(f"{repository} {key} is invalid")
        for path in runtime[key]:
            _safe_absolute(path, f"{repository} {key}")

    deployment = profile["deployment"]
    _require_exact_keys(
        deployment,
        {
            "configuredEnvironmentAllowlist",
            "systemEnvironmentAllowlist",
            "forbiddenEnvironment",
        },
        f"{repository} deployment",
    )
    groups = []
    for key, values in deployment.items():
        if (
            not isinstance(values, list)
            or values != sorted(values)
            or len(values) != len(set(values))
            or not all(re.fullmatch(r"[A-Z][A-Z0-9_]*", item) for item in values)
        ):
            raise PolicyError(f"{repository} deployment {key} is invalid")
        groups.append(set(values))
    if groups[0] & groups[1] or (groups[0] | groups[1]) & groups[2]:
        raise PolicyError(f"{repository} deployment environment groups overlap")

    release = profile["release"]
    _require_exact_keys(
        release,
        {
            "registryRepository",
            "sourceRef",
            "events",
            "job",
            "workflowRef",
        },
        f"{repository} release",
    )
    if (
        not isinstance(release["registryRepository"], str)
        or ":" in release["registryRepository"]
        or "@" in release["registryRepository"]
        or not LOCAL_TAG_RE.fullmatch(release["registryRepository"] + ":validation")
        or release["sourceRef"] != "refs/heads/main"
        or not isinstance(release["events"], list)
        or release["events"] != sorted(set(release["events"]))
        or not release["events"]
        or not all(
            item in {"push", "workflow_dispatch", "workflow_run"}
            for item in release["events"]
        )
        or not re.fullmatch(r"[a-zA-Z0-9_-]+", release["job"])
        or release["workflowRef"]
        != f"{repository}/.github/workflows/cd.yml@refs/heads/main"
    ):
        raise PolicyError(f"{repository} release context policy is invalid")


def load_policy(path: Path = DEFAULT_POLICY) -> dict[str, Any]:
    policy = _read_json(path)
    if not isinstance(policy, dict):
        raise PolicyError("profile policy root must be an object")
    _require_exact_keys(policy, {"schemaVersion", "profiles"}, "profile policy")
    if policy["schemaVersion"] != SCHEMA_VERSION:
        raise PolicyError("unsupported profile policy schema")
    profiles = policy["profiles"]
    if not isinstance(profiles, dict) or not profiles:
        raise PolicyError("profile policy has no profiles")
    for repository, profile in profiles.items():
        if not REPOSITORY_RE.fullmatch(repository):
            raise PolicyError(f"invalid repository profile key: {repository}")
        if not isinstance(profile, dict):
            raise PolicyError(f"profile {repository} is not an object")
        _validate_profile(repository, profile)
    return policy


def profile_for(
    repository: str,
    policy: dict[str, Any],
    *,
    require_approved: bool = True,
) -> dict[str, Any]:
    profile = policy["profiles"].get(repository)
    if not isinstance(profile, dict):
        raise PolicyError(f"repository has no static UI profile: {repository}")
    if require_approved and profile["status"] != "approved":
        raise PolicyError(
            f"profile {repository} is not approved: {profile['pendingReason']}"
        )
    return profile


def profile_digest(repository: str, profile: dict[str, Any]) -> str:
    return _sha256_bytes(
        _canonical_bytes({"repository": repository, "profile": profile})
    )


def _run(
    argv: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    input_bytes: bytes | None = None,
    timeout: int = 900,
) -> bytes:
    try:
        result = subprocess.run(
            argv,
            cwd=cwd,
            env=env,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise PolicyError(f"command could not run: {argv[0]}: {error}") from error
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace")[-2000:]
        raise PolicyError(f"command failed ({result.returncode}): {argv[0]}: {detail}")
    return result.stdout


def _git(repository_root: Path, *arguments: str) -> str:
    return (
        _run(["git", "-C", str(repository_root), *arguments], timeout=120)
        .decode("utf-8", errors="strict")
        .strip()
    )


def _canonical_github_remote(remote: str) -> str | None:
    match = re.fullmatch(
        r"(?:https://github\.com/|git@github\.com:)"
        r"([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?/?",
        remote,
    )
    return match.group(1) if match else None


def _github_repository_identity(repository: str) -> dict[str, str]:
    response = _strict_json_loads(
        _run(["gh", "api", f"repos/{repository}"], timeout=120).decode("utf-8")
    )
    if not isinstance(response, dict) or not isinstance(response.get("owner"), dict):
        raise PolicyError(f"GitHub repository identity is malformed for {repository}")
    repository_id = response.get("id")
    owner_id = response["owner"].get("id")
    visibility = response.get("visibility")
    if (
        isinstance(repository_id, bool)
        or not isinstance(repository_id, int)
        or isinstance(owner_id, bool)
        or not isinstance(owner_id, int)
        or visibility not in {"private", "internal", "public"}
    ):
        raise PolicyError(f"GitHub repository identity is incomplete for {repository}")
    return {
        "repositoryId": str(repository_id),
        "ownerId": str(owner_id),
        "visibility": visibility,
    }


def _require_repository_identity(
    repository: str,
    expected: dict[str, str],
    lookup: Callable[[str], dict[str, str]],
) -> None:
    if lookup(repository) != expected:
        raise PolicyError(f"immutable GitHub identity differs for {repository}")


def _validate_git_source(
    repository_root: Path, repository: str, source_sha: str
) -> str:
    if not SHA1_RE.fullmatch(source_sha):
        raise PolicyError("source SHA must be a full lowercase SHA-1")
    if repository_root.is_symlink() or not repository_root.is_dir():
        raise PolicyError("source repository root is not a regular directory")
    if _git(repository_root, "cat-file", "-t", source_sha) != "commit":
        raise PolicyError("source SHA is not a commit")
    remote = _git(repository_root, "remote", "get-url", "origin")
    if _canonical_github_remote(remote) != repository:
        raise PolicyError("source repository origin is not the profiled repository")
    tree_sha = _git(repository_root, "rev-parse", f"{source_sha}^{{tree}}")
    if not SHA1_RE.fullmatch(tree_sha):
        raise PolicyError("source tree SHA is invalid")
    return tree_sha


def _safe_tar_name(name: str) -> str:
    stripped = name.removeprefix("./").rstrip("/")
    return _safe_relative(stripped, "archive member")


def _extract_git_archive(
    repository_root: Path, treeish: str, destination: Path
) -> None:
    process = subprocess.Popen(
        ["git", "-C", str(repository_root), "archive", "--format=tar", treeish],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdout is not None
    assert process.stderr is not None
    count = 0
    total = 0
    try:
        with tarfile.open(fileobj=process.stdout, mode="r|") as archive:
            for member in archive:
                relative = _safe_tar_name(member.name)
                target = destination / relative
                target.resolve().relative_to(destination.resolve())
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                if not member.isfile():
                    raise PolicyError(
                        f"archive contains a non-regular member: {relative}"
                    )
                count += 1
                total += member.size
                if count > STATIC_MAX_ENTRIES or total > STATIC_MAX_BYTES:
                    raise PolicyError("archive exceeds the bounded context policy")
                if target.exists() or target.is_symlink():
                    raise PolicyError(f"archive contains duplicate path: {relative}")
                target.parent.mkdir(parents=True, exist_ok=True)
                source = archive.extractfile(member)
                if source is None:
                    raise PolicyError(f"archive member cannot be read: {relative}")
                mode = 0o755 if member.mode & 0o111 else 0o644
                with target.open("xb") as stream:
                    shutil.copyfileobj(source, stream)
                target.chmod(mode)
    except (OSError, tarfile.TarError) as error:
        process.kill()
        raise PolicyError(f"git archive extraction failed: {error}") from error
    finally:
        process.stdout.close()
    stderr = process.stderr.read().decode("utf-8", errors="replace")
    process.stderr.close()
    return_code = process.wait(timeout=30)
    if return_code != 0:
        raise PolicyError(f"git archive failed ({return_code}): {stderr[-2000:]}")


def _directory_inventory(root: Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    count = 0
    total = 0
    for path in sorted(
        root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()
    ):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            raise PolicyError(f"context contains a symlink: {relative}")
        metadata = path.stat()
        if path.is_dir():
            continue
        if not path.is_file():
            raise PolicyError(f"context contains a special file: {relative}")
        count += 1
        total += metadata.st_size
        if count > STATIC_MAX_ENTRIES or total > STATIC_MAX_BYTES:
            raise PolicyError("context exceeds the bounded inventory policy")
        entries.append(
            {
                "path": relative,
                "mode": stat.S_IMODE(metadata.st_mode),
                "size": metadata.st_size,
                "sha256": _sha256_file(path),
            }
        )
    return entries


def _validate_packaging_files(
    context_root: Path, profile: dict[str, Any]
) -> dict[str, str]:
    observed: dict[str, str] = {}
    for relative, expected in profile["packagingFiles"].items():
        path = context_root / relative
        if path.is_symlink() or not path.is_file():
            raise PolicyError(f"required packaging file is absent: {relative}")
        actual = _sha256_file(path)
        observed[relative] = actual
        if expected != actual:
            raise PolicyError(
                f"packaging file digest mismatch for {relative}: {actual}"
            )
    dockerfile = context_root / profile["dockerfile"]
    try:
        docker_source = dockerfile.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise PolicyError(f"Dockerfile is unreadable: {error}") from error
    if PARSER_DIRECTIVE_RE.search(docker_source):
        raise PolicyError("Dockerfile parser directives are forbidden")
    if profile["baseImage"] not in docker_source:
        raise PolicyError("Dockerfile final base image is not the profiled digest")
    if re.search(r"^\s*(?:ADD|ONBUILD)\b", docker_source, re.MULTILINE | re.IGNORECASE):
        raise PolicyError("Dockerfile ADD and ONBUILD instructions are forbidden")
    build_secret = profile["buildSecret"]
    if build_secret is not None:
        mount = (
            f"--mount=type=secret,id={build_secret['id']},"
            f"target={build_secret['target']},required=true"
        )
        if mount not in docker_source:
            raise PolicyError("Dockerfile does not use the exact required secret mount")
        if re.search(r"^\s*COPY\b.*\.env", docker_source, re.MULTILINE | re.IGNORECASE):
            raise PolicyError("Dockerfile must not COPY a Vite environment file")
    return observed


def prepare_context(
    *,
    repository: str,
    repository_root: Path,
    source_sha: str,
    destination: Path,
    policy: dict[str, Any],
    beacon_repository_root: Path | None = None,
    identity_lookup: Callable[[str], dict[str, str]] = _github_repository_identity,
) -> dict[str, Any]:
    profile = profile_for(repository, policy)
    _require_repository_identity(
        repository, profile["repositoryIdentity"], identity_lookup
    )
    source_tree_sha = _validate_git_source(repository_root, repository, source_sha)
    repository_root = repository_root.resolve()
    destination = destination.resolve()
    try:
        destination.relative_to(repository_root)
    except ValueError:
        pass
    else:
        raise PolicyError(
            "trusted build context must be outside the candidate checkout"
        )
    if destination.exists():
        if destination.is_symlink() or any(destination.iterdir()):
            raise PolicyError(
                "trusted build context destination must be absent or empty"
            )
    else:
        destination.mkdir(mode=0o700, parents=True)

    subdirectory = profile["contextSubdirectory"]
    treeish = source_sha if subdirectory == "." else f"{source_sha}:{subdirectory}"
    _extract_git_archive(repository_root, treeish, destination)

    submodule_receipts = []
    for submodule_path, submodule_policy in profile["submodules"].items():
        listing = _git(
            repository_root,
            "ls-tree",
            source_sha,
            "--",
            submodule_path,
        )
        match = re.fullmatch(
            rf"160000 commit ([0-9a-f]{{40}})\t{re.escape(submodule_path)}",
            listing,
        )
        if not match:
            raise PolicyError(f"missing exact gitlink for {submodule_path}")
        gitlink_sha = match.group(1)
        if gitlink_sha != submodule_policy["commitSha"]:
            raise PolicyError(
                f"{submodule_path} gitlink differs from the profiled commit"
            )
        if beacon_repository_root is None:
            raise PolicyError(f"trusted checkout is required for {submodule_path}")
        beacon_root = beacon_repository_root.resolve()
        if _git(beacon_root, "rev-parse", "HEAD") != gitlink_sha:
            raise PolicyError(f"{submodule_path} checkout does not match the gitlink")
        if _git(beacon_root, "status", "--porcelain", "--untracked-files=all"):
            raise PolicyError(f"{submodule_path} checkout is dirty")
        remote = _git(beacon_root, "remote", "get-url", "origin")
        if _canonical_github_remote(remote) != submodule_policy["repository"]:
            raise PolicyError(f"{submodule_path} checkout has the wrong origin")
        _require_repository_identity(
            submodule_policy["repository"],
            {
                "repositoryId": str(submodule_policy["repositoryId"]),
                "ownerId": str(submodule_policy["ownerId"]),
                "visibility": submodule_policy["visibility"],
            },
            identity_lookup,
        )
        if _git(beacon_root, "cat-file", "-t", gitlink_sha) != "commit":
            raise PolicyError(f"{submodule_path} gitlink is not a commit")
        target = destination / submodule_path
        if target.exists() and (target.is_symlink() or any(target.iterdir())):
            raise PolicyError(f"context already contains {submodule_path}")
        target.mkdir(mode=0o700, parents=True, exist_ok=True)
        _extract_git_archive(beacon_root, gitlink_sha, target)
        sub_entries = _directory_inventory(target)
        submodule_tree_sha = _git(beacon_root, "rev-parse", f"{gitlink_sha}^{{tree}}")
        if submodule_tree_sha != submodule_policy["treeSha"]:
            raise PolicyError(f"{submodule_path} tree differs from the profiled tree")
        submodule_receipts.append(
            {
                "path": submodule_path,
                "repository": submodule_policy["repository"],
                "repositoryId": str(submodule_policy["repositoryId"]),
                "ownerId": str(submodule_policy["ownerId"]),
                "visibility": submodule_policy["visibility"],
                "commitSha": gitlink_sha,
                "treeSha": submodule_tree_sha,
                "contextDigest": f"sha256:{_sha256_bytes(_canonical_bytes(sub_entries))}",
                "fileCount": len(sub_entries),
            }
        )

    packaging = _validate_packaging_files(destination, profile)
    entries = _directory_inventory(destination)
    context_digest = _sha256_bytes(_canonical_bytes(entries))
    manifest = {
        "schemaVersion": SCHEMA_VERSION,
        "kind": "cognitum.static-ui.committed-context.v1",
        "repository": repository,
        "sourceSha": source_sha,
        "sourceTreeSha": source_tree_sha,
        "contextSubdirectory": subdirectory,
        "contextDigest": f"sha256:{context_digest}",
        "profileDigest": f"sha256:{profile_digest(repository, profile)}",
        "packagingFileDigests": packaging,
        "submodules": submodule_receipts,
        "fileCount": len(entries),
        "totalBytes": sum(entry["size"] for entry in entries),
        "files": entries,
    }
    return manifest


def _validated_premerge_fixture(
    profile: dict[str, Any], *, repository: str = "profile"
) -> tuple[dict[str, Any], bytes]:
    build_secret = profile.get("buildSecret")
    if not isinstance(build_secret, dict):
        raise PolicyError(f"{repository} profile has no build secret fixture")
    fixture = build_secret.get("premergeFixture")
    if not isinstance(fixture, dict):
        raise PolicyError(f"{repository} premerge fixture must be an object")
    _require_exact_keys(
        fixture,
        {
            "kind",
            "mode",
            "source",
            "classification",
            "variables",
            "contentDigest",
        },
        f"{repository} premerge fixture",
    )
    expected_labels = {
        "kind": PREMERGE_FIXTURE_KIND,
        "mode": "premerge",
        "source": PREMERGE_FIXTURE_SOURCE,
        "classification": PREMERGE_FIXTURE_CLASSIFICATION,
    }
    if {key: fixture.get(key) for key in expected_labels} != expected_labels:
        raise PolicyError(f"{repository} premerge fixture labels differ")
    variables = fixture["variables"]
    if not isinstance(variables, dict) or set(variables) != set(
        build_secret["variables"]
    ):
        raise PolicyError(f"{repository} premerge fixture variable set differs")
    lines: list[bytes] = []
    for environment_name in sorted(variables):
        raw_value = variables[environment_name]
        if not isinstance(raw_value, str):
            raise PolicyError(
                f"{repository} premerge fixture value is not text for "
                f"{environment_name}"
            )
        value = _validate_secret_value(
            environment_name,
            raw_value.encode("utf-8"),
            mode="premerge",
        )
        if not value.startswith("premerge-fixture-"):
            raise PolicyError(
                f"{repository} premerge fixture value is not visibly nonrelease "
                f"for {environment_name}"
            )
        lines.append(f"{environment_name}={value}\n".encode("utf-8"))
    content = b"".join(lines)
    expected_digest = f"sha256:{_sha256_bytes(content)}"
    if fixture["contentDigest"] != expected_digest:
        raise PolicyError(f"{repository} premerge fixture content digest differs")
    return fixture, content


def _version_contract_digest(profile: dict[str, Any]) -> str:
    build_secret = profile["buildSecret"]
    if build_secret is None:
        raise PolicyError("profile has no build secret version contract")
    digest = profile["packagingFiles"].get(build_secret["versionContractPath"])
    if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
        raise PolicyError("build secret version contract digest is absent")
    return f"sha256:{digest}"


def _premerge_fixture_evidence(profile: dict[str, Any]) -> dict[str, Any]:
    fixture, _ = _validated_premerge_fixture(profile)
    return {
        "schemaVersion": SCHEMA_VERSION,
        "kind": PREMERGE_FIXTURE_KIND,
        "mode": "premerge",
        "source": PREMERGE_FIXTURE_SOURCE,
        "classification": PREMERGE_FIXTURE_CLASSIFICATION,
        "id": profile["buildSecret"]["id"],
        "target": profile["buildSecret"]["target"],
        "versionContractDigest": _version_contract_digest(profile),
        "fixtureProfileDigest": (f"sha256:{_sha256_bytes(_canonical_bytes(fixture))}"),
        "variables": [
            {
                "environmentName": environment_name,
                "valueDigest": (
                    "sha256:"
                    + _sha256_bytes(fixture["variables"][environment_name].encode())
                ),
            }
            for environment_name in sorted(fixture["variables"])
        ],
        "contentDigest": fixture["contentDigest"],
    }


def _write_private_environment(output_path: Path, content: bytes) -> None:
    if not content or len(content) > MAX_BUILD_ENV_BYTES or not content.endswith(b"\n"):
        raise PolicyError("generated environment content is empty or oversized")
    if output_path.exists() or output_path.is_symlink():
        raise PolicyError("generated environment destination must not exist")
    output_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(
        output_path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
    except BaseException:
        with contextlib.suppress(OSError):
            output_path.unlink()
        raise
    if stat.S_IMODE(output_path.stat().st_mode) != 0o600:
        raise PolicyError("generated environment file mode is not 0600")


def _validated_version_contract(
    contract: dict[str, Any], profile: dict[str, Any]
) -> list[dict[str, Any]]:
    build_secret = profile["buildSecret"]
    if build_secret is None:
        raise PolicyError("profile has no build secret")
    if not isinstance(contract, dict):
        raise PolicyError("secret version contract must be an object")
    _require_exact_keys(
        contract, {"schemaVersion", "project", "variables"}, "secret version contract"
    )
    if contract["schemaVersion"] != SCHEMA_VERSION:
        raise PolicyError("secret version contract schema is unsupported")
    if contract["project"] != build_secret["project"]:
        raise PolicyError("secret version contract project is incorrect")
    variables = contract["variables"]
    if not isinstance(variables, dict) or set(variables) != set(
        build_secret["variables"]
    ):
        raise PolicyError("secret version contract variable set differs")
    records = []
    for env_name in sorted(variables):
        value = variables[env_name]
        if not isinstance(value, dict):
            raise PolicyError(f"secret version for {env_name} is not an object")
        _require_exact_keys(value, {"secret", "version"}, f"secret {env_name}")
        if value["secret"] != build_secret["variables"][env_name]:
            raise PolicyError(f"secret resource drift for {env_name}")
        version = value["version"]
        if isinstance(version, bool) or not isinstance(version, int) or version <= 0:
            raise PolicyError(f"secret version for {env_name} is not positive numeric")
        if version != build_secret["versions"][env_name]:
            raise PolicyError(f"secret numeric version drift for {env_name}")
        records.append(
            {
                "environmentName": env_name,
                "secret": value["secret"],
                "version": version,
            }
        )
    return records


def _validate_secret_value(name: str, value: bytes, *, mode: str = "release") -> str:
    if not value or len(value) > MAX_SECRET_VALUE:
        raise PolicyError(f"secret value for {name} is empty or oversized")
    try:
        text = value.decode("utf-8")
    except UnicodeError as error:
        raise PolicyError(f"secret value for {name} is not UTF-8") from error
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in text):
        raise PolicyError(f"secret value for {name} contains control characters")
    if mode == "premerge":
        if not PREMERGE_ENV_VALUE_RE.fullmatch(text):
            raise PolicyError(
                f"premerge fixture value for {name} is unsafe for a Vite env file"
            )
        return text
    if mode != "release":
        raise PolicyError("secret value validation mode is invalid")
    pattern = RELEASE_ENV_VALUE_RES.get(name)
    if pattern is None or not pattern.fullmatch(text):
        raise PolicyError(
            f"secret value for {name} is outside its canonical Vite env alphabet"
        )
    if name == "VITE_FIREBASE_AUTH_DOMAIN":
        labels = text.split(".")
        if len(labels) < 2 or any(
            not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
            for label in labels
        ):
            raise PolicyError(
                f"secret value for {name} is not a canonical DNS hostname"
            )
    return text


def materialize_management_environment(
    *,
    profile: dict[str, Any],
    contract: dict[str, Any],
    output_path: Path,
    access_secret: Callable[[str, int, str], bytes],
) -> dict[str, Any]:
    records = _validated_version_contract(contract, profile)
    lines: list[bytes] = []
    evidence = []
    for record in records:
        raw = access_secret(
            record["secret"],
            record["version"],
            profile["buildSecret"]["project"],
        )
        text = _validate_secret_value(record["environmentName"], raw)
        lines.append(f"{record['environmentName']}={text}\n".encode("utf-8"))
        evidence.append(
            {
                **record,
                "valueDigest": f"sha256:{_sha256_bytes(raw)}",
            }
        )
    _write_private_environment(output_path, b"".join(lines))
    return {
        "schemaVersion": SCHEMA_VERSION,
        "kind": RELEASE_SECRET_KIND,
        "mode": "release",
        "source": RELEASE_SECRET_SOURCE,
        "id": profile["buildSecret"]["id"],
        "target": profile["buildSecret"]["target"],
        "project": profile["buildSecret"]["project"],
        "versionContractDigest": _version_contract_digest(profile),
        "variables": evidence,
        "contentDigest": f"sha256:{_sha256_file(output_path)}",
    }


def materialize_premerge_fixture(
    *,
    profile: dict[str, Any],
    contract: dict[str, Any],
    output_path: Path,
) -> dict[str, Any]:
    _validated_version_contract(contract, profile)
    _, content = _validated_premerge_fixture(profile)
    _write_private_environment(output_path, content)
    evidence = _premerge_fixture_evidence(profile)
    if evidence["contentDigest"] != f"sha256:{_sha256_file(output_path)}":
        raise PolicyError("materialized premerge fixture digest differs")
    return evidence


def _validate_build_materialization_evidence(
    *,
    profile: dict[str, Any],
    mode: str,
    evidence: dict[str, Any] | None,
) -> dict[str, Any] | None:
    build_secret = profile["buildSecret"]
    if build_secret is None:
        if evidence is not None:
            raise PolicyError("unexpected build environment materialization evidence")
        return None
    if not isinstance(evidence, dict):
        raise PolicyError(
            "required build environment materialization evidence is absent"
        )
    if mode == "premerge":
        expected = _premerge_fixture_evidence(profile)
        if evidence != expected:
            raise PolicyError("premerge fixture evidence differs from the profile")
        return expected
    if mode != "release":
        raise PolicyError("build environment materialization mode is invalid")
    expected_keys = {
        "schemaVersion",
        "kind",
        "mode",
        "source",
        "id",
        "target",
        "project",
        "versionContractDigest",
        "variables",
        "contentDigest",
    }
    _require_exact_keys(evidence, expected_keys, "release secret-manager evidence")
    expected_header = {
        "schemaVersion": SCHEMA_VERSION,
        "kind": RELEASE_SECRET_KIND,
        "mode": "release",
        "source": RELEASE_SECRET_SOURCE,
        "id": build_secret["id"],
        "target": build_secret["target"],
        "project": build_secret["project"],
        "versionContractDigest": _version_contract_digest(profile),
    }
    if {key: evidence.get(key) for key in expected_header} != expected_header:
        raise PolicyError("release secret-manager evidence labels differ")
    if not isinstance(evidence["contentDigest"], str) or not IMAGE_DIGEST_RE.fullmatch(
        evidence["contentDigest"]
    ):
        raise PolicyError("release secret-manager content digest is invalid")
    variables = evidence["variables"]
    if not isinstance(variables, list) or len(variables) != len(
        build_secret["variables"]
    ):
        raise PolicyError("release secret-manager variable evidence differs")
    expected_records = [
        {
            "environmentName": environment_name,
            "secret": build_secret["variables"][environment_name],
            "version": build_secret["versions"][environment_name],
        }
        for environment_name in sorted(build_secret["variables"])
    ]
    for actual, expected in zip(variables, expected_records, strict=True):
        if not isinstance(actual, dict):
            raise PolicyError("release secret-manager variable evidence is malformed")
        _require_exact_keys(
            actual,
            {"environmentName", "secret", "version", "valueDigest"},
            "release secret-manager variable evidence",
        )
        if {key: actual.get(key) for key in expected} != expected:
            raise PolicyError("release secret-manager numeric contract differs")
        if not isinstance(actual["valueDigest"], str) or not IMAGE_DIGEST_RE.fullmatch(
            actual["valueDigest"]
        ):
            raise PolicyError("release secret-manager value digest is invalid")
    return evidence


def _gcloud_secret_accessor(secret: str, version: int, project: str) -> bytes:
    return _run(
        [
            "gcloud",
            "secrets",
            "versions",
            "access",
            str(version),
            f"--secret={secret}",
            f"--project={project}",
        ],
        timeout=120,
    )


def _runtime_tar_path(name: str) -> str:
    relative = _safe_tar_name(name)
    return "/" + relative


def inventory_rootfs(
    stream: io.BufferedIOBase,
    profile: dict[str, Any],
) -> dict[str, Any]:
    entries = []
    seen = set()
    policy_contents: dict[str, bytes] = {}
    total = 0
    policy_total = 0
    member_count = 0
    try:
        with tarfile.open(fileobj=stream, mode="r|*") as archive:
            for member in archive:
                member_count += 1
                if member_count > STATIC_MAX_ENTRIES:
                    raise PolicyError("rootfs inventory exceeds the entry bound")
                path = _runtime_tar_path(member.name)
                if path in seen:
                    raise PolicyError(f"rootfs contains duplicate path: {path}")
                seen.add(path)
                kind: str
                digest: str | None = None
                link_target: str | None = None
                if member.isdir():
                    kind = "directory"
                elif member.isfile():
                    kind = "file"
                    total += member.size
                    if total > STATIC_MAX_BYTES:
                        raise PolicyError("rootfs inventory exceeds policy bounds")
                    source = archive.extractfile(member)
                    if source is None:
                        raise PolicyError(f"rootfs file cannot be read: {path}")
                    hasher = hashlib.sha256()
                    captured = bytearray()
                    capture = PurePosixPath(
                        path
                    ).name == "package.json" or _is_runtime_policy_text(path, profile)
                    for chunk in iter(lambda: source.read(1024 * 1024), b""):
                        hasher.update(chunk)
                        if capture:
                            if len(captured) + len(chunk) > MAX_POLICY_TEXT:
                                raise PolicyError(
                                    f"runtime policy text is oversized: {path}"
                                )
                            captured.extend(chunk)
                    digest = hasher.hexdigest()
                    if capture:
                        captured_bytes = bytes(captured)
                        policy_total += len(captured_bytes)
                        if policy_total > MAX_POLICY_CAPTURE_BYTES:
                            raise PolicyError(
                                "rootfs policy inputs exceed the capture bound"
                            )
                        policy_contents[path] = captured_bytes
                elif member.issym():
                    kind = "symlink"
                    link_target = member.linkname
                elif member.islnk():
                    kind = "hardlink"
                    link_target = member.linkname
                else:
                    raise PolicyError(f"rootfs contains a special file: {path}")
                entry = {
                    "path": path,
                    "type": kind,
                    "mode": member.mode & 0o7777,
                    "uid": member.uid,
                    "gid": member.gid,
                    "size": member.size if kind == "file" else 0,
                }
                if digest is not None:
                    entry["sha256"] = digest
                if link_target is not None:
                    entry["linkTarget"] = link_target
                entries.append(entry)
    except (OSError, tarfile.TarError) as error:
        raise PolicyError(f"rootfs archive is malformed: {error}") from error
    entries.sort(key=lambda item: item["path"])
    evidence, findings = _evaluate_runtime_entries(entries, policy_contents, profile)
    policy_inputs = [
        {
            "path": path,
            "contentBase64": base64.b64encode(content).decode("ascii"),
        }
        for path, content in sorted(policy_contents.items())
    ]
    inventory_digest = _sha256_bytes(
        _canonical_bytes({"entries": entries, "policyInputs": policy_inputs})
    )
    return {
        "schemaVersion": SCHEMA_VERSION,
        "kind": "cognitum.static-ui.rootfs-inventory.v1",
        "inventoryDigest": f"sha256:{inventory_digest}",
        "entryCount": len(entries),
        "regularFileCount": sum(entry["type"] == "file" for entry in entries),
        "totalRegularFileBytes": sum(
            entry["size"] for entry in entries if entry["type"] == "file"
        ),
        "entries": entries,
        "policyInputs": policy_inputs,
        "policyEvidence": evidence,
        "findings": findings,
    }


def _validate_inventory_document(
    inventory: dict[str, Any], profile: dict[str, Any]
) -> str:
    if not isinstance(inventory, dict):
        raise PolicyError("rootfs inventory must be an object")
    _require_exact_keys(
        inventory,
        {
            "schemaVersion",
            "kind",
            "inventoryDigest",
            "entryCount",
            "regularFileCount",
            "totalRegularFileBytes",
            "entries",
            "policyInputs",
            "policyEvidence",
            "findings",
        },
        "rootfs inventory",
    )
    if (
        inventory["schemaVersion"] != SCHEMA_VERSION
        or inventory["kind"] != "cognitum.static-ui.rootfs-inventory.v1"
    ):
        raise PolicyError("rootfs inventory schema is unsupported")
    entries = inventory["entries"]
    if not isinstance(entries, list) or len(entries) > STATIC_MAX_ENTRIES:
        raise PolicyError("rootfs inventory entries are malformed")
    previous = None
    regular_files = 0
    regular_bytes = 0
    for entry in entries:
        if not isinstance(entry, dict):
            raise PolicyError("rootfs inventory entry is not an object")
        kind = entry.get("type")
        expected_keys = {"path", "type", "mode", "uid", "gid", "size"}
        if kind == "file":
            expected_keys.add("sha256")
        elif kind in {"symlink", "hardlink"}:
            expected_keys.add("linkTarget")
        elif kind != "directory":
            raise PolicyError("rootfs inventory entry type is invalid")
        _require_exact_keys(entry, expected_keys, "rootfs inventory entry")
        path = entry["path"]
        if (
            not isinstance(path, str)
            or _safe_absolute(path, "rootfs inventory path") != path
        ):
            raise PolicyError("rootfs inventory path is invalid")
        if previous is not None and path <= previous:
            raise PolicyError("rootfs inventory paths are not unique and sorted")
        previous = path
        for key in ("mode", "uid", "gid", "size"):
            value = entry[key]
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise PolicyError(f"rootfs inventory entry {key} is invalid: {path}")
        if entry["mode"] > 0o7777:
            raise PolicyError(f"rootfs inventory entry mode is invalid: {path}")
        if kind == "file":
            if not SHA256_RE.fullmatch(entry["sha256"]):
                raise PolicyError(f"rootfs inventory file digest is invalid: {path}")
            regular_files += 1
            regular_bytes += entry["size"]
            if regular_bytes > STATIC_MAX_BYTES:
                raise PolicyError("rootfs inventory exceeds the byte bound")
        elif entry["size"] != 0:
            raise PolicyError(f"rootfs inventory non-file size is nonzero: {path}")
        if kind in {"symlink", "hardlink"} and not isinstance(entry["linkTarget"], str):
            raise PolicyError(f"rootfs inventory link target is invalid: {path}")
    policy_inputs = inventory["policyInputs"]
    if not isinstance(policy_inputs, list):
        raise PolicyError("rootfs inventory policy inputs are malformed")
    policy_contents: dict[str, bytes] = {}
    policy_bytes = 0
    for record in policy_inputs:
        if not isinstance(record, dict):
            raise PolicyError("rootfs inventory policy input is malformed")
        _require_exact_keys(
            record, {"path", "contentBase64"}, "rootfs inventory policy input"
        )
        path = record["path"]
        encoded = record["contentBase64"]
        if (
            not isinstance(path, str)
            or path in policy_contents
            or not isinstance(encoded, str)
        ):
            raise PolicyError("rootfs inventory policy input is malformed")
        try:
            content = base64.b64decode(encoded, validate=True)
        except (ValueError, base64.binascii.Error) as error:
            raise PolicyError(
                f"rootfs inventory policy input is not canonical base64: {path}"
            ) from error
        if base64.b64encode(content).decode("ascii") != encoded:
            raise PolicyError(
                f"rootfs inventory policy input is not canonical base64: {path}"
            )
        policy_bytes += len(content)
        if len(content) > MAX_POLICY_TEXT or policy_bytes > MAX_POLICY_CAPTURE_BYTES:
            raise PolicyError("rootfs inventory policy inputs exceed bounds")
        policy_contents[path] = content
    expected_policy_paths = {
        entry["path"]
        for entry in entries
        if entry["type"] == "file"
        and (
            PurePosixPath(entry["path"]).name == "package.json"
            or _is_runtime_policy_text(entry["path"], profile)
        )
    }
    if set(policy_contents) != expected_policy_paths:
        raise PolicyError("rootfs inventory policy input path set differs")
    file_entries = {
        entry["path"]: entry for entry in entries if entry["type"] == "file"
    }
    for path, content in policy_contents.items():
        if file_entries[path]["sha256"] != _sha256_bytes(content):
            raise PolicyError(f"rootfs inventory policy input digest differs: {path}")
    calculated_digest = "sha256:" + _sha256_bytes(
        _canonical_bytes({"entries": entries, "policyInputs": policy_inputs})
    )
    if inventory["inventoryDigest"] != calculated_digest:
        raise PolicyError("rootfs inventory content digest is invalid")
    if (
        inventory["entryCount"] != len(entries)
        or inventory["regularFileCount"] != regular_files
        or inventory["totalRegularFileBytes"] != regular_bytes
    ):
        raise PolicyError("rootfs inventory summary differs from its entries")
    findings = inventory["findings"]
    if (
        not isinstance(findings, list)
        or findings != sorted(set(findings))
        or not all(isinstance(item, str) and item for item in findings)
    ):
        raise PolicyError("rootfs inventory findings are malformed")
    evidence = inventory["policyEvidence"]
    _require_exact_keys(
        evidence,
        {
            "staticRoot",
            "staticEntryCount",
            "staticDigest",
            "packageManifests",
            "runtimePolicyText",
            "nodeBinary",
            "nodeEntrypoints",
        },
        "rootfs inventory policy evidence",
    )
    static_entries = [
        entry
        for entry in entries
        if _path_is_within(entry["path"], profile["runtime"]["staticRoot"])
    ]
    if (
        evidence["staticRoot"] != profile["runtime"]["staticRoot"]
        or evidence["staticEntryCount"] != len(static_entries)
        or evidence["staticDigest"]
        != f"sha256:{_sha256_bytes(_canonical_bytes(static_entries))}"
        or evidence["nodeBinary"] != profile["runtime"]["nodeBinary"]
        or evidence["nodeEntrypoints"] != profile["runtime"]["nodeEntrypoints"]
        or not isinstance(evidence["packageManifests"], list)
        or not isinstance(evidence["runtimePolicyText"], list)
    ):
        raise PolicyError("rootfs inventory policy evidence differs")
    entry_digests = {
        entry["path"]: entry.get("sha256")
        for entry in entries
        if entry["type"] == "file"
    }
    for group in ("packageManifests", "runtimePolicyText"):
        seen_paths: set[str] = set()
        for record in evidence[group]:
            if not isinstance(record, dict):
                raise PolicyError(f"rootfs inventory {group} evidence is malformed")
            path = record.get("path")
            digest = record.get("sha256")
            if (
                not isinstance(path, str)
                or path in seen_paths
                or entry_digests.get(path) != digest
            ):
                raise PolicyError(f"rootfs inventory {group} digest differs")
            seen_paths.add(path)
    calculated_evidence, calculated_findings = _evaluate_runtime_entries(
        entries, policy_contents, profile
    )
    if (
        inventory["policyEvidence"] != calculated_evidence
        or inventory["findings"] != calculated_findings
    ):
        raise PolicyError("rootfs inventory semantic evidence or findings differ")
    return calculated_digest


def _path_is_within(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip("/") + "/")


def _resolved_runtime_link(path: str, target: str) -> str | None:
    if not target or "\x00" in target or "\\" in target:
        return None
    candidate = (
        target
        if target.startswith("/")
        else posixpath.join(posixpath.dirname(path), target)
    )
    resolved = posixpath.normpath(candidate)
    if not resolved.startswith("/") or resolved == "/..":
        return None
    return resolved


def _is_runtime_policy_text(path: str, profile: dict[str, Any]) -> bool:
    static_root = profile["runtime"]["staticRoot"]
    if _path_is_within(path, static_root):
        return False
    suffix = PurePosixPath(path).suffix.lower()
    if suffix not in {".cjs", ".js", ".mjs", ".sh"} and path not in {
        item
        for item in profile["runtime"]["allowedRuntimeScriptRoots"]
        if "." not in PurePosixPath(item).name
    }:
        return False
    return any(
        _path_is_within(path, root)
        for root in profile["runtime"]["allowedRuntimeScriptRoots"]
    )


def _evaluate_runtime_entries(
    entries: list[dict[str, Any]],
    policy_contents: dict[str, bytes],
    profile: dict[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    findings = []
    by_path = {entry["path"]: entry for entry in entries}
    static_root = profile["runtime"]["staticRoot"]
    index_path = profile["runtime"]["indexPath"]
    static_entries = [
        entry for entry in entries if _path_is_within(entry["path"], static_root)
    ]
    if by_path.get(static_root, {}).get("type") != "directory":
        findings.append("static root is absent or not a directory")
    if by_path.get(index_path, {}).get("type") != "file":
        findings.append("static index is absent or not a regular file")
    for entry in static_entries:
        if entry["type"] in {"symlink", "hardlink"}:
            findings.append(f"static root contains a link: {entry['path']}")
        if entry["type"] == "file" and entry["mode"] & 0o111:
            findings.append(f"static root contains an executable: {entry['path']}")

    protected_runtime_paths = {
        static_root,
        index_path,
        *profile["runtime"]["nodeEntrypoints"],
        *profile["runtime"]["allowedPackageJsonPaths"],
        *profile["runtime"]["allowedRuntimeScriptRoots"],
    }
    if profile["runtime"]["nodeBinary"] is not None:
        protected_runtime_paths.add(profile["runtime"]["nodeBinary"])
    for entry in entries:
        if entry["type"] not in {"symlink", "hardlink"}:
            continue
        resolved_target = _resolved_runtime_link(entry["path"], entry["linkTarget"])
        if resolved_target is None:
            findings.append(f"runtime link target is non-canonical: {entry['path']}")
            continue
        if any(
            _path_is_within(entry["path"], protected)
            or _path_is_within(resolved_target, protected)
            for protected in protected_runtime_paths
        ):
            findings.append(
                f"runtime protected path contains or receives a link: "
                f"{entry['path']} -> {resolved_target}"
            )

    package_json_paths = sorted(
        entry["path"]
        for entry in entries
        if PurePosixPath(entry["path"]).name == "package.json"
    )
    expected_packages = sorted(profile["runtime"]["allowedPackageJsonPaths"])
    if package_json_paths != expected_packages:
        findings.append(f"runtime package.json paths differ: {package_json_paths}")
    package_evidence = []
    for path in package_json_paths:
        raw = policy_contents.get(path)
        if raw is None:
            findings.append(f"runtime package manifest was not captured: {path}")
            continue
        try:
            manifest = _strict_json_loads(raw.decode("utf-8"))
        except (PolicyError, UnicodeError) as error:
            findings.append(f"runtime package manifest is invalid: {path}: {error}")
            continue
        if not isinstance(manifest, dict):
            findings.append(f"runtime package manifest is not an object: {path}")
            continue
        dependency_groups = (
            "dependencies",
            "devDependencies",
            "optionalDependencies",
            "peerDependencies",
            "bundledDependencies",
        )
        dependency_names = sorted(
            {
                name
                for group in dependency_groups
                for name in (
                    manifest.get(group, {}).keys()
                    if isinstance(manifest.get(group, {}), dict)
                    else ()
                )
            }
        )
        if dependency_names:
            findings.append(f"runtime package manifest declares dependencies: {path}")
        package_evidence.append(
            {
                "path": path,
                "sha256": _sha256_bytes(raw),
                "name": manifest.get("name"),
                "dependencyNames": dependency_names,
            }
        )

    for entry in entries:
        path = entry["path"]
        lowered_parts = {part.lower() for part in PurePosixPath(path).parts}
        if lowered_parts & FORBIDDEN_RUNTIME_COMPONENTS:
            findings.append(f"forbidden runtime package path: {path}")
        basename = PurePosixPath(path).name.lower()
        if basename in FORBIDDEN_PACKAGE_FILES:
            findings.append(f"runtime lockfile is forbidden: {path}")
        if basename in FORBIDDEN_PACKAGE_MANAGERS and entry["type"] != "directory":
            findings.append(f"runtime package manager is forbidden: {path}")

    node_binary = profile["runtime"]["nodeBinary"]
    if node_binary is None:
        if "/usr/local/bin/node" in by_path:
            findings.append("unapproved Node runtime is present")
    elif by_path.get(node_binary, {}).get("type") != "file":
        findings.append("approved Node runtime is absent")
    for entrypoint in profile["runtime"]["nodeEntrypoints"]:
        if by_path.get(entrypoint, {}).get("type") != "file":
            findings.append(f"Node entrypoint is absent: {entrypoint}")

    runtime_text_evidence = []
    for path, raw in sorted(policy_contents.items()):
        if PurePosixPath(path).name == "package.json":
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeError:
            findings.append(f"runtime policy text is not UTF-8: {path}")
            continue
        if RUNTIME_RSC_RE.search(text):
            findings.append(f"runtime RSC surface found: {path}")
        if DYNAMIC_CODE_RE.search(text):
            findings.append(f"runtime dynamic code loading found: {path}")
        runtime_text_evidence.append({"path": path, "sha256": _sha256_bytes(raw)})

    evidence = {
        "staticRoot": static_root,
        "staticEntryCount": len(static_entries),
        "staticDigest": f"sha256:{_sha256_bytes(_canonical_bytes(static_entries))}",
        "packageManifests": package_evidence,
        "runtimePolicyText": runtime_text_evidence,
        "nodeBinary": node_binary,
        "nodeEntrypoints": profile["runtime"]["nodeEntrypoints"],
    }
    return evidence, sorted(set(findings))


def _normalise_image_environment(values: Any) -> dict[str, str]:
    if not isinstance(values, list):
        raise PolicyError("image Config.Env is not an array")
    environment: dict[str, str] = {}
    for value in values:
        if not isinstance(value, str) or "=" not in value:
            raise PolicyError("image Config.Env contains a malformed item")
        name, item = value.split("=", 1)
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", name) or name in environment:
            raise PolicyError("image Config.Env has a duplicate or invalid name")
        environment[name] = item
    return environment


def validate_image_inspect(
    inspect_value: Any,
    profile: dict[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    if (
        not isinstance(inspect_value, list)
        or len(inspect_value) != 1
        or not isinstance(inspect_value[0], dict)
    ):
        raise PolicyError("docker image inspect must contain exactly one image")
    image = inspect_value[0]
    image_id = image.get("Id")
    if not isinstance(image_id, str) or not IMAGE_ID_RE.fullmatch(image_id):
        raise PolicyError("docker image ID is not immutable")
    findings = []
    platform = profile["platform"]
    if (
        image.get("Os") != platform["os"]
        or image.get("Architecture") != platform["architecture"]
    ):
        findings.append("image platform differs from the profile")
    config = image.get("Config")
    if not isinstance(config, dict):
        raise PolicyError("docker image Config is absent")
    actual_environment = _normalise_image_environment(config.get("Env"))
    expected = profile["imageConfig"]
    comparisons = {
        "user": (config.get("User") or "", expected["user"]),
        "workingDirectory": (
            config.get("WorkingDir") or "/",
            expected["workingDirectory"],
        ),
        "entrypoint": (config.get("Entrypoint") or [], expected["entrypoint"]),
        "command": (config.get("Cmd") or [], expected["command"]),
        "environment": (actual_environment, expected["environment"]),
        "exposedPorts": (
            sorted((config.get("ExposedPorts") or {}).keys()),
            expected["exposedPorts"],
        ),
        "stopSignal": (config.get("StopSignal"), expected["stopSignal"]),
        "volumes": (config.get("Volumes") or {}, {}),
        "healthcheck": (config.get("Healthcheck") or {}, {}),
        "onBuild": (config.get("OnBuild") or [], []),
        "shell": (config.get("Shell") or [], []),
    }
    for label, (actual, wanted) in comparisons.items():
        if actual != wanted:
            findings.append(f"image config {label} differs from the profile")
    rootfs = image.get("RootFS")
    if (
        not isinstance(rootfs, dict)
        or rootfs.get("Type") != "layers"
        or not isinstance(rootfs.get("Layers"), list)
        or not rootfs["Layers"]
        or not all(IMAGE_ID_RE.fullmatch(item or "") for item in rootfs["Layers"])
    ):
        findings.append("image RootFS layer identities are invalid")
    evidence = {
        "imageId": image_id,
        "os": image.get("Os"),
        "architecture": image.get("Architecture"),
        "user": config.get("User") or "",
        "workingDirectory": config.get("WorkingDir") or "/",
        "entrypoint": config.get("Entrypoint") or [],
        "command": config.get("Cmd") or [],
        "environment": actual_environment,
        "exposedPorts": sorted((config.get("ExposedPorts") or {}).keys()),
        "volumes": config.get("Volumes") or {},
        "healthcheck": config.get("Healthcheck") or {},
        "onBuild": config.get("OnBuild") or [],
        "shell": config.get("Shell") or [],
        "stopSignal": config.get("StopSignal"),
        "rootfsLayers": rootfs.get("Layers") if isinstance(rootfs, dict) else [],
    }
    return evidence, findings


def _required_github_context(environment: dict[str, str]) -> dict[str, Any]:
    required = [
        "GITHUB_REPOSITORY",
        "GITHUB_REPOSITORY_ID",
        "GITHUB_REPOSITORY_OWNER_ID",
        "GITHUB_REPOSITORY_VISIBILITY",
        "GITHUB_SHA",
        "GITHUB_REF",
        "GITHUB_WORKFLOW_REF",
        "GITHUB_WORKFLOW_SHA",
        "GITHUB_RUN_ID",
        "GITHUB_RUN_ATTEMPT",
        "GITHUB_JOB",
        "GITHUB_EVENT_NAME",
    ]
    missing = [name for name in required if not environment.get(name)]
    if missing:
        raise PolicyError(f"trusted GitHub context is incomplete: {missing}")
    if not SHA1_RE.fullmatch(environment["GITHUB_SHA"]):
        raise PolicyError("GITHUB_SHA is not a full lowercase SHA")
    if not SHA1_RE.fullmatch(environment["GITHUB_WORKFLOW_SHA"]):
        raise PolicyError("GITHUB_WORKFLOW_SHA is not a full lowercase SHA")
    for name in (
        "GITHUB_REPOSITORY_ID",
        "GITHUB_REPOSITORY_OWNER_ID",
        "GITHUB_RUN_ID",
        "GITHUB_RUN_ATTEMPT",
    ):
        if not environment[name].isdigit() or int(environment[name]) <= 0:
            raise PolicyError(f"{name} is not a positive numeric identifier")
    if environment["GITHUB_REPOSITORY_VISIBILITY"] not in {
        "private",
        "internal",
        "public",
    }:
        raise PolicyError("GITHUB_REPOSITORY_VISIBILITY is invalid")
    return {
        "repository": environment["GITHUB_REPOSITORY"],
        "repositoryId": environment["GITHUB_REPOSITORY_ID"],
        "repositoryOwnerId": environment["GITHUB_REPOSITORY_OWNER_ID"],
        "repositoryVisibility": environment["GITHUB_REPOSITORY_VISIBILITY"],
        "sourceSha": environment["GITHUB_SHA"],
        "sourceRef": environment["GITHUB_REF"],
        "callerWorkflowRef": environment["GITHUB_WORKFLOW_REF"],
        "callerWorkflowSha": environment["GITHUB_WORKFLOW_SHA"],
        "runId": environment["GITHUB_RUN_ID"],
        "runAttempt": environment["GITHUB_RUN_ATTEMPT"],
        "job": environment["GITHUB_JOB"],
        "event": environment["GITHUB_EVENT_NAME"],
    }


def _validate_release_invocation(
    *,
    profile: dict[str, Any],
    github_context: dict[str, Any],
    image_name: str,
    source_sha: str,
) -> None:
    release = profile["release"]
    expected = {
        "imageName": release["registryRepository"],
        "sourceSha": source_sha,
        "sourceRef": release["sourceRef"],
        "event": release["events"],
        "job": release["job"],
        "workflowRef": release["workflowRef"],
        "workflowSha": source_sha,
    }
    actual = {
        "imageName": image_name,
        "sourceSha": github_context.get("sourceSha"),
        "sourceRef": github_context.get("sourceRef"),
        "event": github_context.get("event"),
        "job": github_context.get("job"),
        "workflowRef": github_context.get("callerWorkflowRef"),
        "workflowSha": github_context.get("callerWorkflowSha"),
    }
    if (
        actual["imageName"] != expected["imageName"]
        or actual["sourceSha"] != expected["sourceSha"]
        or actual["sourceRef"] != expected["sourceRef"]
        or actual["event"] not in expected["event"]
        or actual["job"] != expected["job"]
        or actual["workflowRef"] != expected["workflowRef"]
        or actual["workflowSha"] != expected["workflowSha"]
    ):
        raise PolicyError("release invocation differs from the approved context")


def _require_current_origin_main(
    repository_root: Path, repository: str, source_sha: str
) -> None:
    origin_main = _git(
        repository_root, "rev-parse", "--verify", "refs/remotes/origin/main"
    )
    if origin_main != source_sha:
        raise PolicyError("release source is not the exact local origin/main")
    _git(
        repository_root,
        "merge-base",
        "--is-ancestor",
        source_sha,
        "refs/remotes/origin/main",
    )
    remote_main = (
        _run(
            [
                "gh",
                "api",
                f"repos/{repository}/git/ref/heads/main",
                "--jq",
                ".object.sha",
            ],
            timeout=120,
        )
        .decode("ascii", errors="strict")
        .strip()
    )
    if remote_main != source_sha:
        raise PolicyError("release source is not the current GitHub main")


def _validate_build_metadata(metadata: dict[str, Any], image_id: str) -> dict[str, Any]:
    if not isinstance(metadata, dict):
        raise PolicyError("Buildx metadata must be an object")
    config_digest = metadata.get("containerimage.config.digest")
    provenance = metadata.get("buildx.build.provenance")
    if config_digest != image_id:
        raise PolicyError("Buildx config digest does not equal docker image ID")
    if not isinstance(provenance, dict) or not provenance:
        raise PolicyError("Buildx max provenance metadata is absent")
    return {
        "metadataDigest": f"sha256:{_sha256_bytes(_canonical_bytes(metadata))}",
        "configDigest": config_digest,
        "manifestDigest": metadata.get("containerimage.digest"),
        "buildReference": metadata.get("buildx.build.ref"),
    }


def _profile_file_digest(policy_path: Path) -> str:
    return f"sha256:{_sha256_file(policy_path)}"


def _applicability_exception_evidence(
    profile: dict[str, Any],
) -> dict[str, Any]:
    exception = profile["exception"]
    manifest_path = exception["packageManifestPath"]
    lockfile_path = exception["lockfilePath"]
    packaging = profile["packagingFiles"]
    manifest_digest = packaging[manifest_path]
    lockfile_digest = packaging[lockfile_path]
    if not isinstance(manifest_digest, str) or not isinstance(lockfile_digest, str):
        raise PolicyError(
            "approved applicability exception inputs must have exact digests"
        )
    return {
        **exception,
        "packageManifestDigest": f"sha256:{manifest_digest}",
        "lockfileDigest": f"sha256:{lockfile_digest}",
    }


def build_receipt(
    *,
    repository: str,
    policy: dict[str, Any],
    policy_path: Path,
    context_manifest: dict[str, Any],
    image_inspect: Any,
    inventory: dict[str, Any],
    build_metadata: dict[str, Any],
    mode: str,
    image_name: str,
    registry_digest: str | None,
    github_context: dict[str, Any],
    receipt_nonce: str,
    build_invocation: dict[str, Any],
    build_secret_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    profile = profile_for(repository, policy)
    if github_context["repository"] != repository:
        raise PolicyError("GitHub repository differs from the profile")
    expected_identity = profile["repositoryIdentity"]
    actual_identity = {
        "repositoryId": github_context["repositoryId"],
        "ownerId": github_context["repositoryOwnerId"],
        "visibility": github_context["repositoryVisibility"],
    }
    if actual_identity != expected_identity:
        raise PolicyError("GitHub numeric repository identity differs from the profile")
    if github_context["sourceSha"] != context_manifest.get("sourceSha"):
        raise PolicyError("GitHub source SHA differs from the committed context")
    if context_manifest.get("repository") != repository:
        raise PolicyError("committed context repository differs")
    expected_profile_digest = f"sha256:{profile_digest(repository, profile)}"
    if context_manifest.get("profileDigest") != expected_profile_digest:
        raise PolicyError("committed context uses a different profile")
    if mode not in {"premerge", "release"}:
        raise PolicyError("receipt mode must be premerge or release")
    if not re.fullmatch(r"[0-9a-f]{64}", receipt_nonce):
        raise PolicyError("receipt nonce is not a 256-bit lowercase value")
    if not image_name or "@" in image_name or image_name.endswith(":latest"):
        raise PolicyError("image subject name is invalid")
    if mode == "release":
        _validate_release_invocation(
            profile=profile,
            github_context=github_context,
            image_name=image_name,
            source_sha=context_manifest["sourceSha"],
        )

    image_evidence, image_findings = validate_image_inspect(image_inspect, profile)
    inventory_digest = _validate_inventory_document(inventory, profile)
    if mode == "release":
        digest_match = IMAGE_DIGEST_RE.fullmatch(registry_digest or "")
        if not digest_match:
            raise PolicyError("release receipt requires an immutable registry digest")
        subject_digest = digest_match.group(1)
        subject_kind = "oci-manifest"
    else:
        if registry_digest is not None:
            raise PolicyError("premerge receipt must not claim a registry digest")
        subject_digest = image_evidence["imageId"].removeprefix("sha256:")
        subject_kind = "local-image-config"
    build_evidence = _validate_build_metadata(build_metadata, image_evidence["imageId"])
    inventory_findings = inventory.get("findings")
    if not isinstance(inventory_findings, list) or not all(
        isinstance(item, str) for item in inventory_findings
    ):
        raise PolicyError("rootfs inventory findings are malformed")
    build_secret_metadata = _validate_build_materialization_evidence(
        profile=profile,
        mode=mode,
        evidence=build_secret_metadata,
    )

    expected_invocation = {
        "schemaVersion": SCHEMA_VERSION,
        "frontend": "dockerfile.v0",
        "platform": "linux/amd64",
        "pull": True,
        "noCache": True,
        "contextDigest": context_manifest["contextDigest"],
        "dockerfile": profile["dockerfile"],
        "buildArguments": {},
        "buildSecretIds": (
            [] if profile["buildSecret"] is None else [profile["buildSecret"]["id"]]
        ),
        "sshForwarding": False,
        "additionalContexts": {},
        "target": None,
    }
    if build_invocation != expected_invocation:
        raise PolicyError("build invocation differs from the exact org-owned grammar")

    findings = sorted(set(image_findings + inventory_findings))
    bound_invocation = {**github_context, "nonce": receipt_nonce}
    payload = {
        "schemaVersion": SCHEMA_VERSION,
        "predicateType": PREDICATE_TYPE,
        "mode": mode,
        "result": "pass" if not findings else "fail",
        "subject": {
            "name": image_name,
            "kind": subject_kind,
            "digest": {"sha256": subject_digest},
        },
        "policy": {
            "repository": "cognitum-one/.github",
            "profileDigest": expected_profile_digest,
            "profileFileDigest": _profile_file_digest(policy_path),
            "generatorDigest": f"sha256:{_sha256_file(Path(__file__))}",
            "applicabilityException": _applicability_exception_evidence(profile),
        },
        "invocation": bound_invocation,
        "source": {
            "repository": repository,
            "sourceSha": context_manifest["sourceSha"],
            "sourceTreeSha": context_manifest["sourceTreeSha"],
            "contextSubdirectory": context_manifest["contextSubdirectory"],
            "contextDigest": context_manifest["contextDigest"],
            "contextManifestDigest": (
                f"sha256:{_sha256_bytes(_canonical_bytes(context_manifest))}"
            ),
            "packagingFileDigests": context_manifest["packagingFileDigests"],
            "submodules": context_manifest["submodules"],
        },
        "build": {
            "invocation": build_invocation,
            "metadata": build_evidence,
            "buildSecret": build_secret_metadata,
        },
        "image": {
            "registryDigest": registry_digest,
            "configAndRootfs": image_evidence,
            "inventoryDigest": inventory_digest,
            "inventoryEntryCount": inventory.get("entryCount"),
            "runtimeEvidence": inventory.get("policyEvidence"),
        },
        "deploymentPolicy": profile["deployment"],
        "assertions": {
            "committedOnlyContext": True,
            "exactPackagingPolicy": True,
            "exactBuildInvocation": True,
            "sameImageConfigDigest": True,
            "linuxAmd64": not any("platform" in finding for finding in image_findings),
            "defaultCommandApproved": not any(
                "config entrypoint" in finding or "config command" in finding
                for finding in image_findings
            ),
            "bakedEnvironmentAllowlisted": not any(
                "config environment" in finding for finding in image_findings
            ),
            "runtimePackageManagerAbsent": not any(
                "package manager" in finding for finding in inventory_findings
            ),
            "serverSideReactRouterPackageAbsent": not any(
                "runtime package path" in finding for finding in inventory_findings
            ),
            "reactServerRuntimeAbsent": not any(
                "RSC surface" in finding for finding in inventory_findings
            ),
            "browserAssetsConfinedToStaticRoot": not any(
                finding.startswith("static ") for finding in inventory_findings
            ),
        },
        "findings": findings,
    }
    payload["receiptDigest"] = f"sha256:{_sha256_bytes(_canonical_bytes(payload))}"
    return payload


def verify_receipt(
    *,
    receipt: dict[str, Any],
    inventory: dict[str, Any],
    repository: str,
    policy: dict[str, Any],
    policy_path: Path,
    expected_mode: str,
    expected_source_sha: str,
    expected_image_name: str,
    expected_subject_digest: str,
    expected_run_id: str,
    expected_run_attempt: str,
    expected_job: str,
    expected_workflow_ref: str,
    expected_workflow_sha: str,
    expected_nonce: str,
) -> None:
    if expected_mode not in {"premerge", "release"}:
        raise PolicyError("expected receipt mode is invalid")
    if not SHA1_RE.fullmatch(expected_source_sha):
        raise PolicyError("expected source SHA is invalid")
    if not IMAGE_ID_RE.fullmatch(expected_subject_digest):
        raise PolicyError("expected subject digest is invalid")
    if not re.fullmatch(r"[0-9a-f]{64}", expected_nonce):
        raise PolicyError("expected receipt nonce is invalid")
    if (
        not expected_run_id.isdigit()
        or int(expected_run_id) <= 0
        or not expected_run_attempt.isdigit()
        or int(expected_run_attempt) <= 0
        or not expected_job
        or not expected_workflow_ref
        or not SHA1_RE.fullmatch(expected_workflow_sha)
    ):
        raise PolicyError("expected workflow replay tuple is invalid")
    profile = profile_for(repository, policy)
    inventory_digest = _validate_inventory_document(inventory, profile)
    if not isinstance(receipt, dict):
        raise PolicyError("receipt must be an object")
    supplied_digest = receipt.get("receiptDigest")
    unsigned = dict(receipt)
    unsigned.pop("receiptDigest", None)
    actual_digest = f"sha256:{_sha256_bytes(_canonical_bytes(unsigned))}"
    if supplied_digest != actual_digest:
        raise PolicyError("receipt content digest is invalid")
    receipt_build = receipt.get("build")
    if not isinstance(receipt_build, dict):
        raise PolicyError("receipt build evidence is absent")
    _require_exact_keys(
        receipt_build,
        {"invocation", "metadata", "buildSecret"},
        "receipt build evidence",
    )
    materialization_evidence = _validate_build_materialization_evidence(
        profile=profile,
        mode=expected_mode,
        evidence=receipt_build["buildSecret"],
    )
    expected = {
        "predicateType": PREDICATE_TYPE,
        "mode": expected_mode,
        "result": "pass",
        "repository": repository,
        "repositoryId": profile["repositoryIdentity"]["repositoryId"],
        "repositoryOwnerId": profile["repositoryIdentity"]["ownerId"],
        "repositoryVisibility": profile["repositoryIdentity"]["visibility"],
        "sourceSha": expected_source_sha,
        "imageName": expected_image_name,
        "subjectDigest": expected_subject_digest,
        "runId": expected_run_id,
        "runAttempt": expected_run_attempt,
        "job": expected_job,
        "workflowRef": expected_workflow_ref,
        "workflowSha": expected_workflow_sha,
        "nonce": expected_nonce,
        "profileDigest": f"sha256:{profile_digest(repository, profile)}",
        "profileFileDigest": _profile_file_digest(policy_path),
        "generatorDigest": f"sha256:{_sha256_file(Path(__file__))}",
        "applicabilityException": _applicability_exception_evidence(profile),
        "packagingFileDigests": profile["packagingFiles"],
        "inventoryDigest": inventory_digest,
        "inventoryEntryCount": inventory["entryCount"],
        "runtimeEvidence": inventory["policyEvidence"],
        "buildMaterialization": materialization_evidence,
    }
    actual = {
        "predicateType": receipt.get("predicateType"),
        "mode": receipt.get("mode"),
        "result": receipt.get("result"),
        "repository": receipt.get("source", {}).get("repository"),
        "repositoryId": receipt.get("invocation", {}).get("repositoryId"),
        "repositoryOwnerId": receipt.get("invocation", {}).get("repositoryOwnerId"),
        "repositoryVisibility": receipt.get("invocation", {}).get(
            "repositoryVisibility"
        ),
        "sourceSha": receipt.get("source", {}).get("sourceSha"),
        "imageName": receipt.get("subject", {}).get("name"),
        "subjectDigest": (
            "sha256:" + str(receipt.get("subject", {}).get("digest", {}).get("sha256"))
        ),
        "runId": receipt.get("invocation", {}).get("runId"),
        "runAttempt": receipt.get("invocation", {}).get("runAttempt"),
        "job": receipt.get("invocation", {}).get("job"),
        "workflowRef": receipt.get("invocation", {}).get("callerWorkflowRef"),
        "workflowSha": receipt.get("invocation", {}).get("callerWorkflowSha"),
        "nonce": receipt.get("invocation", {}).get("nonce"),
        "profileDigest": receipt.get("policy", {}).get("profileDigest"),
        "profileFileDigest": receipt.get("policy", {}).get("profileFileDigest"),
        "generatorDigest": receipt.get("policy", {}).get("generatorDigest"),
        "applicabilityException": receipt.get("policy", {}).get(
            "applicabilityException"
        ),
        "packagingFileDigests": receipt.get("source", {}).get("packagingFileDigests"),
        "inventoryDigest": receipt.get("image", {}).get("inventoryDigest"),
        "inventoryEntryCount": receipt.get("image", {}).get("inventoryEntryCount"),
        "runtimeEvidence": receipt.get("image", {}).get("runtimeEvidence"),
        "buildMaterialization": receipt_build["buildSecret"],
    }
    if actual != expected:
        # Report only field names, never values. This keeps the receipt
        # fail-closed while making live reusable-workflow drift diagnosable
        # without exposing repository, runtime, nonce, or build evidence.
        differing_fields = sorted(
            field for field in expected if actual.get(field) != expected[field]
        )
        raise PolicyError(
            "receipt replay-binding tuple differs: "
            + ", ".join(differing_fields)
        )
    assertions = receipt.get("assertions")
    if (
        not isinstance(assertions, dict)
        or set(assertions) != ASSERTION_KEYS
        or not all(value is True for value in assertions.values())
    ):
        raise PolicyError("receipt assertions are incomplete or failed")
    if receipt.get("findings") != [] or inventory.get("findings") != []:
        raise PolicyError("receipt or inventory contains findings")
    registry_digest = receipt.get("image", {}).get("registryDigest")
    subject_kind = receipt.get("subject", {}).get("kind")
    if expected_mode == "release":
        if registry_digest != expected_subject_digest or subject_kind != "oci-manifest":
            raise PolicyError("release receipt is not registry-bound")
        invocation = receipt.get("invocation")
        if not isinstance(invocation, dict):
            raise PolicyError("release receipt invocation is absent")
        _validate_release_invocation(
            profile=profile,
            github_context=invocation,
            image_name=expected_image_name,
            source_sha=expected_source_sha,
        )
    elif expected_mode == "premerge":
        image_id = receipt.get("image", {}).get("configAndRootfs", {}).get("imageId")
        if (
            registry_digest is not None
            or image_id != expected_subject_digest
            or subject_kind != "local-image-config"
        ):
            raise PolicyError("premerge receipt is not local-image-bound")
    else:
        raise PolicyError("expected receipt mode is invalid")


def verify_premerge_receipt(
    *,
    receipt: dict[str, Any],
    inventory: dict[str, Any],
    repository: str,
    policy: dict[str, Any],
    policy_path: Path,
    expected_source_sha: str,
    expected_image_name: str,
    expected_image_id: str,
    expected_run_id: str,
    expected_run_attempt: str,
    expected_job: str,
    expected_workflow_ref: str,
    expected_workflow_sha: str,
    expected_nonce: str,
) -> None:
    """Pure, no-subprocess API for the same-job OSV applicability gate."""

    verify_receipt(
        receipt=receipt,
        inventory=inventory,
        repository=repository,
        policy=policy,
        policy_path=policy_path,
        expected_mode="premerge",
        expected_source_sha=expected_source_sha,
        expected_image_name=expected_image_name,
        expected_subject_digest=expected_image_id,
        expected_run_id=expected_run_id,
        expected_run_attempt=expected_run_attempt,
        expected_job=expected_job,
        expected_workflow_ref=expected_workflow_ref,
        expected_workflow_sha=expected_workflow_sha,
        expected_nonce=expected_nonce,
    )


def validate_revision(
    *,
    revision: dict[str, Any],
    profile: dict[str, Any],
    expected_image: str,
    expected_service_account: str,
    expected_spec_digest: str,
) -> dict[str, Any]:
    """Validate and bind the immutable Cloud Run Revision specification.

    Service-level ingress and traffic allocation are intentionally not part of
    a Revision object.  Promotion must bind this returned evidence alongside a
    separately validated Service/traffic record.
    """

    if not isinstance(revision, dict):
        raise PolicyError("Cloud Run revision must be an object")
    if not isinstance(expected_service_account, str) or not re.fullmatch(
        r"[a-z0-9][a-z0-9._-]*@[a-z0-9][a-z0-9.-]*",
        expected_service_account,
    ):
        raise PolicyError("expected runtime service account is invalid")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", expected_spec_digest):
        raise PolicyError("expected Cloud Run revision spec digest is invalid")
    expected_repository = profile["release"]["registryRepository"]
    if not re.fullmatch(
        re.escape(expected_repository) + r"@sha256:[0-9a-f]{64}",
        expected_image,
    ):
        raise PolicyError(
            "expected Cloud Run image is outside the approved digest repository"
        )
    spec = revision.get("spec")
    if not isinstance(spec, dict):
        raise PolicyError("Cloud Run revision spec is absent")
    actual_spec_digest = f"sha256:{_sha256_bytes(_canonical_bytes(spec))}"
    if actual_spec_digest != expected_spec_digest:
        raise PolicyError("Cloud Run revision spec digest differs")
    if spec.get("serviceAccountName") != expected_service_account:
        raise PolicyError("Cloud Run runtime service account differs")
    containers = spec.get("containers")
    if not isinstance(containers, list) or len(containers) != 1:
        raise PolicyError("Cloud Run revision must have exactly one container")
    container = containers[0]
    if not isinstance(container, dict):
        raise PolicyError("Cloud Run container is malformed")
    if container.get("image") != expected_image:
        raise PolicyError("Cloud Run revision image digest differs")
    if container.get("command") not in (None, []) or container.get("args") not in (
        None,
        [],
    ):
        raise PolicyError("Cloud Run revision overrides image command or arguments")
    if container.get("volumeMounts") not in (None, []) or spec.get("volumes") not in (
        None,
        [],
    ):
        raise PolicyError("Cloud Run revision adds volumes or mounts")
    if container.get("dependsOn") not in (None, []) or spec.get(
        "containerDependencies"
    ) not in (None, {}, []):
        raise PolicyError("Cloud Run revision adds startup dependencies")
    for metadata in (revision.get("metadata"), spec.get("metadata")):
        if metadata is None:
            continue
        if not isinstance(metadata, dict):
            raise PolicyError("Cloud Run revision metadata is malformed")
        annotations = metadata.get("annotations", {})
        if not isinstance(annotations, dict):
            raise PolicyError("Cloud Run revision annotations are malformed")
        if any("container-dependencies" in str(key) for key in annotations):
            raise PolicyError("Cloud Run revision adds startup dependencies")

    ports = container.get("ports")
    if not isinstance(ports, list) or len(ports) != 1:
        raise PolicyError("Cloud Run revision must declare exactly one port")
    port = ports[0]
    if not isinstance(port, dict) or set(port) not in (
        {"containerPort"},
        {"name", "containerPort"},
    ):
        raise PolicyError("Cloud Run revision port declaration is malformed")
    if port["containerPort"] != 8080 or ("name" in port and port["name"] != "http1"):
        raise PolicyError("Cloud Run revision must expose only HTTP port 8080")

    env_records = container.get("env", [])
    if not isinstance(env_records, list):
        raise PolicyError("Cloud Run revision environment is malformed")
    names = []
    environment_evidence: list[dict[str, Any]] = []
    for record in env_records:
        if not isinstance(record, dict) or not isinstance(record.get("name"), str):
            raise PolicyError("Cloud Run revision environment item is malformed")
        name = record["name"]
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", name):
            raise PolicyError("Cloud Run revision environment name is invalid")
        names.append(name)
        if set(record) == {"name", "value"}:
            value = record["value"]
            if (
                not isinstance(value, str)
                or "\x00" in value
                or any(
                    ord(character) < 0x20 and character != "\t" for character in value
                )
            ):
                raise PolicyError(
                    f"Cloud Run revision environment value is malformed: {name}"
                )
            environment_evidence.append(
                {
                    "name": name,
                    "source": "value",
                    "valueDigest": f"sha256:{_sha256_bytes(value.encode('utf-8'))}",
                }
            )
            continue
        if set(record) == {"name", "valueFrom"}:
            source = record["valueFrom"]
            if (
                not isinstance(source, dict)
                or set(source) != {"secretKeyRef"}
                or not isinstance(source["secretKeyRef"], dict)
                or set(source["secretKeyRef"]) != {"name", "key"}
            ):
                raise PolicyError(
                    f"Cloud Run revision secret reference is malformed: {name}"
                )
            secret_ref = source["secretKeyRef"]
            secret = secret_ref["name"]
            version = secret_ref["key"]
        elif set(record) == {"name", "valueSource"}:
            source = record["valueSource"]
            if (
                not isinstance(source, dict)
                or set(source) != {"secretKeyRef"}
                or not isinstance(source["secretKeyRef"], dict)
                or set(source["secretKeyRef"]) != {"secret", "version"}
            ):
                raise PolicyError(
                    f"Cloud Run revision secret reference is malformed: {name}"
                )
            secret_ref = source["secretKeyRef"]
            secret = secret_ref["secret"]
            version = secret_ref["version"]
        else:
            raise PolicyError(
                f"Cloud Run revision environment source is not explicit: {name}"
            )
        if (
            not isinstance(secret, str)
            or not re.fullmatch(
                r"(?:projects/[0-9]+/secrets/)?[A-Za-z][A-Za-z0-9_-]{0,254}",
                secret,
            )
            or isinstance(version, bool)
            or not isinstance(version, (str, int))
            or not str(version).isdigit()
            or int(version) <= 0
        ):
            raise PolicyError(
                f"Cloud Run revision secret reference must use a numeric version: {name}"
            )
        environment_evidence.append(
            {
                "name": name,
                "source": "secret",
                "secret": secret,
                "version": str(version),
            }
        )
    if len(names) != len(set(names)):
        raise PolicyError("Cloud Run revision has duplicate environment names")
    allowed = set(profile["deployment"]["configuredEnvironmentAllowlist"])
    forbidden = set(profile["deployment"]["forbiddenEnvironment"])
    unexpected = sorted(set(names) - allowed)
    missing = sorted(allowed - set(names))
    if unexpected or missing or set(names) & forbidden:
        raise PolicyError(
            "Cloud Run revision environment differs from the exact configured "
            f"set: unexpected={unexpected}, missing={missing}"
        )
    evidence = {
        "image": expected_image,
        "runtimeServiceAccount": expected_service_account,
        "specDigest": actual_spec_digest,
        "containerCount": 1,
        "port": 8080,
        "commandOverride": False,
        "argumentsOverride": False,
        "volumeMountCount": 0,
        "startupDependencies": False,
        "environment": sorted(environment_evidence, key=lambda item: item["name"]),
        "evidenceDigest": "",
    }
    evidence["evidenceDigest"] = f"sha256:{_sha256_bytes(_canonical_bytes(evidence))}"
    return evidence


def _write_json(path: Path, value: Any, *, mode: int = 0o600) -> None:
    if path.exists() or path.is_symlink():
        raise PolicyError(f"output already exists: {path}")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2, sort_keys=True, ensure_ascii=False)
        stream.write("\n")


def _read_external_nonce(path: Path, output_directory: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise PolicyError("receipt nonce input is not a regular file")
    try:
        path.resolve().relative_to(output_directory.resolve())
    except ValueError:
        pass
    else:
        raise PolicyError("receipt nonce must be supplied outside the build output")
    if stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise PolicyError("receipt nonce input must not be group/world accessible")
    try:
        nonce = path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError) as error:
        raise PolicyError(f"receipt nonce input cannot be read: {error}") from error
    if not re.fullmatch(r"[0-9a-f]{64}", nonce):
        raise PolicyError("receipt nonce input is not a 256-bit lowercase value")
    return nonce


def _docker_image_inspect(image_ref: str) -> Any:
    # ``docker image inspect --platform`` is not available on every supported
    # Docker CLI. The inspected image's Os/Architecture fields are checked
    # fail-closed by validate_image_inspect immediately after this call.
    return _strict_json_loads(
        _run(
            [
                "docker",
                "image",
                "inspect",
                image_ref,
            ],
            timeout=120,
        ).decode("utf-8")
    )


def _docker_rootfs_inventory(image_ref: str, profile: dict[str, Any]) -> dict[str, Any]:
    container_id = (
        _run(
            [
                "docker",
                "container",
                "create",
                "--platform",
                "linux/amd64",
                "--network",
                "none",
                image_ref,
            ],
            timeout=120,
        )
        .decode("utf-8")
        .strip()
    )
    if not re.fullmatch(r"[0-9a-f]{64}", container_id):
        raise PolicyError("docker create did not return an immutable container ID")
    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen(
            ["docker", "container", "export", container_id],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        assert process.stdout is not None
        inventory = inventory_rootfs(process.stdout, profile)
        process.stdout.close()
        assert process.stderr is not None
        stderr = process.stderr.read().decode("utf-8", errors="replace")
        process.stderr.close()
        status = process.wait(timeout=120)
        if status != 0:
            raise PolicyError(f"docker export failed ({status}): {stderr[-2000:]}")
        return inventory
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        with contextlib.suppress(PolicyError):
            _run(
                ["docker", "container", "rm", "--force", container_id],
                timeout=120,
            )


def _exact_build_invocation(
    profile: dict[str, Any], context_manifest: dict[str, Any]
) -> dict[str, Any]:
    return {
        "schemaVersion": SCHEMA_VERSION,
        "frontend": "dockerfile.v0",
        "platform": "linux/amd64",
        "pull": True,
        "noCache": True,
        "contextDigest": context_manifest["contextDigest"],
        "dockerfile": profile["dockerfile"],
        "buildArguments": {},
        "buildSecretIds": (
            [] if profile["buildSecret"] is None else [profile["buildSecret"]["id"]]
        ),
        "sshForwarding": False,
        "additionalContexts": {},
        "target": None,
    }


def _trusted_docker_environment() -> dict[str, str]:
    """Return only Docker client transport state for an isolated trusted runner.

    This policy assumes an ephemeral organization-controlled runner and Docker
    daemon; it is not a sandbox for a daemon shared with hostile concurrent
    jobs. Candidate-controlled Buildx/BuildKit variables are deliberately
    discarded and provenance is forced back on.
    """

    allowed = (
        "PATH",
        "HOME",
        "DOCKER_CONFIG",
        "DOCKER_HOST",
        "DOCKER_TLS_VERIFY",
        "DOCKER_CERT_PATH",
        "XDG_RUNTIME_DIR",
    )
    environment = {key: os.environ[key] for key in allowed if key in os.environ}
    environment["BUILDX_METADATA_PROVENANCE"] = "max"
    environment.pop("BUILDX_NO_DEFAULT_ATTESTATIONS", None)
    return environment


def _materialize_profile_build_environment(
    *,
    profile: dict[str, Any],
    contract: dict[str, Any],
    output_path: Path,
    mode: str,
) -> dict[str, Any]:
    if mode == "premerge":
        return materialize_premerge_fixture(
            profile=profile,
            contract=contract,
            output_path=output_path,
        )
    if mode == "release":
        return materialize_management_environment(
            profile=profile,
            contract=contract,
            output_path=output_path,
            access_secret=_gcloud_secret_accessor,
        )
    raise PolicyError("build environment materialization mode is invalid")


def trusted_build(
    *,
    repository: str,
    repository_root: Path,
    source_sha: str,
    output_directory: Path,
    image_tag: str,
    policy: dict[str, Any],
    policy_path: Path,
    beacon_repository_root: Path | None,
    mode: str,
    receipt_nonce: str,
) -> dict[str, Any]:
    if not LOCAL_TAG_RE.fullmatch(image_tag) or image_tag.endswith(":latest"):
        raise PolicyError("image tag is mutable, malformed, or latest")
    if mode not in {"premerge", "release"}:
        raise PolicyError("trusted build mode must be premerge or release")
    if not re.fullmatch(r"[0-9a-f]{64}", receipt_nonce):
        raise PolicyError("trusted build receipt nonce is invalid")
    profile = profile_for(repository, policy)
    github_context = _required_github_context(dict(os.environ))
    image_name = image_tag.rsplit(":", 1)[0]
    if mode == "release":
        if image_tag != f"{profile['release']['registryRepository']}:{source_sha}":
            raise PolicyError(
                "release image tag must be the approved repository and source SHA"
            )
        _validate_release_invocation(
            profile=profile,
            github_context=github_context,
            image_name=image_name,
            source_sha=source_sha,
        )
        _require_current_origin_main(repository_root, repository, source_sha)
    if output_directory.exists() and (
        output_directory.is_symlink() or any(output_directory.iterdir())
    ):
        raise PolicyError("trusted build output directory must be absent or empty")
    output_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    context_root = output_directory / "context"
    context_manifest = prepare_context(
        repository=repository,
        repository_root=repository_root,
        source_sha=source_sha,
        destination=context_root,
        policy=policy,
        beacon_repository_root=beacon_repository_root,
    )
    _write_json(output_directory / "context-manifest.json", context_manifest)
    secret_path = (
        None
        if profile["buildSecret"] is None
        else output_directory / "management-vite.env"
    )
    secret_metadata = None
    metadata_path = output_directory / "build-metadata.json"
    iid_path = output_directory / "image-id.txt"
    command = [
        "docker",
        "buildx",
        "build",
        "--load",
        "--pull",
        "--no-cache",
        "--platform",
        "linux/amd64",
        "--metadata-file",
        str(metadata_path),
        "--iidfile",
        str(iid_path),
        "--tag",
        image_tag,
    ]
    try:
        if secret_path is not None:
            contract_path = context_root / profile["buildSecret"]["versionContractPath"]
            contract = _read_json(contract_path)
            secret_metadata = _materialize_profile_build_environment(
                profile=profile,
                contract=contract,
                output_path=secret_path,
                mode=mode,
            )
            command.extend(
                [
                    "--secret",
                    f"id={profile['buildSecret']['id']},src={secret_path}",
                ]
            )
        command.append(str(context_root))
        _run(
            command,
            cwd=context_root,
            env=_trusted_docker_environment(),
            timeout=3600,
        )
    finally:
        if secret_path is not None:
            try:
                secret_path.unlink()
            except FileNotFoundError:
                pass
            except OSError as error:
                raise PolicyError(
                    f"generated management build secret cleanup failed: {error}"
                ) from error
    if secret_metadata is not None:
        _write_json(
            output_directory / "build-secret-metadata.json",
            secret_metadata,
        )
    if metadata_path.is_symlink() or not metadata_path.is_file():
        raise PolicyError("Buildx did not produce metadata")
    if iid_path.is_symlink() or not iid_path.is_file():
        raise PolicyError("Buildx did not produce an image ID")
    iid = iid_path.read_text(encoding="ascii").strip()
    if not IMAGE_ID_RE.fullmatch(iid):
        raise PolicyError("Buildx image ID is invalid")
    inspect_value = _docker_image_inspect(image_tag)
    if inspect_value[0].get("Id") != iid:
        raise PolicyError("Buildx image ID differs from docker image inspect")

    registry_digest = None
    inventory_image_ref = iid
    if mode == "release":
        _run(
            ["docker", "image", "push", image_tag],
            env=_trusted_docker_environment(),
            timeout=1800,
        )
        post_push = _docker_image_inspect(image_tag)
        if post_push[0].get("Id") != iid:
            raise PolicyError("pushed tag no longer resolves to the built image ID")
        repo_digests = post_push[0].get("RepoDigests") or []
        prefix = image_name + "@"
        matching = sorted(
            digest
            for digest in repo_digests
            if isinstance(digest, str) and digest.startswith(prefix)
        )
        if len(matching) != 1:
            raise PolicyError("pushed image has no unique immutable repository digest")
        registry_digest = matching[0].removeprefix(prefix)
        digest_inspect = _docker_image_inspect(matching[0])
        if digest_inspect[0].get("Id") != iid:
            raise PolicyError("immutable repository digest has a different image ID")
        inspect_value = digest_inspect
        inventory_image_ref = matching[0]
    if mode == "release" and registry_digest is None:
        raise PolicyError("release receipt requires the exact pushed registry digest")

    inventory = _docker_rootfs_inventory(inventory_image_ref, profile)
    _write_json(output_directory / "rootfs-inventory.json", inventory)
    metadata = _read_json(metadata_path)
    invocation = _exact_build_invocation(profile, context_manifest)
    _write_json(output_directory / "build-invocation.json", invocation)
    receipt = build_receipt(
        repository=repository,
        policy=policy,
        policy_path=policy_path,
        context_manifest=context_manifest,
        image_inspect=inspect_value,
        inventory=inventory,
        build_metadata=metadata,
        mode=mode,
        image_name=image_name,
        registry_digest=registry_digest,
        github_context=github_context,
        receipt_nonce=receipt_nonce,
        build_invocation=invocation,
        build_secret_metadata=secret_metadata,
    )
    _write_json(output_directory / "static-ui-runtime-receipt.json", receipt)
    return receipt


def _command_profiles(arguments: argparse.Namespace) -> int:
    policy = load_policy(arguments.policy)
    for repository, profile in sorted(policy["profiles"].items()):
        print(f"{repository}: {profile['status']}")
    return 0


def _command_prepare(arguments: argparse.Namespace) -> int:
    policy = load_policy(arguments.policy)
    manifest = prepare_context(
        repository=arguments.repository,
        repository_root=arguments.repository_root,
        source_sha=arguments.source_sha,
        destination=arguments.context,
        policy=policy,
        beacon_repository_root=arguments.beacon_repository_root,
    )
    _write_json(arguments.output, manifest)
    print(manifest["contextDigest"])
    return 0


def _command_build(arguments: argparse.Namespace) -> int:
    policy = load_policy(arguments.policy)
    receipt_nonce = _read_external_nonce(
        arguments.receipt_nonce_file, arguments.output_directory
    )
    receipt = trusted_build(
        repository=arguments.repository,
        repository_root=arguments.repository_root,
        source_sha=arguments.source_sha,
        output_directory=arguments.output_directory,
        image_tag=arguments.image_tag,
        policy=policy,
        policy_path=arguments.policy,
        beacon_repository_root=arguments.beacon_repository_root,
        mode=arguments.mode,
        receipt_nonce=receipt_nonce,
    )
    print(receipt["receiptDigest"])
    return 0


def _command_verify(arguments: argparse.Namespace) -> int:
    policy = load_policy(arguments.policy)
    verify_receipt(
        receipt=_read_json(arguments.receipt),
        inventory=_read_json(arguments.inventory),
        repository=arguments.repository,
        policy=policy,
        policy_path=arguments.policy,
        expected_mode=arguments.expected_mode,
        expected_source_sha=arguments.expected_source_sha,
        expected_image_name=arguments.expected_image_name,
        expected_subject_digest=arguments.expected_subject_digest,
        expected_run_id=arguments.expected_run_id,
        expected_run_attempt=arguments.expected_run_attempt,
        expected_job=arguments.expected_job,
        expected_workflow_ref=arguments.expected_workflow_ref,
        expected_workflow_sha=arguments.expected_workflow_sha,
        expected_nonce=arguments.expected_nonce,
    )
    print("static-ui-runtime-receipt: PASS")
    return 0


def _command_revision(arguments: argparse.Namespace) -> int:
    policy = load_policy(arguments.policy)
    profile = profile_for(arguments.repository, policy)
    evidence = validate_revision(
        revision=_read_json(arguments.revision),
        profile=profile,
        expected_image=arguments.expected_image,
        expected_service_account=arguments.expected_service_account,
        expected_spec_digest=arguments.expected_spec_digest,
    )
    _write_json(arguments.output, evidence)
    print("static-ui-runtime-revision: PASS")
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Organization-owned static UI trusted builder and receipt gate"
    )
    parser.add_argument(
        "--policy",
        type=Path,
        default=DEFAULT_POLICY,
        help="immutable organization profile policy",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    profiles = commands.add_parser("profiles", help="validate and list profiles")
    profiles.set_defaults(handler=_command_profiles)

    prepare = commands.add_parser(
        "prepare-context", help="export one committed-only build context"
    )
    prepare.add_argument("--repository", required=True)
    prepare.add_argument("--repository-root", type=Path, required=True)
    prepare.add_argument("--source-sha", required=True)
    prepare.add_argument("--context", type=Path, required=True)
    prepare.add_argument("--output", type=Path, required=True)
    prepare.add_argument("--beacon-repository-root", type=Path)
    prepare.set_defaults(handler=_command_prepare)

    build = commands.add_parser(
        "build", help="build, push, inspect, and emit the unsigned predicate"
    )
    build.add_argument("--repository", required=True)
    build.add_argument("--repository-root", type=Path, required=True)
    build.add_argument("--source-sha", required=True)
    build.add_argument("--output-directory", type=Path, required=True)
    build.add_argument("--image-tag", required=True)
    build.add_argument("--beacon-repository-root", type=Path)
    build.add_argument("--receipt-nonce-file", type=Path, required=True)
    build.add_argument("--mode", choices=("premerge", "release"), required=True)
    build.set_defaults(handler=_command_build)

    verify = commands.add_parser(
        "verify", help="gate an attested predicate against an exact promotion tuple"
    )
    verify.add_argument("--repository", required=True)
    verify.add_argument("--receipt", type=Path, required=True)
    verify.add_argument("--inventory", type=Path, required=True)
    verify.add_argument("--expected-source-sha", required=True)
    verify.add_argument(
        "--expected-mode", choices=("premerge", "release"), required=True
    )
    verify.add_argument("--expected-image-name", required=True)
    verify.add_argument("--expected-subject-digest", required=True)
    verify.add_argument("--expected-run-id", required=True)
    verify.add_argument("--expected-run-attempt", required=True)
    verify.add_argument("--expected-job", required=True)
    verify.add_argument("--expected-workflow-ref", required=True)
    verify.add_argument("--expected-workflow-sha", required=True)
    verify.add_argument("--expected-nonce", required=True)
    verify.set_defaults(handler=_command_verify)

    revision = commands.add_parser(
        "verify-revision", help="gate the exact deployed Cloud Run revision"
    )
    revision.add_argument("--repository", required=True)
    revision.add_argument("--revision", type=Path, required=True)
    revision.add_argument("--expected-image", required=True)
    revision.add_argument("--expected-service-account", required=True)
    revision.add_argument("--expected-spec-digest", required=True)
    revision.add_argument("--output", type=Path, required=True)
    revision.set_defaults(handler=_command_revision)
    return parser


def main() -> int:
    try:
        arguments = _parser().parse_args()
        return arguments.handler(arguments)
    except PolicyError as error:
        print(f"::error::static UI runtime policy failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
