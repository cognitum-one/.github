#!/usr/bin/env python3
"""Static fail-closed verifier for the org-owned static UI workflows."""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
from pathlib import Path
import re
import sys

SHA1_RE = re.compile(r"[0-9a-f]{40}")
SHA256_RE = re.compile(r"[0-9a-f]{64}")
ACTION_RE = re.compile(r"^\s*(?:-\s*)?uses:\s*([^@\s]+)@([^\s#]+)", re.MULTILINE)
ENV_VALUE_RE = re.compile(r'^\s{2}([A-Z][A-Z0-9_]+):\s*"([^"]+)"\s*$', re.MULTILINE)
ZERO_SHA = "0" * 40
MAX_WORKFLOW_BYTES = 512 * 1024
EXPECTED_BUILDKIT_IMAGE = (
    "moby/buildkit@"
    "sha256:0168606be2315b7c807a03b3d8aa79beefdb31c98740cebdffdfeebf31190c9f"
)
EXPECTED_BUILDKITD_FLAGS = "--oci-worker-net=bridge"
EXPECTED_BUILDX_VERSION = "v0.33.0"
EXPECTED_BUILDX_REVISION = "f7897eba028583e0071642db3c011e860444f8cf"
EXPECTED_BUILDX_LINUX_AMD64_SHA256 = (
    "9426a15411f35f635afef3f5d3bae53155c3e30d26dee430cc968e13d34be49f"
)
EXPECTED_DOCKER_CONFIG = "$RUNNER_TEMP/static-ui-docker-config"
EXPECTED_BUILDX_URL = (
    "https://github.com/docker/buildx/releases/download/"
    "v0.33.0/buildx-v0.33.0.linux-amd64"
)

EXPECTED_ACTIONS = {
    "actions/attest": "f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6",
    "actions/checkout": "fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09",
    "actions/create-github-app-token": "bcd2ba49218906704ab6c1aa796996da409d3eb1",
    "actions/upload-artifact": "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
    "docker/setup-buildx-action": "37fe631027851001ddb9b187196cc803df7f5f0e",
    "google-github-actions/auth": "7c6bc770dae815cd3e89ee6cdf493a5fab2cc093",
    "google-github-actions/setup-gcloud": "aa5489c8933f4cc7a4f7d45035b3b1440c9c10db",
}

EXPECTED_ORG_POLICY = {
    "OSV_POLICY_COMMIT": "9a499d0520a5d5e7818baf3e799048d62617a84d",
    "OSV_GATE_SHA256": "5e998e705b1b4dc22d6f0c0704de64d50124c0783dbc745c3ce2d919fbe9ab2f",
    "OSV_GATE_TEST_SHA256": "801d2ef72cc1905a34edbf54393a44e2deb88b492374fc35f6ba6d14cb58139c",
    "OSV_CONFIG_SHA256": "5bd10fc47448111e6d8bed4682b9b80e4c420ca6cb0808a252b8c6d8cd920c34",
    "OSV_RUNNER_SHA256": "f5d4c3e85e673d031bee763d7d516de07af420b727f8cdb9555748de9867e1a3",
    "OSV_RUNNER_TEST_SHA256": "46b266824f04d4caa84ed9afc1aed0020ef3ce986b7b2b0fd64a8a7f685549d3",
    "STATIC_UI_PROFILES_SHA256": "c1c40fd71dc7943d4ef698aa63d03902c0efe554e8d3566cb628ae6c0913a4da",
    "STATIC_UI_RECEIPT_SHA256": "6333055219e4b3c6a8a561df18774b008ed5afe428dc1d7fcc15fcb705bb0987",
    "STATIC_UI_RECEIPT_TEST_SHA256": "9a92d7076a2b3026c5ad28361783a673b67006b651eb4312a8c9972bd1e91d9d",
}

POLICY_ARTIFACTS = {
    "OSV_GATE_SHA256": "osv_gate.py",
    "OSV_GATE_TEST_SHA256": "test_osv_gate.py",
    "OSV_CONFIG_SHA256": "osv-scanner.toml",
    "OSV_RUNNER_SHA256": "run_osv_scan.py",
    "OSV_RUNNER_TEST_SHA256": "test_run_osv_scan.py",
    "STATIC_UI_PROFILES_SHA256": "static-ui-runtime-profiles.json",
    "STATIC_UI_RECEIPT_SHA256": "static_ui_runtime_receipt.py",
    "STATIC_UI_RECEIPT_TEST_SHA256": "test_static_ui_runtime_receipt.py",
    "STATIC_UI_RELEASE_GATE_SHA256": "static_ui_release_gate.py",
    "STATIC_UI_RELEASE_GATE_TEST_SHA256": "test_static_ui_release_gate.py",
}


class WorkflowPolicyError(ValueError):
    pass


def verify_local_policy_artifacts(security_directory: Path) -> None:
    for variable, filename in POLICY_ARTIFACTS.items():
        if variable not in EXPECTED_ORG_POLICY:
            continue
        artifact = security_directory / filename
        actual = hashlib.sha256(artifact.read_bytes()).hexdigest()
        if actual != EXPECTED_ORG_POLICY[variable]:
            raise WorkflowPolicyError(
                f"approved organization policy hash differs from {filename}"
            )


def _read(path: Path, label: str) -> str:
    if path.is_symlink() or not path.is_file():
        raise WorkflowPolicyError(f"{label} must be a non-symlink regular file")
    if path.stat().st_size <= 0 or path.stat().st_size > MAX_WORKFLOW_BYTES:
        raise WorkflowPolicyError(f"{label} has an invalid size")
    return path.read_text(encoding="utf-8")


def _require(source: str, fragments: tuple[str, ...], label: str) -> None:
    missing = [fragment for fragment in fragments if fragment not in source]
    if missing:
        raise WorkflowPolicyError(f"{label} is missing required grammar: {missing}")


def _require_order(source: str, fragments: tuple[str, ...], label: str) -> None:
    positions = [source.find(fragment) for fragment in fragments]
    if -1 in positions or positions != sorted(positions):
        raise WorkflowPolicyError(f"{label} required operations are out of order")


def _environment(source: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for key, value in ENV_VALUE_RE.findall(source):
        if key in values and values[key] != value:
            raise WorkflowPolicyError(f"workflow environment duplicates {key}")
        values[key] = value
    return values


def _verify_hash_checks(
    source: str, label: str, environment_names: tuple[str, ...]
) -> None:
    for environment_name in environment_names:
        artifact = POLICY_ARTIFACTS[environment_name]
        fragment = (
            f'echo "${{{environment_name}}}  ${{POLICY_DIR}}/{artifact}" '
            "| sha256sum -c -"
        )
        if source.count(fragment) != 1:
            raise WorkflowPolicyError(
                f"{label} must hash-check {artifact} exactly once"
            )


def _verify_actions(*sources: str) -> None:
    found: Counter[tuple[str, str]] = Counter()
    for source in sources:
        for action, revision in ACTION_RE.findall(source):
            if action.startswith("./"):
                raise WorkflowPolicyError("candidate-relative actions are forbidden")
            if not SHA1_RE.fullmatch(revision):
                raise WorkflowPolicyError(
                    f"action is not pinned by a full SHA: {action}"
                )
            expected = EXPECTED_ACTIONS.get(action)
            if expected is None:
                raise WorkflowPolicyError(f"unreviewed third-party action: {action}")
            if revision != expected:
                raise WorkflowPolicyError(f"action pin differs: {action}@{revision}")
            found[(action, revision)] += 1
    if not found:
        raise WorkflowPolicyError("no pinned Actions were found")


def _verify_trusted_buildkit(source: str, label: str) -> None:
    if "--allow-insecure-entitlement" in source:
        raise WorkflowPolicyError(
            f"{label} must not enable a BuildKit insecure entitlement"
        )
    if any(
        fragment in source
        for fragment in ("network=host", "--network host", "--network=host")
    ):
        raise WorkflowPolicyError(
            f"{label} must not select host networking for BuildKit or a build"
        )
    if re.search(
        r"--allow(?:=|\s+)(?:network\.host|security\.insecure)(?:\s|$)",
        source,
    ):
        raise WorkflowPolicyError(
            f"{label} must not grant a client-side BuildKit entitlement"
        )

    action = "docker/setup-buildx-action"
    marker = f"uses: {action}@{EXPECTED_ACTIONS[action]}"
    starts = [match.start() for match in re.finditer(r"(?m)^      - ", source)]
    steps = [
        source[start : starts[index + 1] if index + 1 < len(starts) else len(source)]
        for index, start in enumerate(starts)
    ]
    install_steps = [
        step
        for step in steps
        if "name: Install the exact verified Buildx client" in step
    ]
    if len(install_steps) != 1:
        raise WorkflowPolicyError(
            f"{label} must install exactly one hash-verified Buildx client"
        )
    install_step = install_steps[0]
    matching_steps = [step for step in steps if marker in step]
    if len(matching_steps) != 1:
        raise WorkflowPolicyError(
            f"{label} must configure exactly one trusted Docker builder"
        )
    step = matching_steps[0]
    if source.find(install_step) >= source.find(step):
        raise WorkflowPolicyError(
            f"{label} must verify Buildx before the setup action can execute it"
        )

    docker_configs = re.findall(
        r'(?m)^          DOCKER_CONFIG="([^"]+)"\s*$',
        install_step,
    )
    if docker_configs != [EXPECTED_DOCKER_CONFIG]:
        raise WorkflowPolicyError(
            f"{label} must isolate Buildx in the reviewed job-scoped DOCKER_CONFIG"
        )
    if source.count("DOCKER_CONFIG") != install_step.count("DOCKER_CONFIG"):
        raise WorkflowPolicyError(
            f"{label} must not override DOCKER_CONFIG outside the verified installer"
        )

    buildx_environment = re.findall(
        r'(?m)^          (BUILDX_[A-Z0-9_]+):\s*"([^"]+)"\s*$',
        install_step,
    )
    if buildx_environment != [
        ("BUILDX_VERSION", EXPECTED_BUILDX_VERSION),
        ("BUILDX_REVISION", EXPECTED_BUILDX_REVISION),
        ("BUILDX_LINUX_AMD64_SHA256", EXPECTED_BUILDX_LINUX_AMD64_SHA256),
    ]:
        raise WorkflowPolicyError(
            f"{label} Buildx version, revision, or checksum differs from policy"
        )

    run_match = re.search(
        r"(?m)^        run: \|\n((?:          [^\n]*\n?)*)",
        install_step,
    )
    if run_match is None:
        raise WorkflowPolicyError(
            f"{label} must use the reviewed Buildx installation grammar"
        )
    install_script = "\n".join(
        line.removeprefix("          ") for line in run_match.group(1).splitlines()
    )
    expected_install_script = "\n".join(
        (
            "set -euo pipefail",
            'DOCKER_CONFIG="$RUNNER_TEMP/static-ui-docker-config"',
            "export DOCKER_CONFIG",
            'test ! -e "$DOCKER_CONFIG" && test ! -L "$DOCKER_CONFIG"',
            'install -d -m 0700 "$DOCKER_CONFIG"',
            'install -d -m 0700 "$DOCKER_CONFIG/cli-plugins"',
            'BUILDX_DOWNLOAD="$RUNNER_TEMP/buildx-v0.33.0.linux-amd64"',
            'test ! -e "$BUILDX_DOWNLOAD" && test ! -L "$BUILDX_DOWNLOAD"',
            "curl --proto '=https' --tlsv1.2 -fsSLo \"$BUILDX_DOWNLOAD\" \\",
            f'  "{EXPECTED_BUILDX_URL}"',
            (
                'echo "${BUILDX_LINUX_AMD64_SHA256}  ${BUILDX_DOWNLOAD}" '
                "| sha256sum -c -"
            ),
            'BUILDX_PLUGIN="$DOCKER_CONFIG/cli-plugins/docker-buildx"',
            'install -m 0755 "$BUILDX_DOWNLOAD" "$BUILDX_PLUGIN"',
            'test -f "$BUILDX_PLUGIN" && test ! -L "$BUILDX_PLUGIN"',
            (
                'EXPECTED_BUILDX="github.com/docker/buildx '
                '${BUILDX_VERSION} ${BUILDX_REVISION}"'
            ),
            'test "$("$BUILDX_PLUGIN" version)" = "$EXPECTED_BUILDX"',
            'test "$(docker buildx version)" = "$EXPECTED_BUILDX"',
            'printf \'%s\\n\' "DOCKER_CONFIG=$DOCKER_CONFIG" >> "$GITHUB_ENV"',
        )
    )
    if install_script != expected_install_script:
        raise WorkflowPolicyError(
            f"{label} must use the exact hash-before-execution Buildx installation"
        )

    if re.search(r"(?m)^\s+install\s*:", step):
        raise WorkflowPolicyError(
            f"{label} must not install the deprecated docker build alias"
        )
    if re.search(r"(?m)^\s+(?:version|cache-binary)\s*:", step):
        raise WorkflowPolicyError(
            f"{label} setup action must not download or cache an alternate Buildx binary"
        )
    driver = re.findall(r"(?m)^          driver:\s*(\S+)\s*$", step)
    if driver != ["docker-container"]:
        raise WorkflowPolicyError(
            f"{label} must use the docker-container Buildx driver"
        )

    driver_options_match = re.search(
        r"(?m)^          driver-opts: \|\n((?:            [^\n]*\n?)*)",
        step,
    )
    if driver_options_match is None:
        raise WorkflowPolicyError(
            f"{label} must use the reviewed multiline driver-opts grammar"
        )
    driver_options = [
        line.strip()
        for line in driver_options_match.group(1).splitlines()
        if line.strip()
    ]
    image_options = [
        option.removeprefix("image=")
        for option in driver_options
        if option.startswith("image=")
    ]
    if len(image_options) != 1:
        raise WorkflowPolicyError(f"{label} must configure exactly one BuildKit image")
    image = image_options[0]
    if not re.fullmatch(r"moby/buildkit@sha256:[0-9a-f]{64}", image):
        raise WorkflowPolicyError(
            f"{label} BuildKit image must use an immutable sha256 digest"
        )
    if image != EXPECTED_BUILDKIT_IMAGE:
        raise WorkflowPolicyError(
            f"{label} BuildKit image differs from the approved digest"
        )
    if driver_options != [f"image={EXPECTED_BUILDKIT_IMAGE}", "network=bridge"]:
        raise WorkflowPolicyError(
            f"{label} contains an unreviewed Buildx driver option"
        )

    buildkitd_flags = re.findall(
        r"(?m)^          buildkitd-flags:\s*(\S.*)\s*$",
        step,
    )
    if buildkitd_flags != [EXPECTED_BUILDKITD_FLAGS]:
        raise WorkflowPolicyError(
            f"{label} must explicitly reset BuildKit defaults with safe daemon flags"
        )

    action_inputs = re.findall(
        r"(?m)^          ([a-z][a-z0-9-]*):(?:\s.*)?$",
        step,
    )
    if action_inputs != ["driver", "driver-opts", "buildkitd-flags"]:
        raise WorkflowPolicyError(
            f"{label} Buildx action inputs differ from the reviewed grammar"
        )


def _verify_common(source: str, label: str) -> None:
    _require(
        source,
        (
            "on:\n  workflow_call:",
            "permissions:",
            "contents: read",
        ),
        label,
    )
    forbidden = (
        "pull_request_target:",
        "secrets: inherit",
        "continue-on-error:",
        "workflow_call:\n    inputs:\n      execute",
    )
    for fragment in forbidden:
        if fragment in source:
            raise WorkflowPolicyError(f"{label} contains forbidden grammar: {fragment}")


def _verify_security_app_bridge(source: str) -> None:
    secret_block_match = re.search(
        r"(?ms)^  workflow_call:\n    secrets:\n"
        r"(?P<body>.*?)^permissions:\n",
        source,
    )
    if secret_block_match is None:
        raise WorkflowPolicyError(
            "security workflow GitHub App secret contract is missing"
        )
    secret_block = secret_block_match.group("body")
    secret_names = re.findall(r"(?m)^      ([a-z][a-z0-9_]+):\s*$", secret_block)
    if secret_names != [
        "static_ui_bridge_app_id",
        "static_ui_bridge_app_private_key",
    ]:
        raise WorkflowPolicyError(
            "security workflow must accept only the two named GitHub App secrets"
        )
    if secret_block.count("        required: false") != 2:
        raise WorkflowPolicyError(
            "security workflow GitHub App secrets must remain optional for other callers"
        )

    starts = [match.start() for match in re.finditer(r"(?m)^      - ", source)]
    steps = [
        source[start : starts[index + 1] if index + 1 < len(starts) else len(source)]
        for index, start in enumerate(starts)
    ]
    token_steps = [
        step
        for step in steps
        if "uses: actions/create-github-app-token@" in step
    ]
    if len(token_steps) != 1:
        raise WorkflowPolicyError(
            "security workflow must mint exactly one GitHub App token"
        )
    token_step = token_steps[0]
    required_token_step = (
        "name: Mint the exact website and Beacon read token",
        "id: static-ui-bridge-token",
        "if: ${{ github.repository == 'cognitum-one/website' }}",
        (
            "uses: actions/create-github-app-token@"
            "bcd2ba49218906704ab6c1aa796996da409d3eb1"
        ),
        "app-id: ${{ secrets.static_ui_bridge_app_id }}",
        "private-key: ${{ secrets.static_ui_bridge_app_private_key }}",
        "owner: cognitum-one",
        "repositories: |\n            website\n            beacon",
        "permission-contents: read",
    )
    _require(token_step, required_token_step, "security GitHub App token step")
    inputs = re.findall(
        r"(?m)^          ([a-z][a-z0-9-]*):(?:\s.*)?$",
        token_step,
    )
    if inputs != [
        "app-id",
        "private-key",
        "owner",
        "repositories",
        "permission-contents",
    ]:
        raise WorkflowPolicyError(
            "security GitHub App token inputs differ from the reviewed grammar"
        )
    repositories_match = re.search(
        r"(?m)^          repositories: \|\n"
        r"((?:            [^\n]*\n?)*)",
        token_step,
    )
    repositories = (
        [
            line.strip()
            for line in repositories_match.group(1).splitlines()
            if line.strip()
        ]
        if repositories_match is not None
        else []
    )
    if repositories != ["website", "beacon"]:
        raise WorkflowPolicyError(
            "security GitHub App token repository set differs from website and Beacon"
        )
    if "env:" in token_step or "skip-token-revoke" in token_step:
        raise WorkflowPolicyError(
            "security GitHub App credentials may only enter the pinned action"
        )

    app_id = "${{ secrets.static_ui_bridge_app_id }}"
    private_key = "${{ secrets.static_ui_bridge_app_private_key }}"
    if source.count(app_id) != 1 or source.count(private_key) != 1:
        raise WorkflowPolicyError(
            "security GitHub App credentials escaped their one minting step"
        )
    legacy_fragments = (
        "static_ui_beacon_read_token",
        "STATIC_UI_BEACON_READ_TOKEN",
        "permission-contents: write",
        "repositories: '*'",
    )
    for fragment in legacy_fragments:
        if fragment in source:
            raise WorkflowPolicyError(
                f"security GitHub App bridge contains forbidden grammar: {fragment}"
            )

    beacon_steps = [
        step
        for step in steps
        if "name: Checkout the exact Beacon submodule source outside the candidate"
        in step
    ]
    runtime_steps = [
        step
        for step in steps
        if "name: Build and verify the committed static-UI runtime" in step
    ]
    if len(beacon_steps) != 1 or len(runtime_steps) != 1:
        raise WorkflowPolicyError(
            "security GitHub App token consumers differ from the reviewed steps"
        )
    beacon_step = beacon_steps[0]
    runtime_step = runtime_steps[0]
    token_output = "${{ steps.static-ui-bridge-token.outputs.token }}"
    if source.count(token_output) != 2:
        raise WorkflowPolicyError(
            "security GitHub App token must reach only Beacon checkout and runtime proof"
        )
    _require(
        beacon_step,
        (
            "if: ${{ github.repository == 'cognitum-one/website' }}",
            f"GH_TOKEN: {token_output}",
            'ASKPASS="$RUNNER_TEMP/static-ui-beacon-askpass.sh"',
            "trap cleanup_beacon_credentials EXIT",
            "'  *Username*) printf \"%s\\n\" x-access-token ;;'",
            "'  *Password*) printf \"%s\\n\" \"$GH_TOKEN\" ;;'",
            'chmod 0700 "$ASKPASS"',
            'GIT_ASKPASS="$ASKPASS" GIT_TERMINAL_PROMPT=0',
            "git -c credential.helper= clone",
            "https://github.com/cognitum-one/beacon.git",
            'git -C "$BEACON_ROOT" -c credential.helper=',
        ),
        "security Beacon checkout step",
    )
    if (
        "gh repo clone" in beacon_step
        or "https://x-access-token:" in beacon_step
        or "credential.helper store" in beacon_step
    ):
        raise WorkflowPolicyError(
            "security Beacon checkout must use the ephemeral askpass boundary"
        )
    askpass_boundary = 'GIT_ASKPASS="$ASKPASS" GIT_TERMINAL_PROMPT=0'
    if (
        beacon_step.count(askpass_boundary) != 3
        or beacon_step.count(
            'git -C "$BEACON_ROOT" -c credential.helper='
        )
        != 2
    ):
        raise WorkflowPolicyError(
            "security Beacon clone, fetch, and partial-clone checkout must all "
            "use the ephemeral askpass boundary"
        )
    _require(
        runtime_step,
        (
            f"STATIC_UI_BRIDGE_TOKEN: {token_output}",
            (
                "STATIC_UI_MANAGEMENT_TOKEN: "
                "${{ github.repository == 'cognitum-one/management' "
                "&& github.token || '' }}"
            ),
            'case "$GITHUB_REPOSITORY" in',
            "cognitum-one/website)",
            'STATIC_UI_IDENTITY_TOKEN="$STATIC_UI_BRIDGE_TOKEN"',
            "cognitum-one/management)",
            'STATIC_UI_IDENTITY_TOKEN="$STATIC_UI_MANAGEMENT_TOKEN"',
            "unset STATIC_UI_BRIDGE_TOKEN STATIC_UI_MANAGEMENT_TOKEN",
            'GH_TOKEN="$STATIC_UI_IDENTITY_TOKEN"',
        ),
        "security runtime identity step",
    )
    if (
        "github.repository == 'cognitum-one/website' && github.token"
        in runtime_step
        or "secrets.static_ui_bridge_app_" in runtime_step
    ):
        raise WorkflowPolicyError(
            "website runtime proof must not fall back or receive App credentials"
        )
    _require_order(
        source,
        (
            "Mint the exact website and Beacon read token",
            "Checkout the exact Beacon submodule source outside the candidate",
            "Build and verify the committed static-UI runtime",
        ),
        "security GitHub App bridge",
    )


def _verify_security(source: str) -> None:
    _verify_common(source, "security workflow")
    _verify_trusted_buildkit(source, "security workflow")
    _verify_security_app_bridge(source)
    required = (
        "static_ui_bridge_app_id:",
        "static_ui_bridge_app_private_key:",
        "fetch-depth: 0",
        "persist-credentials: false",
        "deps:\n    name: dependency scan (OSV, fail on High+ fixable)\n"
        "    runs-on: ${{ github.event.repository.visibility == 'public' "
        "&& 'ubuntu-latest' || fromJSON('[\"self-hosted\",\"gcp-bypass\"]') }}",
        "static-ui-runtime-profiles.json",
        "static_ui_runtime_receipt.py",
        "test_static_ui_runtime_receipt.py",
        'python3 "$POLICY_DIR/test_osv_gate.py"',
        'python3 "$POLICY_DIR/test_run_osv_scan.py"',
        'python3 "$POLICY_DIR/test_static_ui_runtime_receipt.py"',
        'openssl rand -hex 32 > "$NONCE_DIR/nonce"',
        '--receipt-nonce-file "$NONCE_DIR/nonce"',
        "--mode premerge",
        'rm -f -- "$OUTPUT_DIR/management-vite.env"',
        "REPOSITORY_VISIBILITY: ${{ github.event.repository.visibility }}",
        "STATIC_UI_BRIDGE_TOKEN: ${{ steps.static-ui-bridge-token.outputs.token }}",
        "STATIC_UI_MANAGEMENT_TOKEN: ${{ github.repository == 'cognitum-one/management' && github.token || '' }}",
        'test -n "$STATIC_UI_IDENTITY_TOKEN"',
        'GH_TOKEN="$STATIC_UI_IDENTITY_TOKEN"',
        'GITHUB_REPOSITORY_VISIBILITY="$REPOSITORY_VISIBILITY"',
        'OSV_RUNTIME_RECEIPT="${{ steps.runtime.outputs.receipt }}"',
        'OSV_RUNTIME_INVENTORY="${{ steps.runtime.outputs.inventory }}"',
        'OSV_RUNTIME_NONCE="${{ steps.runtime.outputs.nonce }}"',
        'OSV_RUNTIME_IMAGE_NAME="${{ steps.runtime.outputs.image_name }}"',
        'OSV_RUNTIME_IMAGE_ID="${{ steps.runtime.outputs.image_id }}"',
        'GITHUB_REPOSITORY="$GITHUB_REPOSITORY"',
        'GITHUB_SHA="$GITHUB_SHA"',
        'GITHUB_RUN_ID="$GITHUB_RUN_ID"',
        'GITHUB_RUN_ATTEMPT="$GITHUB_RUN_ATTEMPT"',
        'GITHUB_JOB="$GITHUB_JOB"',
        'GITHUB_WORKFLOW_REF="$GITHUB_WORKFLOW_REF"',
        'GITHUB_WORKFLOW_SHA="$GITHUB_WORKFLOW_SHA"',
        'python3 "$POLICY_DIR/osv_gate.py"',
    )
    _require(source, required, "security workflow")
    _require_order(
        source,
        (
            "Fetch and self-test the immutable organization OSV gate",
            'python3 "$POLICY_DIR/test_static_ui_runtime_receipt.py"',
            "Build and verify the committed static-UI runtime",
            "Run OSV-Scanner",
            'python3 "$POLICY_DIR/osv_gate.py"',
        ),
        "security workflow",
    )
    if source.count('python3 "$POLICY_DIR/osv_gate.py"') != 1:
        raise WorkflowPolicyError("security workflow must invoke the OSV gate once")
    if "google-github-actions/auth@" in source or "gcloud secrets" in source:
        raise WorkflowPolicyError(
            "premerge runtime proof must not authenticate to Secret Manager"
        )
    _verify_hash_checks(
        source,
        "security workflow",
        tuple(name for name in EXPECTED_ORG_POLICY if name != "OSV_POLICY_COMMIT"),
    )


def _verify_release(source: str, allow_unresolved_self_pin: bool) -> None:
    _verify_common(source, "release workflow")
    _verify_trusted_buildkit(source, "release workflow")
    # The security scan has required the ephemeral askpass boundary since the App
    # bridge landed, but this workflow was not covered and kept the original
    # `gh repo clone` followed by a bare `git fetch`. `gh` authenticates the clone
    # through its own credential path and leaves a plain https remote behind, so
    # with `--filter=blob:none --no-checkout` the fetch that actually retrieves
    # the objects ran unauthenticated. Requiring the boundary here stops that
    # shape returning to this file the way it survived the last migration.
    if (
        "gh repo clone" in source
        or "https://x-access-token:" in source
        or "credential.helper store" in source
    ):
        raise WorkflowPolicyError(
            "release Beacon checkout must use the ephemeral askpass boundary"
        )
    askpass_boundary = 'GIT_ASKPASS="$ASKPASS" GIT_TERMINAL_PROMPT=0'
    if source.count(askpass_boundary) != 3 or source.count(
        'git -C "$BEACON_ROOT" -c credential.helper='
    ) != 2:
        raise WorkflowPolicyError(
            "release Beacon clone, fetch, and partial-clone checkout must all "
            "use the ephemeral askpass boundary"
        )
    for fragment in (
        "static_ui_beacon_read_token",
        "STATIC_UI_BEACON_READ_TOKEN",
        "permission-contents: write",
        "repositories: '*'",
    ):
        if fragment in source:
            raise WorkflowPolicyError(
                f"release workflow retains a legacy credential grammar: {fragment}"
            )
    required = (
        "attestations: write",
        "id-token: write",
        "environment: staging",
        "persist-credentials: false",
        "runs-on: ubuntu-24.04",
        "projects/186366152200/locations/global/workloadIdentityPools/github-website-frontend-stg/providers/github-main",
        "website-frontend-deploy-stg@cognitum-20260110.iam.gserviceaccount.com",
        "projects/186366152200/locations/global/workloadIdentityPools/github-management-stg/providers/github-main",
        "management-ui-deploy-stg@cognitum-20260110.iam.gserviceaccount.com",
        'test "$WIF_PROVIDER" = "$EXPECTED_WIF_PROVIDER"',
        'test "$BUILDER_SERVICE_ACCOUNT" = "$EXPECTED_BUILDER_SERVICE_ACCOUNT"',
        'test "$SOURCE_REF" = "refs/heads/main"',
        'test "$WORKFLOW_SHA" = "$SOURCE_SHA"',
        "static_ui_release_gate.py",
        "test_static_ui_release_gate.py",
        'python3 "$POLICY_DIR/test_osv_gate.py"',
        'python3 "$POLICY_DIR/test_run_osv_scan.py"',
        'python3 "$POLICY_DIR/test_static_ui_runtime_receipt.py"',
        'python3 "$POLICY_DIR/test_static_ui_release_gate.py"',
        'openssl rand -hex 32 > "$NONCE_DIR/nonce"',
        '--receipt-nonce-file "$NONCE"',
        "--mode release",
        'rm -f -- "$OUTPUT_DIR/management-vite.env"',
        "REPOSITORY_VISIBILITY: ${{ github.event.repository.visibility }}",
        # The release workflow derives its identity token the same way the
        # security scan does: from the scoped GitHub App bridge, selected in
        # shell rather than interpolated. It previously required
        # `secrets.static_ui_beacon_read_token`, which no longer exists on any
        # caller, so for cognitum-one/website that expression resolved to the
        # empty string instead of falling through to github.token.
        "STATIC_UI_BRIDGE_TOKEN: ${{ steps.static-ui-bridge-token.outputs.token }}",
        "STATIC_UI_MANAGEMENT_TOKEN: ${{ github.repository == 'cognitum-one/management' && github.token || '' }}",
        'STATIC_UI_IDENTITY_TOKEN="$STATIC_UI_BRIDGE_TOKEN"',
        'STATIC_UI_IDENTITY_TOKEN="$STATIC_UI_MANAGEMENT_TOKEN"',
        "unset STATIC_UI_BRIDGE_TOKEN STATIC_UI_MANAGEMENT_TOKEN",
        'test -n "$STATIC_UI_IDENTITY_TOKEN"',
        'GH_TOKEN="$STATIC_UI_IDENTITY_TOKEN"',
        'GITHUB_REPOSITORY_VISIBILITY="$REPOSITORY_VISIBILITY"',
        "inventory \\",
        '--image-digest "$IMAGE_DIGEST"',
        '--expected-inventory "$OUTPUT_DIR/rootfs-inventory.json"',
        '--output "$OUTPUT_DIR/exact-digest-rootfs-inventory.json"',
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
        "job_workflow_ref",
        "job_workflow_sha",
        'payload.get("repository_id") != os.environ["GITHUB_REPOSITORY_ID"]',
        'payload.get("repository_owner_id")',
        '!= os.environ["GITHUB_REPOSITORY_OWNER_ID"]',
        'payload.get("repository_visibility")',
        '!= os.environ["REPOSITORY_VISIBILITY"]',
        'payload.get("run_id") != os.environ["GITHUB_RUN_ID"]',
        'payload.get("run_attempt") != os.environ["GITHUB_RUN_ATTEMPT"]',
        'payload.get("event_name") != os.environ["GITHUB_EVENT_NAME"]',
        'payload.get("workflow_ref") != os.environ["GITHUB_WORKFLOW_REF"]',
        'payload.get("workflow_sha") != os.environ["GITHUB_WORKFLOW_SHA"]',
        'payload.get("runner_environment") != "github-hosted"',
        "uses: actions/attest@f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6",
        "subject-name: ${{ steps.subject.outputs.image_name }}",
        "subject-digest: ${{ steps.subject.outputs.image_digest }}",
        "predicate-type: ${{ env.STATIC_UI_PREDICATE_TYPE }}",
        "predicate-path: ${{ steps.build.outputs.output }}/static-ui-runtime-receipt.json",
        'gh attestation verify "oci://$IMAGE"',
        '--bundle "$BUNDLE"',
        '--repo "$GITHUB_REPOSITORY"',
        '--predicate-type "$STATIC_UI_PREDICATE_TYPE"',
        '--signer-workflow "$SIGNER_WORKFLOW"',
        '--signer-digest "$SIGNER_DIGEST"',
        '--source-digest "$GITHUB_SHA"',
        "--source-ref refs/heads/main",
        "--deny-self-hosted-runners",
        "--format json",
        "attestation \\",
        '--inventory "$OUTPUT_DIR/exact-digest-rootfs-inventory.json"',
        '--caller-workflow-ref "$GITHUB_WORKFLOW_REF"',
        '--caller-workflow-sha "$GITHUB_WORKFLOW_SHA"',
        "verified-release-attestation.json",
    )
    _require(source, required, "release workflow")
    _require_order(
        source,
        (
            "Build and push current main with the exact org grammar",
            "Re-inventory the exact pushed OCI digest",
            "Sign the exact runtime receipt",
            "gh attestation verify",
            'static_ui_release_gate.py" attestation',
            "Upload verified non-secret release evidence",
        ),
        "release workflow",
    )
    for fragment, expected_count in (
        ('--signer-workflow "$SIGNER_WORKFLOW"', 2),
        ('--signer-digest "$SIGNER_DIGEST"', 2),
        ('--source-digest "$GITHUB_SHA"', 1),
        ('--bundle "$BUNDLE"', 1),
    ):
        if source.count(fragment) != expected_count:
            raise WorkflowPolicyError(
                f"release workflow requires {expected_count} exact {fragment} occurrence(s)"
            )
    prohibited = (
        "packages: write",
        "gcloud run deploy",
        "gcloud run services update",
        "gcloud run services update-traffic",
        "gcloud iam",
        "gcloud projects add-iam-policy-binding",
        "gcloud secrets versions add",
        "gcloud secrets create",
        "--allow-unauthenticated",
    )
    for fragment in prohibited:
        if fragment in source:
            raise WorkflowPolicyError(
                f"release workflow contains forbidden mutation: {fragment}"
            )
    pin = _environment(source).get("STATIC_UI_WORKFLOW_COMMIT")
    if not pin or not SHA1_RE.fullmatch(pin):
        raise WorkflowPolicyError("release workflow self-pin is malformed")
    if pin == ZERO_SHA and not allow_unresolved_self_pin:
        raise WorkflowPolicyError("release workflow self-pin is unresolved")
    _verify_hash_checks(
        source,
        "release workflow",
        tuple(POLICY_ARTIFACTS),
    )


def _verify_revision(source: str, allow_unresolved_self_pin: bool) -> None:
    _verify_common(source, "revision workflow")
    required = (
        "expected_image:",
        "expected_revision:",
        "expected_spec_digest:",
        "expected_environment_json:",
        "static_ui_verifier_wif_provider:",
        "static_ui_verifier_service_account:",
        "environment: staging",
        "runs-on: ubuntu-24.04",
        "website-release-verify-stg@cognitum-20260110.iam.gserviceaccount.com",
        "management-ui-release-verify-stg@cognitum-20260110.iam.gserviceaccount.com",
        'test "$WIF_PROVIDER" = "$EXPECTED_WIF_PROVIDER"',
        'test "$VERIFIER_SERVICE_ACCOUNT" = "$EXPECTED_VERIFIER_SERVICE_ACCOUNT"',
        'test "$SOURCE_REF" = "refs/heads/main"',
        "cognitum-dashboard-staging",
        "website-runtime-stg@cognitum-20260110.iam.gserviceaccount.com",
        "cognitum-manage-staging",
        "management-runtime-stg@cognitum-20260110.iam.gserviceaccount.com",
        "internal-and-cloud-load-balancing",
        'gcloud run revisions describe "$REVISION"',
        'gcloud run services describe "$SERVICE"',
        'static_ui_release_gate.py" service',
        '--expected-environment "$EVIDENCE_DIR/expected-environment.json"',
        '--expected-service-account "$SERVICE_ACCOUNT"',
        '--expected-spec-digest "$SPEC_DIGEST"',
        '--expected-ingress "$INGRESS"',
        "verified-cloud-run-release.json",
    )
    _require(source, required, "revision workflow")
    _require_order(
        source,
        (
            "Resolve the organization-owned staging target",
            "Read the exact revision and service",
            "Verify revision, service, environment, ingress, and traffic",
            "Upload immutable revision evidence",
        ),
        "revision workflow",
    )
    allowed_gcloud = re.findall(r"gcloud run [^\n\\]+", source)
    if sorted(item.strip() for item in allowed_gcloud) != sorted(
        [
            'gcloud run revisions describe "$REVISION"',
            'gcloud run services describe "$SERVICE"',
        ]
    ):
        raise WorkflowPolicyError(
            f"revision workflow has non-read-only Cloud Run grammar: {allowed_gcloud}"
        )
    prohibited = (
        "gcloud iam",
        "gcloud secrets",
        "update-traffic",
        " run deploy ",
        "allow-unauthenticated",
    )
    for fragment in prohibited:
        if fragment in source:
            raise WorkflowPolicyError(
                f"revision workflow contains forbidden mutation: {fragment}"
            )
    pin = _environment(source).get("STATIC_UI_WORKFLOW_COMMIT")
    if not pin or not SHA1_RE.fullmatch(pin):
        raise WorkflowPolicyError("revision workflow self-pin is malformed")
    if pin == ZERO_SHA and not allow_unresolved_self_pin:
        raise WorkflowPolicyError("revision workflow self-pin is unresolved")
    _verify_hash_checks(
        source,
        "revision workflow",
        (
            "STATIC_UI_PROFILES_SHA256",
            "STATIC_UI_RECEIPT_SHA256",
            "STATIC_UI_RELEASE_GATE_SHA256",
        ),
    )


def _verify_template(
    source: str, expected_pin: str, allow_unresolved_self_pin: bool
) -> None:
    _require(
        source,
        (
            "permissions:\n  contents: read",
            "permissions:\n      contents: read",
            # The template must map what security-scan.yml actually declares.
            # It mapped `static_ui_beacon_read_token` until 2026-07-30 -- a name
            # the reusable workflow stopped declaring when the App bridge landed.
            # Passing an undeclared secret is an "Invalid workflow file" error,
            # not a soft failure, so any caller conforming to the template was
            # broken. cognitum-one/website hit exactly this and had to diverge
            # from the template deliberately (website#331).
            "static_ui_bridge_app_id: ${{ secrets.STATIC_UI_BRIDGE_APP_ID }}",
            "static_ui_bridge_app_private_key: ${{ secrets.STATIC_UI_BRIDGE_APP_KEY }}",
        ),
        "security caller template",
    )
    for fragment in ("static_ui_beacon_read_token", "STATIC_UI_BEACON_READ_TOKEN"):
        if fragment in source:
            raise WorkflowPolicyError(
                f"security caller template retains a removed secret: {fragment}"
            )
    match = re.search(
        r"uses:\s*cognitum-one/\.github/\.github/workflows/"
        r"security-scan\.yml@([0-9a-f]{40})",
        source,
    )
    if not match:
        raise WorkflowPolicyError("security caller template is not full-SHA pinned")
    pin = match.group(1)
    if pin != expected_pin:
        raise WorkflowPolicyError("security caller template and PR2 pin differ")
    if pin == ZERO_SHA and not allow_unresolved_self_pin:
        raise WorkflowPolicyError("security caller template pin is unresolved")


def _verify_selftest(source: str) -> None:
    _require(
        source,
        (
            "on:\n  pull_request:",
            "permissions:\n  contents: read",
            "persist-credentials: false",
            "runs-on: ubuntu-24.04",
            "python3 security/test_osv_gate.py",
            "python3 security/test_run_osv_scan.py",
            "python3 security/test_static_ui_runtime_receipt.py",
            "python3 security/test_static_ui_release_gate.py",
            "python3 security/test_verify_static_ui_workflows.py",
            "python3 security/verify_static_ui_workflows.py",
            "python3 security/test_security_policy.py",
            "python3 security/test_security_release_workflow.py",
            "python3 -m json.tool workflow-templates/security.properties.json >/dev/null",
            "python3 -m json.tool security/security-policy-v1.json >/dev/null",
            'ACTIONLINT_VERSION: "1.7.12"',
            'ACTIONLINT_SHA256: "8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8"',
            'echo "${ACTIONLINT_SHA256}  ${ARCHIVE}" | sha256sum -c -',
            "-shellcheck shellcheck",
            ".github/workflows/security-scan.yml",
            ".github/workflows/security-release.yml",
            ".github/workflows/static-ui-release.yml",
            ".github/workflows/static-ui-revision.yml",
            ".github/workflows/static-ui-policy-selftest.yml",
            "workflow-templates/security.yml",
        ),
        "policy selftest workflow",
    )
    _require_order(
        source,
        (
            "Run every organization policy test directly",
            "python3 security/test_osv_gate.py",
            "python3 security/test_verify_static_ui_workflows.py",
            "python3 security/verify_static_ui_workflows.py",
            "Run hash-verified actionlint and ShellCheck",
            'echo "${ACTIONLINT_SHA256}  ${ARCHIVE}" | sha256sum -c -',
        ),
        "policy selftest workflow",
    )
    if "--allow-unresolved-self-pin" in source:
        raise WorkflowPolicyError("branch selftest must enforce resolved PR2 pins")
    for path in (
        '"workflow-templates/security.yml"',
        '"workflow-templates/security.properties.json"',
    ):
        if source.count(path) != 2:
            raise WorkflowPolicyError(
                f"policy selftest must trigger exactly on both changes to {path}"
            )


def verify(
    *,
    security_path: Path,
    release_path: Path,
    revision_path: Path,
    selftest_path: Path,
    template_path: Path,
    release_gate_path: Path,
    release_gate_test_path: Path,
    allow_unresolved_self_pin: bool = False,
) -> None:
    security = _read(security_path, "security workflow")
    release = _read(release_path, "release workflow")
    revision = _read(revision_path, "revision workflow")
    selftest = _read(selftest_path, "policy selftest workflow")
    template = _read(template_path, "security caller template")
    release_gate = _read(release_gate_path, "release gate")
    release_gate_test = _read(release_gate_test_path, "release gate test")
    _verify_actions(security, release, revision, selftest)
    _verify_security(security)
    _verify_release(release, allow_unresolved_self_pin)
    _verify_revision(revision, allow_unresolved_self_pin)
    _verify_selftest(selftest)

    environments = [_environment(source) for source in (security, release, revision)]
    security_environment, release_environment, revision_environment = environments
    required_policy_keys = (
        ("security workflow", security_environment, tuple(EXPECTED_ORG_POLICY)),
        ("release workflow", release_environment, tuple(EXPECTED_ORG_POLICY)),
        (
            "revision workflow",
            revision_environment,
            (
                "OSV_POLICY_COMMIT",
                "STATIC_UI_PROFILES_SHA256",
                "STATIC_UI_RECEIPT_SHA256",
            ),
        ),
    )
    for label, environment, keys in required_policy_keys:
        for key in keys:
            if environment.get(key) != EXPECTED_ORG_POLICY[key]:
                raise WorkflowPolicyError(
                    f"{label} differs from approved organization policy: {key}"
                )

    workflow_pin = release_environment["STATIC_UI_WORKFLOW_COMMIT"]
    if revision_environment.get("STATIC_UI_WORKFLOW_COMMIT") != workflow_pin:
        raise WorkflowPolicyError("release and revision workflow self-pins differ")
    _verify_template(template, workflow_pin, allow_unresolved_self_pin)
    policy_commits = {value.get("OSV_POLICY_COMMIT") for value in environments}
    if len(policy_commits) != 1 or not SHA1_RE.fullmatch(
        next(iter(policy_commits)) or ""
    ):
        raise WorkflowPolicyError("workflows do not share one immutable policy pin")
    shared_hashes = ("STATIC_UI_PROFILES_SHA256", "STATIC_UI_RECEIPT_SHA256")
    for name in shared_hashes:
        values = {value.get(name) for value in environments}
        if len(values) != 1 or not SHA256_RE.fullmatch(next(iter(values)) or ""):
            raise WorkflowPolicyError(f"workflows disagree on {name}")
    for name, value in _environment(release).items():
        if name.endswith("_SHA256") and not SHA256_RE.fullmatch(value):
            raise WorkflowPolicyError(f"release workflow hash is malformed: {name}")
    release_gate_digest = hashlib.sha256(release_gate.encode("utf-8")).hexdigest()
    release_gate_test_digest = hashlib.sha256(
        release_gate_test.encode("utf-8")
    ).hexdigest()
    if (
        release_environment.get("STATIC_UI_RELEASE_GATE_SHA256") != release_gate_digest
        or revision_environment.get("STATIC_UI_RELEASE_GATE_SHA256")
        != release_gate_digest
        or release_environment.get("STATIC_UI_RELEASE_GATE_TEST_SHA256")
        != release_gate_test_digest
    ):
        raise WorkflowPolicyError(
            "release workflow companion hashes differ from committed bytes"
        )
    if "gcloud " in release_gate:
        raise WorkflowPolicyError("release evidence gate must not execute gcloud")
    _require(
        release_gate,
        (
            '["docker", "image", "pull", "--platform", "linux/amd64", image_ref]',
            "_docker_rootfs_inventory(image_ref, profile)",
            'statement.get("predicate") != receipt',
            "validate_revision(",
            'revision.get("status", {}).get("imageDigest") != expected_image',
            "Cloud Run revision environment differs from the contract",
            "Cloud Run ingress differs",
            "Cloud Run serving traffic differs from the exact revision",
        ),
        "release gate",
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    root = Path(__file__).resolve().parents[1]
    parser.add_argument(
        "--security-workflow",
        type=Path,
        default=root / ".github/workflows/security-scan.yml",
    )
    parser.add_argument(
        "--release-workflow",
        type=Path,
        default=root / ".github/workflows/static-ui-release.yml",
    )
    parser.add_argument(
        "--revision-workflow",
        type=Path,
        default=root / ".github/workflows/static-ui-revision.yml",
    )
    parser.add_argument(
        "--selftest-workflow",
        type=Path,
        default=root / ".github/workflows/static-ui-policy-selftest.yml",
    )
    parser.add_argument(
        "--release-gate",
        type=Path,
        default=root / "security/static_ui_release_gate.py",
    )
    parser.add_argument(
        "--release-gate-test",
        type=Path,
        default=root / "security/test_static_ui_release_gate.py",
    )
    parser.add_argument(
        "--security-template",
        type=Path,
        default=root / "workflow-templates/security.yml",
    )
    parser.add_argument(
        "--allow-unresolved-self-pin",
        action="store_true",
        help="PR-only bootstrap; never use in the final branch check",
    )
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    try:
        verify_local_policy_artifacts(Path(__file__).resolve().parent)
        verify(
            security_path=arguments.security_workflow,
            release_path=arguments.release_workflow,
            revision_path=arguments.revision_workflow,
            selftest_path=arguments.selftest_workflow,
            template_path=arguments.security_template,
            release_gate_path=arguments.release_gate,
            release_gate_test_path=arguments.release_gate_test,
            allow_unresolved_self_pin=arguments.allow_unresolved_self_pin,
        )
    except (OSError, UnicodeError, ValueError, TypeError) as error:
        print(f"static-ui-workflow-policy: FAIL: {error}", file=sys.stderr)
        return 2
    print("static-ui-workflow-policy: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
