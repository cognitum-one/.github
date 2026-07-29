#!/usr/bin/env python3
"""Release-only gates layered on the static UI runtime receipt.

The trusted builder lives in ``static_ui_runtime_receipt.py``.  This companion
keeps the release workflow small while enforcing three properties that are
outside a pre-merge receipt:

* the root filesystem is re-inventoried from the exact pushed OCI digest;
* the verified GitHub attestation statement contains the exact receipt; and
* a Cloud Run Revision and its Service/traffic record match the approved image.

Every input is treated as untrusted.  JSON is parsed with duplicate-key and
non-finite-number rejection, outputs are create-only, and no command in this
module mutates Cloud Run, IAM, Secret Manager, or traffic.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any

from static_ui_runtime_receipt import (
    PREDICATE_TYPE,
    PolicyError,
    _canonical_bytes,
    _docker_image_inspect,
    _docker_rootfs_inventory,
    _sha256_bytes,
    _trusted_docker_environment,
    _validate_inventory_document,
    load_policy,
    profile_for,
    validate_revision,
    verify_receipt,
)

SHA1_RE = re.compile(r"[0-9a-f]{40}")
SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}")
IMAGE_NAME_RE = re.compile(
    r"[a-z0-9][a-z0-9.-]*(?::[0-9]+)?" r"(?:/[a-z0-9][a-z0-9._-]*){2,}"
)
WORKFLOW_RE = re.compile(
    r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/\.github/workflows/" r"[A-Za-z0-9_.-]+\.ya?ml"
)
INGRESS_VALUES = {"all", "internal", "internal-and-cloud-load-balancing"}
MAX_JSON_BYTES = 512 * 1024 * 1024


def _strict_json_loads(source: str) -> Any:
    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise PolicyError(f"duplicate JSON key: {key}")
            value[key] = item
        return value

    def reject_constant(value: str) -> None:
        raise PolicyError(f"non-finite JSON constant: {value}")

    return json.loads(
        source,
        object_pairs_hook=object_pairs,
        parse_constant=reject_constant,
    )


def _read_json(path: Path, label: str) -> Any:
    if path.is_symlink() or not path.is_file():
        raise PolicyError(f"{label} must be a non-symlink regular file")
    size = path.stat().st_size
    if size <= 0 or size > MAX_JSON_BYTES:
        raise PolicyError(f"{label} has an invalid size")
    try:
        return _strict_json_loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise PolicyError(f"{label} is unreadable or malformed: {error}") from error


def _write_json(path: Path, value: Any) -> None:
    if path.exists() or path.is_symlink():
        raise PolicyError(f"output already exists: {path}")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2, sort_keys=True, ensure_ascii=False)
        stream.write("\n")


def _condition_ready(document: dict[str, Any], label: str) -> None:
    conditions = document.get("status", {}).get("conditions")
    if not isinstance(conditions, list) or not conditions:
        raise PolicyError(f"{label} Ready condition is absent")
    ready = [
        item
        for item in conditions
        if isinstance(item, dict) and item.get("type") == "Ready"
    ]
    if len(ready) != 1 or ready[0].get("status") not in (True, "True"):
        raise PolicyError(f"{label} is not uniquely Ready=True")


def _validate_environment_contract(expected: Any, actual: list[dict[str, Any]]) -> None:
    if not isinstance(expected, list):
        raise PolicyError("expected environment evidence must be an array")
    names: list[str] = []
    for record in expected:
        if not isinstance(record, dict) or not isinstance(record.get("name"), str):
            raise PolicyError("expected environment evidence is malformed")
        if set(record) == {"name", "source", "valueDigest"}:
            if record["source"] != "value" or not SHA256_RE.fullmatch(
                str(record["valueDigest"])
            ):
                raise PolicyError("expected literal environment evidence is malformed")
        elif set(record) == {"name", "source", "secret", "version"}:
            if (
                record["source"] != "secret"
                or not isinstance(record["secret"], str)
                or not record["secret"]
                or not str(record["version"]).isdigit()
                or int(record["version"]) <= 0
            ):
                raise PolicyError("expected secret environment evidence is malformed")
        else:
            raise PolicyError("expected environment evidence has unexpected fields")
        names.append(record["name"])
    if len(names) != len(set(names)) or expected != sorted(
        expected, key=lambda item: item["name"]
    ):
        raise PolicyError("expected environment evidence must be unique and sorted")
    if actual != expected:
        raise PolicyError("Cloud Run revision environment differs from the contract")


def verify_exact_digest_inventory(
    *,
    repository: str,
    policy_path: Path,
    image_name: str,
    image_digest: str,
    expected_image_id: str,
    expected_inventory_path: Path,
    output: Path,
) -> dict[str, Any]:
    if not IMAGE_NAME_RE.fullmatch(image_name) or not SHA256_RE.fullmatch(image_digest):
        raise PolicyError("immutable image subject is malformed")
    if not SHA256_RE.fullmatch(expected_image_id):
        raise PolicyError("expected image config digest is malformed")
    policy = load_policy(policy_path)
    profile = profile_for(repository, policy)
    if image_name != profile["release"]["registryRepository"]:
        raise PolicyError("image repository differs from the approved profile")
    image_ref = f"{image_name}@{image_digest}"
    subprocess.run(
        ["docker", "image", "pull", "--platform", "linux/amd64", image_ref],
        check=True,
        env=_trusted_docker_environment(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=1800,
    )
    inspect = _docker_image_inspect(image_ref)
    if (
        not isinstance(inspect, list)
        or len(inspect) != 1
        or inspect[0].get("Id") != expected_image_id
    ):
        raise PolicyError("exact pushed digest resolves to a different image config")
    inventory = _docker_rootfs_inventory(image_ref, profile)
    _validate_inventory_document(inventory, profile)
    expected_inventory = _read_json(
        expected_inventory_path, "trusted-builder rootfs inventory"
    )
    _validate_inventory_document(expected_inventory, profile)
    if inventory != expected_inventory:
        raise PolicyError("exact-digest rootfs inventory differs from the built image")
    _write_json(output, inventory)
    return inventory


def verify_attestation_statement(
    *,
    verification_path: Path,
    receipt_path: Path,
    inventory_path: Path,
    policy_path: Path,
    repository: str,
    image_name: str,
    image_digest: str,
    source_sha: str,
    run_id: str,
    run_attempt: str,
    job: str,
    caller_workflow_ref: str,
    caller_workflow_sha: str,
    nonce_path: Path,
    signer_workflow: str,
    signer_digest: str,
    output: Path,
) -> dict[str, Any]:
    if (
        not IMAGE_NAME_RE.fullmatch(image_name)
        or not SHA256_RE.fullmatch(image_digest)
        or not SHA1_RE.fullmatch(source_sha)
        or not SHA1_RE.fullmatch(caller_workflow_sha)
        or not SHA1_RE.fullmatch(signer_digest)
        or not WORKFLOW_RE.fullmatch(signer_workflow)
        or not run_id.isdigit()
        or int(run_id) <= 0
        or not run_attempt.isdigit()
        or int(run_attempt) <= 0
        or not job
        or not caller_workflow_ref
    ):
        raise PolicyError("expected release/attestation tuple is malformed")
    if nonce_path.is_symlink() or not nonce_path.is_file():
        raise PolicyError("release nonce must be a non-symlink regular file")
    nonce_source = nonce_path.read_text(encoding="ascii")
    if not re.fullmatch(r"[0-9a-f]{64}\n", nonce_source):
        raise PolicyError("release nonce is malformed")

    verification = _read_json(verification_path, "gh attestation verification")
    if not isinstance(verification, list) or len(verification) != 1:
        raise PolicyError("exactly one verified attestation is required")
    result = verification[0]
    if not isinstance(result, dict) or set(result) != {
        "attestation",
        "verificationResult",
    }:
        raise PolicyError("verified attestation result shape is invalid")
    verification_result = result["verificationResult"]
    if not isinstance(verification_result, dict):
        raise PolicyError("verified attestation metadata is absent")
    statement = verification_result.get("statement")
    signature = verification_result.get("signature")
    timestamps = verification_result.get("verifiedTimestamps")
    if (
        not isinstance(statement, dict)
        or not isinstance(signature, dict)
        or not isinstance(signature.get("certificate"), dict)
        or not isinstance(timestamps, list)
        or not timestamps
    ):
        raise PolicyError("attestation signature or trusted timestamp is absent")

    receipt = _read_json(receipt_path, "release runtime receipt")
    inventory = _read_json(inventory_path, "exact-digest rootfs inventory")
    expected_subject = [
        {
            "name": image_name,
            "digest": {"sha256": image_digest.removeprefix("sha256:")},
        }
    ]
    if (
        statement.get("_type") != "https://in-toto.io/Statement/v1"
        or statement.get("predicateType") != PREDICATE_TYPE
        or statement.get("subject") != expected_subject
        or statement.get("predicate") != receipt
    ):
        raise PolicyError("verified attestation statement differs from the receipt")

    policy = load_policy(policy_path)
    verify_receipt(
        receipt=receipt,
        inventory=inventory,
        repository=repository,
        policy=policy,
        policy_path=policy_path,
        expected_mode="release",
        expected_source_sha=source_sha,
        expected_image_name=image_name,
        expected_subject_digest=image_digest,
        expected_run_id=run_id,
        expected_run_attempt=run_attempt,
        expected_job=job,
        expected_workflow_ref=caller_workflow_ref,
        expected_workflow_sha=caller_workflow_sha,
        expected_nonce=nonce_source.rstrip("\n"),
    )
    evidence = {
        "schemaVersion": 1,
        "kind": "cognitum.static-ui.verified-release-attestation.v1",
        "repository": repository,
        "sourceSha": source_sha,
        "subject": expected_subject[0],
        "predicateType": PREDICATE_TYPE,
        "receiptDigest": receipt["receiptDigest"],
        "inventoryDigest": inventory["inventoryDigest"],
        "signerWorkflow": signer_workflow,
        "signerDigest": signer_digest,
        "callerWorkflowRef": caller_workflow_ref,
        "callerWorkflowSha": caller_workflow_sha,
        "runId": run_id,
        "runAttempt": run_attempt,
        "job": job,
        "trustedTimestampCount": len(timestamps),
        "evidenceDigest": "",
    }
    evidence["evidenceDigest"] = f"sha256:{_sha256_bytes(_canonical_bytes(evidence))}"
    _write_json(output, evidence)
    return evidence


def verify_cloud_run_service(
    *,
    repository: str,
    policy_path: Path,
    revision_path: Path,
    service_path: Path,
    expected_environment_path: Path,
    expected_revision: str,
    expected_service: str,
    expected_image: str,
    expected_service_account: str,
    expected_spec_digest: str,
    expected_ingress: str,
    output: Path,
) -> dict[str, Any]:
    if (
        not expected_revision
        or not expected_service
        or "@" not in expected_image
        or not SHA256_RE.fullmatch(expected_image.rsplit("@", 1)[1])
        or expected_ingress not in INGRESS_VALUES
    ):
        raise PolicyError("expected Cloud Run promotion tuple is malformed")
    policy = load_policy(policy_path)
    profile = profile_for(repository, policy)
    revision = _read_json(revision_path, "Cloud Run revision")
    service = _read_json(service_path, "Cloud Run service")
    if not isinstance(revision, dict) or not isinstance(service, dict):
        raise PolicyError("Cloud Run evidence roots must be objects")
    revision_evidence = validate_revision(
        revision=revision,
        profile=profile,
        expected_image=expected_image,
        expected_service_account=expected_service_account,
        expected_spec_digest=expected_spec_digest,
    )
    if revision.get("metadata", {}).get("name") != expected_revision:
        raise PolicyError("Cloud Run revision name differs")
    _condition_ready(revision, "Cloud Run revision")
    if revision.get("status", {}).get("imageDigest") != expected_image:
        raise PolicyError("Cloud Run revision status.imageDigest differs")
    expected_environment = _read_json(
        expected_environment_path, "expected environment evidence"
    )
    _validate_environment_contract(
        expected_environment, revision_evidence["environment"]
    )

    if service.get("metadata", {}).get("name") != expected_service:
        raise PolicyError("Cloud Run service name differs")
    _condition_ready(service, "Cloud Run service")
    annotations = service.get("metadata", {}).get("annotations", {})
    if (
        not isinstance(annotations, dict)
        or annotations.get("run.googleapis.com/ingress") != expected_ingress
    ):
        raise PolicyError("Cloud Run ingress differs")
    spec = service.get("spec")
    status = service.get("status")
    if not isinstance(spec, dict) or not isinstance(status, dict):
        raise PolicyError("Cloud Run service spec/status is absent")
    template_spec = spec.get("template", {}).get("spec")
    if not isinstance(template_spec, dict):
        raise PolicyError("Cloud Run Service template spec is absent")
    normalized_template_spec = copy.deepcopy(template_spec)
    template_containers = normalized_template_spec.get("containers")
    revision_containers = revision["spec"].get("containers")
    if (
        isinstance(template_containers, list)
        and len(template_containers) == 1
        and isinstance(template_containers[0], dict)
        and isinstance(revision_containers, list)
        and len(revision_containers) == 1
        and isinstance(revision_containers[0], dict)
        and "name" not in template_containers[0]
        and isinstance(revision_containers[0].get("name"), str)
    ):
        # Cloud Run injects the default single-container name into Revision
        # output while omitting it from Service.template. This is the only
        # accepted normalization; every other field remains byte-for-byte
        # canonical after JSON key ordering.
        template_containers[0]["name"] = revision_containers[0]["name"]
    if (
        normalized_template_spec != revision["spec"]
        or f"sha256:{_sha256_bytes(_canonical_bytes(normalized_template_spec))}"
        != expected_spec_digest
    ):
        raise PolicyError("Cloud Run Service template spec differs from the revision")
    if status.get("latestCreatedRevisionName") != expected_revision:
        raise PolicyError("Cloud Run latest-created revision differs")
    if status.get("latestReadyRevisionName") != expected_revision:
        raise PolicyError("Cloud Run latest-ready revision differs")

    expected_traffic = [{"percent": 100, "revisionName": expected_revision}]
    if spec.get("traffic") != expected_traffic:
        raise PolicyError(
            "Cloud Run desired traffic is not exact 100% revision traffic"
        )
    actual_traffic = status.get("traffic")
    if not isinstance(actual_traffic, list) or len(actual_traffic) != 1:
        raise PolicyError("Cloud Run serving traffic is not singular")
    actual = actual_traffic[0]
    if (
        not isinstance(actual, dict)
        or actual.get("revisionName") != expected_revision
        or actual.get("percent") != 100
        or actual.get("tag") not in (None, "")
    ):
        raise PolicyError("Cloud Run serving traffic differs from the exact revision")

    evidence = {
        "schemaVersion": 1,
        "kind": "cognitum.static-ui.cloud-run-release.v1",
        "repository": repository,
        "service": expected_service,
        "revision": expected_revision,
        "image": expected_image,
        "ingress": expected_ingress,
        "trafficPercent": 100,
        "revisionEvidence": revision_evidence,
        "evidenceDigest": "",
    }
    evidence["evidenceDigest"] = f"sha256:{_sha256_bytes(_canonical_bytes(evidence))}"
    _write_json(output, evidence)
    return evidence


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Gate exact static-UI release evidence"
    )
    commands = parser.add_subparsers(dest="command", required=True)

    inventory = commands.add_parser(
        "inventory", help="re-inventory the exact pushed OCI digest"
    )
    inventory.add_argument("--repository", required=True)
    inventory.add_argument("--policy", type=Path, required=True)
    inventory.add_argument("--image-name", required=True)
    inventory.add_argument("--image-digest", required=True)
    inventory.add_argument("--expected-image-id", required=True)
    inventory.add_argument("--expected-inventory", type=Path, required=True)
    inventory.add_argument("--output", type=Path, required=True)

    attestation = commands.add_parser(
        "attestation", help="bind gh's verified statement to the release receipt"
    )
    attestation.add_argument("--verification", type=Path, required=True)
    attestation.add_argument("--receipt", type=Path, required=True)
    attestation.add_argument("--inventory", type=Path, required=True)
    attestation.add_argument("--policy", type=Path, required=True)
    attestation.add_argument("--repository", required=True)
    attestation.add_argument("--image-name", required=True)
    attestation.add_argument("--image-digest", required=True)
    attestation.add_argument("--source-sha", required=True)
    attestation.add_argument("--run-id", required=True)
    attestation.add_argument("--run-attempt", required=True)
    attestation.add_argument("--job", required=True)
    attestation.add_argument("--caller-workflow-ref", required=True)
    attestation.add_argument("--caller-workflow-sha", required=True)
    attestation.add_argument("--nonce", type=Path, required=True)
    attestation.add_argument("--signer-workflow", required=True)
    attestation.add_argument("--signer-digest", required=True)
    attestation.add_argument("--output", type=Path, required=True)

    service = commands.add_parser(
        "service", help="bind a Ready Cloud Run Revision and exact 100% traffic"
    )
    service.add_argument("--repository", required=True)
    service.add_argument("--policy", type=Path, required=True)
    service.add_argument("--revision", type=Path, required=True)
    service.add_argument("--service-document", type=Path, required=True)
    service.add_argument("--expected-environment", type=Path, required=True)
    service.add_argument("--expected-revision", required=True)
    service.add_argument("--expected-service", required=True)
    service.add_argument("--expected-image", required=True)
    service.add_argument("--expected-service-account", required=True)
    service.add_argument("--expected-spec-digest", required=True)
    service.add_argument("--expected-ingress", required=True)
    service.add_argument("--output", type=Path, required=True)
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    try:
        if arguments.command == "inventory":
            verify_exact_digest_inventory(
                repository=arguments.repository,
                policy_path=arguments.policy,
                image_name=arguments.image_name,
                image_digest=arguments.image_digest,
                expected_image_id=arguments.expected_image_id,
                expected_inventory_path=arguments.expected_inventory,
                output=arguments.output,
            )
        elif arguments.command == "attestation":
            verify_attestation_statement(
                verification_path=arguments.verification,
                receipt_path=arguments.receipt,
                inventory_path=arguments.inventory,
                policy_path=arguments.policy,
                repository=arguments.repository,
                image_name=arguments.image_name,
                image_digest=arguments.image_digest,
                source_sha=arguments.source_sha,
                run_id=arguments.run_id,
                run_attempt=arguments.run_attempt,
                job=arguments.job,
                caller_workflow_ref=arguments.caller_workflow_ref,
                caller_workflow_sha=arguments.caller_workflow_sha,
                nonce_path=arguments.nonce,
                signer_workflow=arguments.signer_workflow,
                signer_digest=arguments.signer_digest,
                output=arguments.output,
            )
        elif arguments.command == "service":
            verify_cloud_run_service(
                repository=arguments.repository,
                policy_path=arguments.policy,
                revision_path=arguments.revision,
                service_path=arguments.service_document,
                expected_environment_path=arguments.expected_environment,
                expected_revision=arguments.expected_revision,
                expected_service=arguments.expected_service,
                expected_image=arguments.expected_image,
                expected_service_account=arguments.expected_service_account,
                expected_spec_digest=arguments.expected_spec_digest,
                expected_ingress=arguments.expected_ingress,
                output=arguments.output,
            )
        else:
            raise PolicyError("unsupported command")
    except (
        OSError,
        UnicodeError,
        ValueError,
        TypeError,
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
    ) as error:
        print(f"static-ui-release-gate: FAIL: {error}", file=sys.stderr)
        return 2
    print(f"static-ui-release-gate {arguments.command}: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
