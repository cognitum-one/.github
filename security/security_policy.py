#!/usr/bin/env python3
"""Immutable SecurityPolicy/v1 resolver and evidence-receipt writer.

The registry is owned by this repository and is addressed by immutable workflow
commit.  A caller supplies observations, never a control mode or a baseline.

The enforcement mode (``--mode``) is separate from the per-control policy
modes.  It never changes the verdict that is written to the receipt.  In
``advisory`` mode the process exits 0 when the only refusals are completed
dependency findings under an ``enforce`` or ``ratchet`` control; every other
refusal (secrets, workflow pins, a failed or skipped control, release
evidence, integrity errors) still exits non-zero in every mode.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any

SHA_RE = re.compile(r"[0-9a-f]{40}")
MODES = frozenset(("observe", "ratchet", "enforce", "release"))
ENFORCEMENT_MODES = ("enforce", "advisory")
# The only control whose completed findings an advisory run may leave
# unenforced. Secrets and workflow pins are blocking in every mode.
ADVISORY_CONTROLS = frozenset(("dependencies",))
SUCCESS = "success"


class PolicyError(ValueError):
    """Raised when policy integrity or a security decision is invalid."""


def _finding_refusal(control: str, observed: list[str]) -> str:
    return f"{control} has finding(s): {', '.join(sorted(set(observed)))}"


def _new_finding_refusal(control: str, new: list[str]) -> str:
    return f"{control} has new finding(s): {', '.join(new)}"


def _strict_json(text: str) -> Any:
    def no_duplicates(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise PolicyError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    try:
        return json.loads(text, object_pairs_hook=no_duplicates)
    except (TypeError, json.JSONDecodeError) as error:
        raise PolicyError(f"invalid policy JSON: {error}") from error


def load_policy(path: Path, expected_sha256: str) -> dict[str, Any]:
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise PolicyError("policy digest is malformed")
    if path.is_symlink() or not path.is_file():
        raise PolicyError("policy must be a regular file")
    source = path.read_bytes()
    if hashlib.sha256(source).hexdigest() != expected_sha256:
        raise PolicyError("policy bytes differ from the reviewed digest")
    policy = _strict_json(source.decode("utf-8"))
    if not isinstance(policy, dict) or policy.get("schema") != "SecurityPolicy/v1":
        raise PolicyError("policy schema is not SecurityPolicy/v1")
    if not isinstance(policy.get("revision"), str) or not policy["revision"]:
        raise PolicyError("policy revision is missing")
    controls = policy.get("controls")
    profiles = policy.get("profiles")
    repositories = policy.get("repositories")
    baselines = policy.get("baselines")
    if (
        not isinstance(controls, list)
        or not all(isinstance(control, str) for control in controls)
        or len(controls) != len(set(controls))
        or not isinstance(profiles, dict)
        or not isinstance(repositories, dict)
        or not isinstance(baselines, list)
    ):
        raise PolicyError("policy registry shape is invalid")
    for profile_name, modes in profiles.items():
        if not isinstance(profile_name, str) or not isinstance(modes, dict):
            raise PolicyError("policy profile is invalid")
        if set(modes) != set(controls) or any(mode not in MODES for mode in modes.values()):
            raise PolicyError(f"profile {profile_name} does not control every control")
    for repository_id, registration in repositories.items():
        if not repository_id.isdigit() or not isinstance(registration, dict):
            raise PolicyError("repository registry is invalid")
        if (
            not isinstance(registration.get("name"), str)
            or registration.get("profile") not in profiles
        ):
            raise PolicyError("repository registration is invalid")
    return policy


def resolve_profile(policy: dict[str, Any], repository_id: str, repository: str) -> tuple[str, dict[str, str]]:
    registration = policy["repositories"].get(repository_id)
    if registration is None:
        return "strict", dict(policy["profiles"]["strict"])
    if registration["name"] != repository:
        raise PolicyError("repository ID does not match its immutable registry name")
    profile = registration["profile"]
    return profile, dict(policy["profiles"][profile])


def _active_baselines(
    policy: dict[str, Any], repository_id: str, today: dt.date
) -> dict[str, dict[str, list[dict[str, Any]]]]:
    active: dict[str, dict[str, list[dict[str, Any]]]] = {}
    baseline_ids: set[str] = set()
    baseline_ownership: set[tuple[str, str]] = set()
    for baseline in policy["baselines"]:
        if not isinstance(baseline, dict):
            raise PolicyError("baseline is invalid")
        required = ("id", "repository_id", "control", "owner", "expires_at", "evidence", "findings")
        if any(not baseline.get(key) for key in required):
            raise PolicyError("baseline must be owned, finite, identified, and evidenced")
        if (
            not isinstance(baseline["id"], str)
            or not isinstance(baseline["repository_id"], str)
            or not isinstance(baseline["control"], str)
            or not isinstance(baseline["owner"], str)
            or baseline["control"] not in policy["controls"]
        ):
            raise PolicyError("baseline identity is invalid")
        # A baseline is an indivisible, owner-accountable exception. Letting a
        # second record reuse its ID or repository/control ownership merge a
        # disjoint finding set into the ratchet, which turns an explicit finite
        # exception into an accidental broadening. Validate globally, before
        # filtering for the caller repository, so a malformed registry is never
        # selectively accepted.
        if baseline["id"] in baseline_ids:
            raise PolicyError(f"baseline ID is duplicated: {baseline['id']}")
        ownership = (baseline["repository_id"], baseline["control"])
        if ownership in baseline_ownership:
            raise PolicyError(
                "baseline ownership overlaps for repository/control: "
                f"{baseline['repository_id']}/{baseline['control']}"
            )
        baseline_ids.add(baseline["id"])
        baseline_ownership.add(ownership)
        evidence = baseline["evidence"]
        if (
            not isinstance(evidence, dict)
            or not isinstance(evidence.get("repository"), str)
            or not isinstance(evidence.get("pull_request"), int)
            or evidence["pull_request"] <= 0
            or not isinstance(evidence.get("run_id"), str)
            or not evidence["run_id"].isdigit()
            or not isinstance(evidence.get("source_sha"), str)
            or not SHA_RE.fullmatch(evidence["source_sha"])
            or not isinstance(evidence.get("base_sha"), str)
            or not SHA_RE.fullmatch(evidence["base_sha"])
            or not isinstance(evidence.get("workflow_sha"), str)
            or not SHA_RE.fullmatch(evidence["workflow_sha"])
            or not isinstance(evidence.get("lockfile_blobs"), dict)
            or not evidence["lockfile_blobs"]
            or any(
                not isinstance(path, str)
                or not path
                or Path(path).is_absolute()
                or not isinstance(blob, str)
                or not SHA_RE.fullmatch(blob)
                for path, blob in evidence["lockfile_blobs"].items()
            )
        ):
            raise PolicyError("baseline evidence is invalid")
        if baseline["repository_id"] != repository_id:
            continue
        try:
            expiry = dt.date.fromisoformat(baseline["expires_at"])
        except (TypeError, ValueError) as error:
            raise PolicyError("baseline expiry is invalid") from error
        if expiry <= today:
            raise PolicyError(f"baseline {baseline['id']} has expired")
        if not isinstance(baseline["findings"], list) or not all(
            isinstance(finding, str) and finding for finding in baseline["findings"]
        ):
            raise PolicyError("baseline findings are invalid")
        for finding in baseline["findings"]:
            active.setdefault(baseline["control"], {}).setdefault(finding, []).append(
                {
                    "id": baseline["id"],
                    "owner": baseline["owner"],
                    "expires_at": baseline["expires_at"],
                    "evidence": evidence,
                }
            )
    return active


def evaluate(
    *,
    policy: dict[str, Any],
    repository_id: str,
    repository: str,
    source_sha: str,
    workflow_sha: str,
    producer: str,
    results: dict[str, str],
    findings: dict[str, list[str]],
    completions: dict[str, dict[str, Any]],
    today: dt.date,
    release_rerun: bool = False,
    release_candidate_sha: str | None = None,
    advisories: dict[str, list[str] | None] | None = None,
) -> dict[str, Any]:
    if not SHA_RE.fullmatch(source_sha) or not SHA_RE.fullmatch(workflow_sha):
        raise PolicyError("source/workflow SHA must be a full SHA")
    if producer != policy["producer"]:
        raise PolicyError("receipt producer is not the reviewed security workflow")
    profile, modes = resolve_profile(policy, repository_id, repository)
    if set(results) != set(policy["controls"]) or any(not isinstance(value, str) for value in results.values()):
        raise PolicyError("missing or skipped security subcheck results")
    if set(findings) != set(policy["controls"]):
        raise PolicyError("findings are missing a security subcheck or name an unknown control")
    if set(completions) != set(policy["controls"]):
        raise PolicyError("completion evidence is missing a security subcheck or name an unknown control")
    # Evidence only. `advisories` is every advisory a producer observed for a
    # control (for dependencies: the whole --all-vulns report), while
    # `findings` is the subset the producer's own gate blocks on and the only
    # set a control mode ever counts. Recording both keeps a Moderate or
    # unfixable advisory visible in the receipt without letting it decide the
    # verdict. A finding that is not among its control's advisories is an
    # integrity fault, never a pass.
    if advisories is None:
        advisories = {}
    if not isinstance(advisories, dict) or not set(advisories) <= set(policy["controls"]):
        raise PolicyError("advisory evidence names an unknown control")
    receipt_advisories: dict[str, list[str]] = {}
    for control in policy["controls"]:
        observed_advisories = advisories.get(control)
        if observed_advisories is None:
            observed_advisories = []
        if not isinstance(observed_advisories, list) or not all(
            isinstance(item, str) and item for item in observed_advisories
        ):
            raise PolicyError(f"advisory evidence for {control} is invalid")
        receipt_advisories[control] = sorted(set(observed_advisories))
    baselines = _active_baselines(policy, repository_id, today)
    exceptions: list[dict[str, Any]] = []
    blocking: list[str] = []
    receipt_findings: dict[str, list[str]] = {}
    baseline_matches: dict[str, list[str]] = {}
    if release_rerun and release_candidate_sha != source_sha:
        blocking.append("release rerun did not use the exact candidate SHA")
    for control in policy["controls"]:
        mode = modes[control]
        observed = findings.get(control, [])
        if not isinstance(observed, list) or not all(isinstance(item, str) and item for item in observed):
            raise PolicyError(f"findings for {control} are invalid")
        completion = completions[control]
        if not isinstance(completion, dict) or completion != {
            "schema": "security-producer-evidence-v1",
            "producer": f"{policy['producer']}#{control}",
            "control": control,
            "source_sha": source_sha,
            "workflow_sha": workflow_sha,
            "state": "completed",
            "findings": sorted(set(observed)),
        }:
            raise PolicyError(f"completion evidence for {control} is missing, malformed, or wrong-producer")
        receipt_findings[control] = sorted(set(observed))
        if receipt_advisories[control] and not set(observed) <= set(receipt_advisories[control]):
            raise PolicyError(f"findings for {control} are not among its observed advisories")
        baseline_findings = baselines.get(control, {})
        matched = sorted(set(observed) & set(baseline_findings))
        baseline_matches[control] = matched
        if results[control] != SUCCESS:
            blocking.append(f"{control}={results[control]}")
            continue
        if mode == "observe":
            continue
        if mode == "ratchet":
            new = sorted(set(observed) - set(baseline_findings))
            if new:
                blocking.append(_new_finding_refusal(control, new))
            if matched:
                exceptions.append(
                    {
                        "control": control,
                        "findings": matched,
                        "baselines": {
                            finding: baseline_findings[finding] for finding in matched
                        },
                    }
                )
        elif mode == "enforce":
            if observed:
                blocking.append(_finding_refusal(control, observed))
        elif mode == "release":
            if observed:
                blocking.append(f"{control} release evidence has finding(s): {', '.join(sorted(set(observed)))}")
            if not release_rerun or release_candidate_sha != source_sha:
                blocking.append(f"{control} release mode did not independently rerun exact candidate")
    return {
        "schema": "security-evidence-v1",
        "policy_revision": policy["revision"],
        "repository_id": repository_id,
        "repository": repository,
        "profile": profile,
        "source_sha": source_sha,
        "workflow_sha": workflow_sha,
        "producer": producer,
        "controls": modes,
        "results": results,
        "findings": receipt_findings,
        "advisories": receipt_advisories,
        "completions": completions,
        "baseline_matches": baseline_matches,
        "exceptions": exceptions,
        "release_rerun": release_rerun,
        "verdict": "pass" if not blocking else "fail",
        "blocking": blocking,
    }


def advisory_waivable(receipt: dict[str, Any]) -> list[str]:
    """Return the blocking entries an advisory run may leave unenforced.

    Recomputed from the receipt rather than carried as a flag, so an entry is
    waivable only when it is byte-identical to the refusal ``evaluate`` writes
    for a completed dependency finding under ``enforce`` or ``ratchet``.  A
    failed/skipped control, a ``release`` control, a secrets or workflow-pin
    refusal, and any unrecognised text are never waivable.
    """
    waivable: set[str] = set()
    for control in sorted(ADVISORY_CONTROLS):
        if receipt["results"].get(control) != SUCCESS:
            continue
        observed = receipt["findings"].get(control, [])
        matched = receipt["baseline_matches"].get(control, [])
        mode = receipt["controls"].get(control)
        if mode == "enforce" and observed:
            waivable.add(_finding_refusal(control, observed))
        elif mode == "ratchet":
            new = sorted(set(observed) - set(matched))
            if new:
                waivable.add(_new_finding_refusal(control, new))
    return [entry for entry in receipt["blocking"] if entry in waivable]


def apply_enforcement_mode(receipt: dict[str, Any], mode: str) -> dict[str, Any]:
    """Annotate a receipt with the enforcement mode; the verdict is untouched."""
    if mode not in ENFORCEMENT_MODES:
        raise PolicyError(f"enforcement mode must be one of {', '.join(ENFORCEMENT_MODES)}")
    advisory = advisory_waivable(receipt) if mode == "advisory" else []
    return {**receipt, "mode": mode, "advisory": advisory}


def enforced_blocking(receipt: dict[str, Any]) -> list[str]:
    """Blocking entries that still refuse after the enforcement mode is applied."""
    waived = set(receipt.get("advisory", []))
    return [entry for entry in receipt["blocking"] if entry not in waived]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--policy-sha256", required=True)
    parser.add_argument("--repository-id", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--workflow-sha", required=True)
    parser.add_argument("--producer", required=True)
    parser.add_argument("--results", required=True)
    parser.add_argument("--findings", required=True)
    parser.add_argument("--completions", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--release-rerun", action="store_true")
    parser.add_argument("--release-candidate-sha")
    parser.add_argument("--mode", choices=ENFORCEMENT_MODES, default="enforce")
    parser.add_argument(
        "--advisories", default="{}",
        help="JSON object of every observed advisory per control; evidence only, never counted",
    )
    args = parser.parse_args()
    policy = load_policy(args.policy, args.policy_sha256)
    results = _strict_json(args.results)
    findings = _strict_json(args.findings)
    completions = _strict_json(args.completions)
    advisories = _strict_json(args.advisories)
    if not isinstance(results, dict) or not isinstance(findings, dict) or not isinstance(completions, dict):
        raise PolicyError("results, findings, and completions must be JSON objects")
    if not isinstance(advisories, dict):
        raise PolicyError("advisories must be a JSON object")
    receipt = evaluate(
        policy=policy, repository_id=args.repository_id, repository=args.repository,
        source_sha=args.source_sha, workflow_sha=args.workflow_sha, producer=args.producer,
        results=results, findings=findings, completions=completions, today=dt.date.today(),
        release_rerun=args.release_rerun, release_candidate_sha=args.release_candidate_sha,
        advisories=advisories,
    )
    receipt = apply_enforcement_mode(receipt, args.mode)
    args.output.write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    refused = enforced_blocking(receipt)
    if refused:
        raise SystemExit("SecurityPolicy/v1 refused: " + "; ".join(refused))
    if receipt["advisory"]:
        print(
            "SecurityPolicy/v1 ADVISORY (mode=advisory): verdict=fail is recorded but not enforced: "
            + "; ".join(receipt["advisory"]),
            file=sys.stderr,
        )


if __name__ == "__main__":
    main()
