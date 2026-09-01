#!/usr/bin/env python3
"""Fail-closed aggregate for the reusable organization security workflow."""

from __future__ import annotations

import argparse


REQUIRED_RESULTS = ("success",)
AUDIT_EVENTS = ("schedule", "workflow_dispatch")


class EnforcementError(ValueError):
    """Raised when any blocking security control did not pass."""


def enforce(
    *,
    event: str,
    secrets: str,
    dependencies: str,
    workflow_pins: str,
    history: str,
) -> None:
    blocking = {
        "current-tree secret scan": secrets,
        "dependency scan": dependencies,
        "workflow pin policy": workflow_pins,
    }
    failures = [
        f"{name}={result}"
        for name, result in blocking.items()
        if result not in REQUIRED_RESULTS
    ]

    expected_history = "success" if event in AUDIT_EVENTS else "skipped"
    if history != expected_history:
        failures.append(
            f"full-history audit={history} (expected {expected_history} for {event})"
        )

    if failures:
        raise EnforcementError("security enforcement refused: " + "; ".join(failures))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--event", required=True)
    parser.add_argument("--secrets", required=True)
    parser.add_argument("--dependencies", required=True)
    parser.add_argument("--workflow-pins", required=True)
    parser.add_argument("--history", required=True)
    args = parser.parse_args()
    enforce(
        event=args.event,
        secrets=args.secrets,
        dependencies=args.dependencies,
        workflow_pins=args.workflow_pins,
        history=args.history,
    )
    print("security enforcement: all blocking controls passed")


if __name__ == "__main__":
    main()
