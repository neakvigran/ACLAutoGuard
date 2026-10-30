"""Shared analysis output and error handling for terminal interfaces."""

import sys

from aclautoguard.application import analyze_policy
from aclautoguard.policy import PolicyError


def run_analysis(path: str) -> int:
    """Print analysis results: 0 means no findings, 1 shadows, 2 input error."""
    try:
        findings = analyze_policy(path)
    except PolicyError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    for finding in findings:
        action_relation = "same action" if finding.same_action else "different actions"
        print(
            f"Rule {finding.rule_id} is fully shadowed by earlier rule "
            f"{finding.covered_by} ({action_relation})."
        )
    if not findings:
        print("No single-earlier-rule shadows found.")
    print(
        "Scope: single-rule shadow detection only; joint coverage is not checked. "
        "Results do not prove security or access-requirement compliance."
    )
    return 1 if findings else 0
