"""Shared analysis output and error handling for terminal interfaces."""

import sys

from aclautoguard.application import analyze_policy, check_policy_requirements
from aclautoguard.policy import PolicyError
from aclautoguard.requirement_checker import RequirementCheckError
from aclautoguard.requirements import RequirementsError


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


def run_requirement_check(
    policy_path: str, requirements_path: str, requirement_ids: list[str]
) -> int:
    """Print static comparisons: 0 all agree, 1 mismatch, 2 invalid input."""
    try:
        results = check_policy_requirements(
            policy_path, requirements_path, requirement_ids=requirement_ids
        )
    except (PolicyError, RequirementsError, RequirementCheckError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    for result in results:
        status = "MATCH" if result.satisfied else "MISMATCH"
        deciding_rule = (
            f"rule {result.decision.matched_rule_id}"
            if result.decision.matched_rule_id is not None else "default action"
        )
        print(
            f"{result.requirement_id}: {status}; expected {result.expected_action}, "
            f"modeled {result.decision.action} ({deciding_rule})."
        )
    mismatches = sum(not result.satisfied for result in results)
    print(f"Checked {len(results)} selected requirements; {mismatches} mismatches.")
    print(
        "Scope: static host-level checks only; no traffic was sent. "
        "Selection asserts ACL applicability; network paths are not verified. "
        "Unselected requirements and shadow analysis are not checked."
    )
    return 1 if mismatches else 0
