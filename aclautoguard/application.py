"""Shared application operations for terminal interfaces."""

from pathlib import Path

from aclautoguard.analyzer import ShadowFinding, find_pairwise_shadows
from aclautoguard.policy import load_policy
from aclautoguard.requirement_checker import RequirementResult, check_host_requirements
from aclautoguard.requirements import load_requirements


def analyze_policy(path: str | Path) -> list[ShadowFinding]:
    """Validate a policy file and return single-earlier-rule shadows.

    Raises PolicyError if loading or validation fails. An empty result
    does not prove security or compliance with access requirements.
    """
    policy = load_policy(path)
    return find_pairwise_shadows(policy)


def check_policy_requirements(
    policy_path: str | Path,
    requirements_path: str | Path,
    *,
    requirement_ids: list[str] | tuple[str, ...],
) -> list[RequirementResult]:
    """Load both files and compare explicitly selected host requirements.

    Raises PolicyError, RequirementsError, or RequirementCheckError for invalid
    inputs or unsupported checks. A modeled mismatch is returned as a result,
    not raised as an exception. Caller selection asserts ACL applicability;
    no network path or actual connectivity is verified. Shadow analysis is a
    separate operation, available through analyze_policy().
    """
    policy = load_policy(policy_path)
    requirements = load_requirements(requirements_path)
    return check_host_requirements(policy, requirements, requirement_ids=requirement_ids)
