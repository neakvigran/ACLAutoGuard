"""Shared application operations for terminal interfaces."""

from dataclasses import dataclass
from pathlib import Path

from aclautoguard.analyzer import ShadowFinding, find_pairwise_shadows
from aclautoguard.policy import load_policy
from aclautoguard.requirement_checker import RequirementResult, check_host_requirements
from aclautoguard.requirements import load_requirements


@dataclass(frozen=True)
class StaticAssessment:
    """Results of supported local checks; not authorization to deploy."""

    shadow_findings: tuple[ShadowFinding, ...]
    requirement_results: tuple[RequirementResult, ...]

    @property
    def blocked(self) -> bool:
        """Conservatively block on any shadow or selected requirement mismatch."""
        return bool(self.shadow_findings) or any(
            not result.satisfied for result in self.requirement_results
        )


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


def assess_policy(
    policy_path: str | Path,
    requirements_path: str | Path,
    *,
    requirement_ids: list[str] | tuple[str, ...],
) -> StaticAssessment:
    """Load once and run shadow analysis plus selected host requirement checks.

    Any detected shadow blocks, including same-action redundancy. Both types
    of findings are retained. Invalid or unsupported input raises PolicyError,
    RequirementsError, or RequirementCheckError; no assessment is returned.
    A nonblocking result only clears these static checks, with the existing
    pairwise-shadow and host-requirement limits. It does not establish ACL
    applicability, baseline health, recovery readiness, or deployment safety.
    """
    policy = load_policy(policy_path)
    requirements = load_requirements(requirements_path)
    results = check_host_requirements(policy, requirements, requirement_ids=requirement_ids)
    shadows = find_pairwise_shadows(policy)
    return StaticAssessment(tuple(shadows), tuple(results))
