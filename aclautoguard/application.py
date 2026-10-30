"""Shared application operations for terminal interfaces."""

from pathlib import Path

from aclautoguard.analyzer import ShadowFinding, find_pairwise_shadows
from aclautoguard.policy import load_policy


def analyze_policy(path: str | Path) -> list[ShadowFinding]:
    """Validate a policy file and return single-earlier-rule shadows.

    Raises PolicyError if loading or validation fails. An empty result
    does not prove security or compliance with access requirements.
    """
    policy = load_policy(path)
    return find_pairwise_shadows(policy)
