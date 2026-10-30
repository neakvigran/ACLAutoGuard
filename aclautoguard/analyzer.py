"""Single-rule shadow detection for validated IPv4 policies."""

from dataclasses import dataclass
from ipaddress import IPv4Network


@dataclass(frozen=True)
class ShadowFinding:
    rule_id: str
    covered_by: str
    same_action: bool


def _covers(earlier: dict, later: dict) -> bool:
    """Whether earlier's match conditions contain all of later's."""
    for field in ("source", "destination"):
        earlier_network = IPv4Network(earlier[field])
        later_network = IPv4Network(later[field])
        if not later_network.subnet_of(earlier_network):
            return False

    if earlier["protocol"] != "ip":
        if earlier["protocol"] != later["protocol"]:
            return False

    if "destination_port" in earlier:
        if earlier["destination_port"] != later.get("destination_port"):
            return False

    return True


def find_pairwise_shadows(policy: dict) -> list[ShadowFinding]:
    """Find rules fully covered by a single earlier rule.

    Input must have passed load_policy().
    Several earlier rules jointly covering a later rule are not detected.
    A covering rule is evidence of unreachability, but may itself be
    shadowed; it is not necessarily the rule that decides packet actions.
    """
    findings = []
    rules = policy["rules"]

    for index, later in enumerate(rules):
        for earlier in rules[:index]:
            if _covers(earlier, later):
                findings.append(
                    ShadowFinding(
                        rule_id=later["id"],
                        covered_by=earlier["id"],
                        same_action=earlier["action"] == later["action"],
                    )
                )
                break

    return findings
