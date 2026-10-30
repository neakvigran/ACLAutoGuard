"""Detect contradictory expectations in validated access requirements."""

from dataclasses import dataclass
from ipaddress import IPv4Network
from itertools import combinations


@dataclass(frozen=True)
class RequirementConflict:
    """Two requirements demand opposite actions for some common traffic."""

    first_id: str
    second_id: str


def _overlap(first: dict, second: dict) -> bool:
    for field in ("source", "destination"):
        if not IPv4Network(first[field]).overlaps(IPv4Network(second[field])):
            return False

    protocols = (first["protocol"], second["protocol"])
    if protocols[0] != protocols[1] and "ip" not in protocols:
        return False

    first_port = first.get("destination_port")
    second_port = second.get("destination_port")
    return first_port is None or second_port is None or first_port == second_port


def find_requirement_conflicts(requirements: dict) -> list[RequirementConflict]:
    """Report every overlapping pair with opposite expected actions.

    Input must have passed load_requirements(). Each pair is reported once,
    in file order; order does not give either requirement precedence.
    This does not compare requirements to ACLs or verify actual traffic.
    """
    return [
        RequirementConflict(first["id"], second["id"])
        for first, second in combinations(requirements["requirements"], 2)
        if first["expected_action"] != second["expected_action"]
        and _overlap(first, second)
    ]
