"""Compare explicitly selected host requirements with modeled ACL decisions."""

from dataclasses import dataclass
from ipaddress import IPv4Network

from aclautoguard.evaluator import Decision, evaluate_connection
from aclautoguard.requirements_analysis import find_requirement_conflicts


class RequirementCheckError(ValueError):
    """Selection is invalid, requirements conflict, or checking is unsupported."""


@dataclass(frozen=True)
class RequirementResult:
    requirement_id: str
    expected_action: str
    decision: Decision

    @property
    def satisfied(self) -> bool:
        """Whether this policy model agrees; not a real connectivity result."""
        return self.expected_action == self.decision.action


def check_host_requirements(
    policy: dict, requirements: dict, *, requirement_ids: list[str] | tuple[str, ...]
) -> list[RequirementResult]:
    """Check selected requirements, in selection order, without sending traffic.

    Inputs must have passed load_policy() and load_requirements(). The caller
    must establish that the selected requirements apply to this ACL. Selection
    does not verify applicability. Any conflict in the requirements document
    blocks checking. Only /32 endpoints, TCP/UDP with a specified destination
    port, and ICMP are supported. Unselected entries are not evaluated.
    """
    if not isinstance(requirement_ids, (list, tuple)) or not requirement_ids:
        raise RequirementCheckError("Select a nonempty list or tuple of requirement IDs.")
    if any(not isinstance(identifier, str) or not identifier.strip() for identifier in requirement_ids):
        raise RequirementCheckError("Selected requirement IDs must be nonempty strings.")
    if len(set(requirement_ids)) != len(requirement_ids):
        raise RequirementCheckError("Selected requirement IDs must not repeat.")
    by_id = {entry["id"]: entry for entry in requirements["requirements"]}
    unknown = set(requirement_ids) - by_id.keys()
    if unknown:
        raise RequirementCheckError(f"Unknown requirement IDs: {', '.join(sorted(unknown))}")

    conflicts = find_requirement_conflicts(requirements)
    if conflicts:
        pairs = ", ".join(f"{item.first_id}/{item.second_id}" for item in conflicts)
        raise RequirementCheckError(f"Conflicting requirements: {pairs}")

    selected = [by_id[identifier] for identifier in requirement_ids]
    for entry in selected:
        if any(IPv4Network(entry[field]).prefixlen != 32 for field in ("source", "destination")):
            raise RequirementCheckError(f"{entry['id']}: checking requires /32 endpoints.")
        if entry["protocol"] == "ip":
            raise RequirementCheckError(f"{entry['id']}: wildcard ip checking is not supported.")
        if entry["protocol"] in ("tcp", "udp") and "destination_port" not in entry:
            raise RequirementCheckError(f"{entry['id']}: checking requires a specific destination_port.")

    return [
        RequirementResult(
            entry["id"], entry["expected_action"],
            evaluate_connection(
                policy,
                source=str(IPv4Network(entry["source"]).network_address),
                destination=str(IPv4Network(entry["destination"]).network_address),
                protocol=entry["protocol"],
                destination_port=entry.get("destination_port"),
            ),
        )
        for entry in selected
    ]
