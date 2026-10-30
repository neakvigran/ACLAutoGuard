"""Evaluate concrete IPv4 traffic against the supported policy model."""

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network


class ConnectionError(ValueError):
    """Concrete traffic input is invalid or unsupported by the evaluator."""


@dataclass(frozen=True)
class Decision:
    action: str
    matched_rule_id: str | None


def evaluate_connection(
    policy: dict,
    *,
    source: str,
    destination: str,
    protocol: str,
    destination_port: int | None = None,
) -> Decision:
    """Return the first matching action, or default action with no rule ID.

    Policy must have passed load_policy(). Traffic must specify individual IPv4
    addresses, TCP/UDP with a port, or ICMP without a port. The policy wildcard
    'ip' is not a concrete protocol. No packets are sent and no routing, ACL
    attachment, return traffic, or router-local behavior is inferred.
    """
    addresses = []
    for field, value in (("source", source), ("destination", destination)):
        if not isinstance(value, str):
            raise ConnectionError(f"{field} must be an individual IPv4 address string.")
        try:
            addresses.append(IPv4Address(value))
        except ValueError as exc:
            raise ConnectionError(f"{field} must be an individual IPv4 address.") from exc

    if protocol not in ("tcp", "udp", "icmp"):
        raise ConnectionError("Concrete protocol must be tcp, udp, or icmp.")
    if protocol in ("tcp", "udp"):
        if type(destination_port) is not int or not 1 <= destination_port <= 65535:
            raise ConnectionError("TCP/UDP requires an integer destination_port from 1 to 65535.")
    elif destination_port is not None:
        raise ConnectionError("ICMP must not specify destination_port.")

    source_address, destination_address = addresses
    for rule in policy["rules"]:
        if source_address not in IPv4Network(rule["source"]):
            continue
        if destination_address not in IPv4Network(rule["destination"]):
            continue
        if rule["protocol"] not in ("ip", protocol):
            continue
        if "destination_port" in rule and rule["destination_port"] != destination_port:
            continue
        return Decision(rule["action"], rule["id"])
    return Decision(policy["default_action"], None)
