"""Check first-match decisions and concrete traffic input boundaries."""

from copy import deepcopy
from pathlib import Path

import pytest
import yaml

from aclautoguard.evaluator import ConnectionError, Decision, evaluate_connection
from aclautoguard.policy import load_policy


EXAMPLES = Path(__file__).resolve().parents[1] / "examples/policies"
TRAFFIC = dict(
    source="192.168.10.10", destination="192.168.30.10",
    protocol="tcp", destination_port=80,
)


@pytest.mark.parametrize("filename,port,expected", [
    ("shadowed.yaml", 80, Decision("deny", "rule_10")),
    ("corrected.yaml", 80, Decision("permit", "rule_20")),
    ("corrected.yaml", 22, Decision("deny", "rule_10")),
])
def test_examples(filename, port, expected):
    policy = load_policy(EXAMPLES / filename)
    before = deepcopy(policy)
    assert evaluate_connection(policy, **{**TRAFFIC, "destination_port": port}) == expected
    assert policy == before


@pytest.mark.parametrize("changes", [
    {"source": "192.168.20.10"},
    {"destination": "192.168.20.20"},
])
def test_default_deny_has_no_rule_id(changes):
    policy = load_policy(EXAMPLES / "corrected.yaml")
    assert evaluate_connection(policy, **{**TRAFFIC, **changes}) == Decision("deny", None)


@pytest.mark.parametrize("rule_protocol,rule_port,traffic_protocol,traffic_port,matched", [
    ("ip", None, "tcp", 80, True),
    ("ip", None, "udp", 53, True),
    ("ip", None, "icmp", None, True),
    ("tcp", None, "tcp", 1, True),
    ("tcp", None, "tcp", 65535, True),
    ("udp", None, "udp", 65535, True),
    ("tcp", 80, "tcp", 80, True),
    ("tcp", 80, "tcp", 443, False),
    ("tcp", 80, "udp", 80, False),
    ("udp", 53, "udp", 53, True),
    ("icmp", None, "icmp", None, True),
    ("icmp", None, "tcp", 80, False),
    ("tcp", None, "icmp", None, False),
])
def test_protocol_and_ports(
    tmp_path, rule_protocol, rule_port, traffic_protocol, traffic_port, matched
):
    rule = dict(
        id="allow", action="permit", protocol=rule_protocol,
        source="0.0.0.0/0", destination="192.168.30.10/32",
    )
    if rule_port is not None:
        rule["destination_port"] = rule_port
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(dict(
        schema_version=1, name="protocol_checks", default_action="deny", rules=[rule]
    )), encoding="utf-8")
    policy = load_policy(path)
    result = evaluate_connection(policy, **{
        **TRAFFIC, "protocol": traffic_protocol, "destination_port": traffic_port,
    })
    assert result == (Decision("permit", "allow") if matched else Decision("deny", None))


@pytest.mark.parametrize("source,destination,rule_id", [
    ("192.168.10.0", "192.168.30.10", "rule_20"),
    ("192.168.10.255", "192.168.30.10", "rule_20"),
    ("192.168.11.0", "192.168.30.10", None),
    ("192.168.10.10", "192.168.30.11", "rule_10"),
    ("192.168.10.10", "192.168.31.0", None),
])
def test_address_boundaries(source, destination, rule_id):
    result = evaluate_connection(load_policy(EXAMPLES / "corrected.yaml"), **{
        **TRAFFIC, "source": source, "destination": destination,
    })
    assert result == Decision("permit" if rule_id == "rule_20" else "deny", rule_id)


@pytest.mark.parametrize("changes", [
    {"source": "192.168.10.0/24"}, {"source": "2001:db8::1"},
    {"source": 123}, {"destination": "invalid"}, {"destination": None},
    {"protocol": "ip"}, {"protocol": "TCP"}, {"protocol": "sctp"},
    {"destination_port": None}, {"destination_port": True},
    {"destination_port": "80"}, {"destination_port": 0},
    {"destination_port": 65536}, {"protocol": "icmp", "destination_port": 80},
])
def test_rejects_invalid_traffic(changes):
    with pytest.raises(ConnectionError):
        evaluate_connection(load_policy(EXAMPLES / "corrected.yaml"), **{**TRAFFIC, **changes})


def test_first_matching_permit_wins_over_later_deny():
    policy = load_policy(EXAMPLES / "corrected.yaml")
    policy["rules"].append({**policy["rules"][0], "id": "later_deny", "action": "deny"})
    assert evaluate_connection(policy, **TRAFFIC) == Decision("permit", "rule_20")
