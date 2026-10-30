"""Acceptance and rejection tests for the initial policy loader."""

from pathlib import Path

import pytest
import yaml

from aclautoguard.policy import PolicyError, load_policy


EXAMPLES = Path(__file__).resolve().parents[1] / "examples" / "policies"


@pytest.mark.parametrize(
    "filename,expected_order",
    [
        ("shadowed", ["rule_10", "rule_20"]),
        ("corrected", ["rule_20", "rule_10"]),
    ],
)
def test_examples_preserve_rule_order(filename, expected_order):
    policy = load_policy(EXAMPLES / f"{filename}.yaml")
    assert [rule["id"] for rule in policy["rules"]] == expected_order


@pytest.mark.parametrize(
    "content",
    [
        "",                         # Empty document
        "- not\n- a mapping\n",      # Wrong root structure
        "rules: [",                  # Invalid YAML
        "name: first\nname: second", # Duplicate top-level key
        "rules:\n  - action: deny\n    action: permit\n",  # Duplicate rule key
    ],
)
def test_rejects_invalid_documents(tmp_path, content):
    path = tmp_path / "invalid.yaml"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(PolicyError):
        load_policy(path)


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", True),
        ("schema_version", 2),
        ("name", "   "),
        ("default_action", "permit"),
        ("rules", []),
        ("rules", ["not a rule mapping"]),
        ("unexpected_field", "value"),
    ],
)
def test_rejects_invalid_top_level_fields(tmp_path, field, value):
    policy = yaml.safe_load(
        (EXAMPLES / "corrected.yaml").read_text(encoding="utf-8")
    )
    policy[field] = value
    path = tmp_path / "invalid.yaml"
    path.write_text(yaml.safe_dump(policy), encoding="utf-8")
    with pytest.raises(PolicyError):
        load_policy(path)


def test_rejects_missing_required_field(tmp_path):
    policy = yaml.safe_load(
        (EXAMPLES / "corrected.yaml").read_text(encoding="utf-8")
    )
    del policy["default_action"]
    path = tmp_path / "missing-field.yaml"
    path.write_text(yaml.safe_dump(policy), encoding="utf-8")
    with pytest.raises(PolicyError):
        load_policy(path)


def test_missing_file_reports_policy_error(tmp_path):
    with pytest.raises(PolicyError, match="Cannot read policy"):
        load_policy(tmp_path / "does-not-exist.yaml")


@pytest.mark.parametrize(
    "field,value",
    [
        ("id", ""),
        ("action", "allow"),
        ("protocol", "unknown"),
        ("source", "192.168.10.5/24"),
        ("source", "2001:db8::/32"),
        ("destination", "not-an-address"),
        ("destination_port", True),
        ("destination_port", "80"),
        ("destination_port", 0),
        ("destination_port", 65536),
        ("source_port", 12345),
    ],
)
def test_rejects_invalid_rule_fields(tmp_path, field, value):
    policy = yaml.safe_load(
        (EXAMPLES / "corrected.yaml").read_text(encoding="utf-8")
    )
    policy["rules"][0][field] = value
    path = tmp_path / "invalid-rule.yaml"
    path.write_text(yaml.safe_dump(policy), encoding="utf-8")
    with pytest.raises(PolicyError):
        load_policy(path)


def test_rejects_duplicate_rule_ids(tmp_path):
    policy = yaml.safe_load(
        (EXAMPLES / "corrected.yaml").read_text(encoding="utf-8")
    )
    policy["rules"][1]["id"] = policy["rules"][0]["id"]
    path = tmp_path / "duplicate-id.yaml"
    path.write_text(yaml.safe_dump(policy), encoding="utf-8")
    with pytest.raises(PolicyError, match="duplicate rule id"):
        load_policy(path)


@pytest.mark.parametrize(
    "protocol,port",
    [
        ("ip", None),
        ("icmp", None),
        ("tcp", None),
        ("udp", None),
        ("tcp", 1),
        ("tcp", 65535),
        ("udp", 1),
        ("udp", 65535),
    ],
)
def test_accepts_supported_protocols_and_ports(tmp_path, protocol, port):
    policy = yaml.safe_load(
        (EXAMPLES / "corrected.yaml").read_text(encoding="utf-8")
    )
    rule = policy["rules"][0]
    rule["protocol"] = protocol
    rule.pop("destination_port")
    if port is not None:
        rule["destination_port"] = port

    path = tmp_path / "valid-rule.yaml"
    path.write_text(yaml.safe_dump(policy), encoding="utf-8")
    loaded = load_policy(path)
    assert loaded["rules"][0] == rule


@pytest.mark.parametrize(
    "field", ["id", "action", "protocol", "source", "destination"]
)
def test_rejects_missing_rule_fields(tmp_path, field):
    policy = yaml.safe_load(
        (EXAMPLES / "corrected.yaml").read_text(encoding="utf-8")
    )
    del policy["rules"][0][field]
    path = tmp_path / "missing-rule-field.yaml"
    path.write_text(yaml.safe_dump(policy), encoding="utf-8")
    with pytest.raises(PolicyError, match="missing fields"):
        load_policy(path)


@pytest.mark.parametrize("protocol", ["ip", "icmp"])
def test_rejects_ports_on_non_transport_protocols(tmp_path, protocol):
    policy = yaml.safe_load(
        (EXAMPLES / "corrected.yaml").read_text(encoding="utf-8")
    )
    policy["rules"][0]["protocol"] = protocol
    path = tmp_path / "invalid-protocol-port.yaml"
    path.write_text(yaml.safe_dump(policy), encoding="utf-8")
    with pytest.raises(PolicyError, match="requires TCP or UDP"):
        load_policy(path)
