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
