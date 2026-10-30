"""Tests for single-rule shadow detection."""

from pathlib import Path

import pytest

from aclautoguard.analyzer import ShadowFinding, find_pairwise_shadows
from aclautoguard.policy import load_policy


EXAMPLES = Path(__file__).resolve().parents[1] / "examples" / "policies"


def test_detects_shadowed_website_permission():
    policy = load_policy(EXAMPLES / "shadowed.yaml")
    assert find_pairwise_shadows(policy) == [
        ShadowFinding("rule_20", "rule_10", False)
    ]


def test_corrected_policy_has_no_fully_shadowed_rules():
    policy = load_policy(EXAMPLES / "corrected.yaml")
    assert find_pairwise_shadows(policy) == []


@pytest.mark.parametrize(
    "earlier_changes,later_changes,expected",
    [
        ({}, {}, True),
        ({}, {"protocol": "tcp", "destination_port": 80}, True),
        ({"protocol": "tcp", "destination_port": 80},
         {"protocol": "tcp"}, False),
        ({"protocol": "tcp", "destination_port": 80},
         {"protocol": "udp", "destination_port": 80}, False),
        ({"protocol": "tcp", "destination_port": 80},
         {"protocol": "tcp", "destination_port": 443}, False),
        ({}, {"source": "192.168.0.0/16"}, False),
        ({}, {"destination": "192.168.40.0/24"}, False),
        ({}, {"source": "192.168.10.10/32",
              "destination": "192.168.30.10/32"}, True),
    ],
)
def test_match_coverage(tmp_path, earlier_changes, later_changes, expected):
    import yaml

    base = {
        "action": "deny",
        "protocol": "ip",
        "source": "192.168.10.0/24",
        "destination": "192.168.30.0/24",
    }
    policy = {
        "schema_version": 1,
        "name": "coverage_test",
        "default_action": "deny",
        "rules": [
            {**base, **earlier_changes, "id": "earlier"},
            {**base, **later_changes, "id": "later"},
        ],
    }
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(policy), encoding="utf-8")
    findings = find_pairwise_shadows(load_policy(path))
    assert findings == (
        [ShadowFinding("later", "earlier", True)] if expected else []
    )
