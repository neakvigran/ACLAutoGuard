"""Verify the combined static gate retains findings and rejects invalid input."""

from pathlib import Path

import pytest
import yaml

from aclautoguard.analyzer import ShadowFinding
from aclautoguard.application import assess_policy
from aclautoguard.evaluator import Decision
from aclautoguard.policy import PolicyError
from aclautoguard.requirement_checker import RequirementCheckError, RequirementResult
from aclautoguard.requirements import RequirementsError


EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
BASELINE = EXAMPLES / "requirements/baseline.yaml"
CORRECTED = EXAMPLES / "policies/corrected.yaml"
SHADOWED = EXAMPLES / "policies/shadowed.yaml"


def test_corrected_selected_checks_clear_static_gate():
    result = assess_policy(CORRECTED, BASELINE, requirement_ids=["T1", "T2", "T3"])
    assert result.blocked is False
    assert result.shadow_findings == ()
    assert result.requirement_results == (
        RequirementResult("T1", "permit", Decision("permit", "rule_20")),
        RequirementResult("T2", "deny", Decision("deny", "rule_10")),
        RequirementResult("T3", "deny", Decision("deny", None)),
    )


def test_shadow_and_mismatch_are_both_retained():
    result = assess_policy(SHADOWED, BASELINE, requirement_ids=["T1", "T2"])
    assert result.blocked is True
    assert result.shadow_findings == (ShadowFinding("rule_20", "rule_10", False),)
    assert result.requirement_results == (
        RequirementResult("T1", "permit", Decision("deny", "rule_10")),
        RequirementResult("T2", "deny", Decision("deny", "rule_10")),
    )


def test_shadow_alone_blocks_even_when_selected_requirements_agree():
    result = assess_policy(SHADOWED, BASELINE, requirement_ids=["T2"])
    assert all(item.satisfied for item in result.requirement_results)
    assert result.shadow_findings
    assert result.blocked is True


def write_policy(tmp_path, document):
    path = tmp_path / "proposed policy.yaml"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    return path


def test_mismatch_alone_blocks(tmp_path):
    policy = yaml.safe_load(CORRECTED.read_text(encoding="utf-8"))
    policy["rules"][0]["destination_port"] = 443
    result = assess_policy(write_policy(tmp_path, policy), BASELINE, requirement_ids=["T1"])
    assert result.shadow_findings == ()
    assert not result.requirement_results[0].satisfied
    assert result.blocked is True


def test_same_action_shadow_blocks(tmp_path):
    policy = yaml.safe_load(CORRECTED.read_text(encoding="utf-8"))
    policy["rules"].append({**policy["rules"][0], "id": "redundant"})
    result = assess_policy(write_policy(tmp_path, policy), BASELINE, requirement_ids=["T1"])
    assert result.shadow_findings == (ShadowFinding("redundant", "rule_20", True),)
    assert result.requirement_results[0].satisfied
    assert result.blocked is True


def test_string_paths_and_explicit_order(tmp_path):
    policy = tmp_path / "policy with spaces.yaml"
    requirements = tmp_path / "requirements with spaces.yaml"
    policy.write_bytes(CORRECTED.read_bytes())
    requirements.write_bytes(BASELINE.read_bytes())
    result = assess_policy(str(policy), str(requirements), requirement_ids=("T3", "T1"))
    assert [item.requirement_id for item in result.requirement_results] == ["T3", "T1"]
    assert result.blocked is False


@pytest.mark.parametrize("kind", ["missing_policy", "bad_policy", "missing_requirements", "bad_requirements"])
def test_loading_errors_return_no_assessment(tmp_path, kind):
    path = tmp_path / "invalid.yaml"
    if kind.startswith("bad"):
        path.write_text("{}", encoding="utf-8")
    is_policy = kind.endswith("policy")
    with pytest.raises(PolicyError if is_policy else RequirementsError):
        assess_policy(
            path if is_policy else CORRECTED,
            BASELINE if is_policy else path,
            requirement_ids=["T1"],
        )


@pytest.mark.parametrize("selection", [[], ["unknown"], ["T1", "T1"]])
def test_invalid_selection_returns_no_assessment(selection):
    with pytest.raises(RequirementCheckError):
        assess_policy(CORRECTED, BASELINE, requirement_ids=selection)


@pytest.mark.parametrize("conflict", [False, True])
def test_semantic_errors_return_no_assessment(tmp_path, conflict):
    document = yaml.safe_load(BASELINE.read_text(encoding="utf-8"))
    if conflict:
        document["requirements"].append({
            **document["requirements"][0], "id": "opposite", "expected_action": "deny"
        })
    else:
        document["requirements"][0]["source"] = "192.168.10.0/24"
    path = tmp_path / "requirements.yaml"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    with pytest.raises(RequirementCheckError):
        assess_policy(CORRECTED, path, requirement_ids=["T1"])
