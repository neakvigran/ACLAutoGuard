"""Exercise file-to-results requirement checking for future terminal callers."""

from pathlib import Path

import pytest
import yaml

from aclautoguard.application import check_policy_requirements
from aclautoguard.evaluator import Decision
from aclautoguard.policy import PolicyError
from aclautoguard.requirement_checker import RequirementCheckError, RequirementResult
from aclautoguard.requirements import RequirementsError


EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
BASELINE = EXAMPLES / "requirements/baseline.yaml"
CORRECTED = EXAMPLES / "policies/corrected.yaml"


@pytest.mark.parametrize("filename,decision,satisfied", [
    ("corrected.yaml", Decision("permit", "rule_20"), True),
    ("shadowed.yaml", Decision("deny", "rule_10"), False),
])
def test_examples(filename, decision, satisfied):
    results = check_policy_requirements(
        EXAMPLES / "policies" / filename, BASELINE, requirement_ids=["T1"]
    )
    assert results == [RequirementResult("T1", "permit", decision)]
    assert results[0].satisfied is satisfied


def test_string_paths_with_spaces_and_selection_order(tmp_path):
    policy = tmp_path / "proposed policy.yaml"
    requirements = tmp_path / "access requirements.yaml"
    policy.write_bytes(CORRECTED.read_bytes())
    requirements.write_bytes(BASELINE.read_bytes())
    results = check_policy_requirements(
        str(policy), str(requirements), requirement_ids=("T3", "T1")
    )
    assert results == [
        RequirementResult("T3", "deny", Decision("deny", None)),
        RequirementResult("T1", "permit", Decision("permit", "rule_20")),
    ]


@pytest.mark.parametrize("kind,invalid", [
    ("policy", False), ("policy", True),
    ("requirements", False), ("requirements", True),
])
def test_loading_errors(tmp_path, kind, invalid):
    path = tmp_path / "bad.yaml"
    if invalid:
        path.write_text("{}\n", encoding="utf-8")
    with pytest.raises(PolicyError if kind == "policy" else RequirementsError):
        check_policy_requirements(
            path if kind == "policy" else CORRECTED,
            path if kind == "requirements" else BASELINE,
            requirement_ids=["T1"],
        )


@pytest.mark.parametrize("selection", [[], ["missing"], ["T1", "T1"]])
def test_selection_errors(selection):
    with pytest.raises(RequirementCheckError):
        check_policy_requirements(CORRECTED, BASELINE, requirement_ids=selection)


@pytest.mark.parametrize("conflict", [False, True])
def test_semantic_errors(tmp_path, conflict):
    document = yaml.safe_load(BASELINE.read_text(encoding="utf-8"))
    if conflict:
        document["requirements"].append({
            **document["requirements"][0], "id": "opposite", "expected_action": "deny"
        })
    else:
        document["requirements"][0]["source"] = "192.168.10.0/24"
    path = tmp_path / "requirements.yaml"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    with pytest.raises(RequirementCheckError, match="Conflicting requirements" if conflict else "/32"):
        check_policy_requirements(CORRECTED, path, requirement_ids=["T1"])
