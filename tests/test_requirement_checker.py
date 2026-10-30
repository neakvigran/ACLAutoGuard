"""Check modeled requirements with explicit selection and fail-closed limits."""

from copy import deepcopy
from pathlib import Path

import pytest
import yaml

from aclautoguard.evaluator import Decision
from aclautoguard.policy import load_policy
from aclautoguard.requirements import load_requirements
from aclautoguard.requirement_checker import (
    RequirementCheckError, RequirementResult, check_host_requirements,
)


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def policy():
    return load_policy(ROOT / "examples/policies/corrected.yaml")


@pytest.fixture
def requirements():
    return load_requirements(ROOT / "examples/requirements/baseline.yaml")


def test_student_samples(policy, requirements):
    before = deepcopy((policy, requirements))
    results = check_host_requirements(policy, requirements, requirement_ids=["T1", "T2", "T3"])
    assert results == [
        RequirementResult("T1", "permit", Decision("permit", "rule_20")),
        RequirementResult("T2", "deny", Decision("deny", "rule_10")),
        RequirementResult("T3", "deny", Decision("deny", None)),
    ]
    assert all(result.satisfied for result in results)
    assert (policy, requirements) == before


def test_shadowed_http_requirement_fails(requirements):
    policy = load_policy(ROOT / "examples/policies/shadowed.yaml")
    results = check_host_requirements(policy, requirements, requirement_ids=["T1"])
    assert results == [RequirementResult("T1", "permit", Decision("deny", "rule_10"))]
    assert not results[0].satisfied


def test_selection_order_and_unselected_entries(policy, requirements):
    results = check_host_requirements(policy, requirements, requirement_ids=("T3", "T1"))
    assert [result.requirement_id for result in results] == ["T3", "T1"]


@pytest.mark.parametrize("selection", [[], (), "T1", None, ["T1", "T1"], ["unknown"], [1], [" "]])
def test_invalid_selection(policy, requirements, selection):
    with pytest.raises(RequirementCheckError):
        check_host_requirements(policy, requirements, requirement_ids=selection)


def test_selection_is_mandatory(policy, requirements):
    with pytest.raises(TypeError):
        check_host_requirements(policy, requirements)


def write_requirements(tmp_path, requirements):
    path = tmp_path / "requirements.yaml"
    path.write_text(yaml.safe_dump(requirements), encoding="utf-8")
    return load_requirements(path)


@pytest.mark.parametrize("changes,message", [
    ({"source": "192.168.10.0/24"}, "/32"),
    ({"destination": "192.168.30.0/24"}, "/32"),
    ({"protocol": "ip", "destination_port": None}, "wildcard ip"),
    ({"destination_port": None}, "specific destination_port"),
])
def test_unsupported_selected_requirement(policy, requirements, tmp_path, changes, message):
    requirements["requirements"] = [requirements["requirements"][0]]
    entry = requirements["requirements"][0]
    entry.update(changes)
    if entry.get("destination_port") is None:
        entry.pop("destination_port", None)
    document = write_requirements(tmp_path, requirements)
    with pytest.raises(RequirementCheckError, match=message):
        check_host_requirements(policy, document, requirement_ids=["T1"])


def test_unselected_conflict_blocks_checking(policy, requirements, tmp_path):
    opposite = {**requirements["requirements"][0], "id": "opposite", "expected_action": "deny"}
    requirements["requirements"].append(opposite)
    document = write_requirements(tmp_path, requirements)
    with pytest.raises(RequirementCheckError, match="T1/opposite"):
        check_host_requirements(policy, document, requirement_ids=["T3"])


@pytest.mark.parametrize("protocol,port", [("udp", 53), ("icmp", None)])
def test_udp_and_icmp(policy, requirements, tmp_path, protocol, port):
    entry = requirements["requirements"][1]
    entry.update(protocol=protocol)
    if port is None:
        entry.pop("destination_port")
    else:
        entry["destination_port"] = port
    requirements["requirements"] = [entry]
    result = check_host_requirements(
        policy, write_requirements(tmp_path, requirements), requirement_ids=["T2"]
    )[0]
    assert result.satisfied
    assert result.decision == Decision("deny", "rule_10")
