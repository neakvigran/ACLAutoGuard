"""Verify contradictions across network, protocol, and port boundaries."""

from copy import deepcopy
from pathlib import Path

import pytest
import yaml

from aclautoguard.requirements import load_requirements
from aclautoguard.requirements_analysis import (
    RequirementConflict,
    find_requirement_conflicts,
)


BASELINE = Path(__file__).resolve().parents[1] / "examples/requirements/baseline.yaml"


def load_entries(tmp_path, entries):
    path = tmp_path / "requirements.yaml"
    path.write_text(yaml.safe_dump({
        "schema_version": 1,
        "name": "conflict_checks",
        "requirements": entries,
    }), encoding="utf-8")
    return load_requirements(path)


@pytest.fixture
def entry():
    return {
        "id": "allow",
        "expected_action": "permit",
        "protocol": "tcp",
        "source": "192.168.10.0/24",
        "destination": "192.168.30.0/24",
        "destination_port": 80,
    }


def test_baseline_has_no_conflicts():
    assert find_requirement_conflicts(load_requirements(BASELINE)) == []


@pytest.mark.parametrize("changes,expected", [
    ({}, True),
    ({"expected_action": "permit"}, False),
    ({"source": "192.168.10.10/32"}, True),
    ({"source": "0.0.0.0/0"}, True),
    ({"source": "192.168.11.0/24"}, False),
    ({"destination": "192.168.30.10/32"}, True),
    ({"destination": "192.168.0.0/16"}, True),
    ({"destination": "192.168.31.0/24"}, False),
    ({"source": "192.168.10.10/32", "destination": "0.0.0.0/0"}, True),
    ({"protocol": "udp"}, False),
    ({"destination_port": 443}, False),
    ({"destination_port": 1}, False),
    ({"destination_port": 65535}, False),
])
def test_overlap_is_symmetric(tmp_path, entry, changes, expected):
    other = {**entry, "id": "other", "expected_action": "deny", **changes}
    for first, second in ((entry, other), (other, entry)):
        data = load_entries(tmp_path, [first, second])
        original = deepcopy(data)
        assert find_requirement_conflicts(data) == (
            [RequirementConflict(first["id"], second["id"])] if expected else []
        )
        assert data == original


@pytest.mark.parametrize("first_protocol,first_port,second_protocol,second_port,expected", [
    ("ip", None, "tcp", 80, True),
    ("ip", None, "udp", 65535, True),
    ("ip", None, "icmp", None, True),
    ("ip", None, "ip", None, True),
    ("icmp", None, "tcp", None, False),
    ("icmp", None, "icmp", None, True),
    ("tcp", None, "tcp", 80, True),
    ("udp", None, "udp", 1, True),
    ("tcp", None, "udp", None, False),
    ("tcp", 80, "udp", 80, False),
    ("tcp", 1, "tcp", 1, True),
    ("udp", 65535, "udp", 65535, True),
    ("udp", 1, "udp", 65535, False),
])
def test_protocol_and_port_intersections(
    tmp_path, entry, first_protocol, first_port, second_protocol, second_port, expected
):
    entries = []
    for identifier, action, protocol, port in [
        ("first", "permit", first_protocol, first_port),
        ("second", "deny", second_protocol, second_port),
    ]:
        item = {**entry, "id": identifier, "expected_action": action, "protocol": protocol}
        item.pop("destination_port")
        if port is not None:
            item["destination_port"] = port
        entries.append(item)
    for ordered in (entries, entries[::-1]):
        assert find_requirement_conflicts(load_entries(tmp_path, ordered)) == (
            [RequirementConflict(ordered[0]["id"], ordered[1]["id"])] if expected else []
        )


def test_reports_every_conflicting_pair_once(tmp_path, entry):
    entries = [
        entry,
        {**entry, "id": "deny_one", "expected_action": "deny"},
        {**entry, "id": "deny_two", "expected_action": "deny"},
        {**entry, "id": "allow_two"},
    ]
    assert find_requirement_conflicts(load_entries(tmp_path, entries)) == [
        RequirementConflict("allow", "deny_one"),
        RequirementConflict("allow", "deny_two"),
        RequirementConflict("deny_one", "allow_two"),
        RequirementConflict("deny_two", "allow_two"),
    ]


def test_single_requirement(tmp_path, entry):
    assert find_requirement_conflicts(load_entries(tmp_path, [entry])) == []
