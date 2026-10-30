"""Acceptance and boundary checks for independent requirements input."""

from copy import deepcopy
from pathlib import Path

import pytest
import yaml

from aclautoguard.requirements import RequirementsError, load_requirements


BASELINE = Path(__file__).resolve().parents[1] / "examples/requirements/baseline.yaml"


@pytest.fixture
def document():
    return yaml.safe_load(BASELINE.read_text(encoding="utf-8"))


def write_document(tmp_path, document):
    path = tmp_path / "access requirements.yaml"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    return path


def test_baseline_preserves_values_and_order(document):
    loaded = load_requirements(BASELINE)
    assert loaded == document
    assert [entry["id"] for entry in loaded["requirements"]] == [
        f"T{index}" for index in range(1, 9)
    ]
    assert [entry["expected_action"] for entry in loaded["requirements"]] == [
        "permit", "deny", "deny", "permit", "permit", "deny", "deny", "permit"
    ]


@pytest.mark.parametrize("content", [
    "", "[]", "requirements: [", "name: first\nname: second",
    "requirements:\n  - id: T1\n    id: T2\n",
    "1: value", "!!python/object:builtins.object {}",
])
def test_rejects_invalid_yaml_documents(tmp_path, content):
    path = tmp_path / "invalid.yaml"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(RequirementsError):
        load_requirements(path)


@pytest.mark.parametrize("field,value", [
    ("schema_version", True), ("schema_version", 1.0), ("schema_version", 2),
    ("name", " "), ("name", None), ("requirements", []),
    ("requirements", {}), ("requirements", [None]), ("default_action", "deny"),
])
def test_rejects_invalid_document_fields(tmp_path, document, field, value):
    document[field] = value
    with pytest.raises(RequirementsError):
        load_requirements(write_document(tmp_path, document))


@pytest.mark.parametrize("field", ["schema_version", "name", "requirements"])
def test_missing_document_fields(tmp_path, document, field):
    del document[field]
    with pytest.raises(RequirementsError, match="missing fields"):
        load_requirements(write_document(tmp_path, document))


@pytest.mark.parametrize("field", ["id", "expected_action", "protocol", "source", "destination"])
def test_missing_requirement_fields(tmp_path, document, field):
    del document["requirements"][0][field]
    with pytest.raises(RequirementsError, match="Requirement 1: missing fields"):
        load_requirements(write_document(tmp_path, document))


@pytest.mark.parametrize("field,value", [
    ("id", ""), ("id", " T1"), ("id", 1),
    ("expected_action", "allow"), ("expected_action", True),
    ("protocol", "TCP"), ("protocol", []),
    ("source", "192.168.10.5/24"), ("source", "2001:db8::/32"),
    ("source", "192.168.10.10"), ("source", None),
    ("destination", "invalid"), ("destination", "192.168.30.5/24"),
    ("destination_port", True), ("destination_port", "80"),
    ("destination_port", 0), ("destination_port", 65536),
    ("source_port", 12345), ("action", "permit"),
])
def test_rejects_invalid_requirement_fields(tmp_path, document, field, value):
    document["requirements"][0][field] = value
    with pytest.raises(RequirementsError, match="Requirement 1"):
        load_requirements(write_document(tmp_path, document))


def test_duplicate_ids(tmp_path, document):
    document["requirements"][1]["id"] = "T1"
    with pytest.raises(RequirementsError, match="duplicate requirement id"):
        load_requirements(write_document(tmp_path, document))


@pytest.mark.parametrize("protocol,port", [
    ("ip", None), ("icmp", None), ("tcp", None), ("udp", None),
    ("tcp", 1), ("tcp", 65535), ("udp", 1), ("udp", 65535),
])
def test_supported_matches(tmp_path, document, protocol, port):
    entry = document["requirements"][0]
    entry["protocol"] = protocol
    entry["source"] = "0.0.0.0/0"
    entry["destination"] = "192.168.30.0/24"
    entry.pop("destination_port")
    if port is not None:
        entry["destination_port"] = port
    assert load_requirements(str(write_document(tmp_path, document))) == document


@pytest.mark.parametrize("protocol", ["ip", "icmp"])
def test_non_transport_ports_rejected(tmp_path, document, protocol):
    document["requirements"][0]["protocol"] = protocol
    with pytest.raises(RequirementsError, match="requires TCP or UDP"):
        load_requirements(write_document(tmp_path, document))


def test_file_errors(tmp_path):
    with pytest.raises(RequirementsError, match="Cannot read requirements"):
        load_requirements(tmp_path / "missing.yaml")
    path = tmp_path / "invalid-encoding.yaml"
    path.write_bytes(b"\xff")
    with pytest.raises(RequirementsError, match="Cannot read requirements"):
        load_requirements(path)


def test_semantic_conflicts_are_deferred(tmp_path, document):
    opposite = deepcopy(document["requirements"][0])
    opposite.update(id="conflicting", expected_action="deny")
    document["requirements"].append(opposite)
    assert load_requirements(write_document(tmp_path, document)) == document
