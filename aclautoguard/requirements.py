"""Load and validate independent version 1 access requirements."""

from ipaddress import IPv4Network
from pathlib import Path

import yaml

from aclautoguard.policy import PolicyError, UniqueKeyLoader


class RequirementsError(ValueError):
    """A requirements file cannot be loaded or fails validation."""


def load_requirements(path: str | Path) -> dict:
    """Validate structure and fields without evaluating access or conflicts."""
    try:
        data = yaml.load(Path(path).read_text(encoding="utf-8"), Loader=UniqueKeyLoader)
    except (OSError, UnicodeError, yaml.YAMLError, PolicyError) as exc:
        raise RequirementsError(f"Cannot read requirements: {exc}") from exc

    if not isinstance(data, dict):
        raise RequirementsError("Requirements document must be a YAML mapping.")
    _check_fields(data, {"schema_version", "name", "requirements"}, set(), "Document")
    if type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise RequirementsError("schema_version must be integer 1.")
    if not isinstance(data["name"], str) or not data["name"].strip():
        raise RequirementsError("name must be a nonempty string.")
    entries = data["requirements"]
    if not isinstance(entries, list) or not entries:
        raise RequirementsError("requirements must be a nonempty list.")

    seen_ids = set()
    for position, entry in enumerate(entries, start=1):
        label = f"Requirement {position}"
        if not isinstance(entry, dict):
            raise RequirementsError(f"{label}: must be a YAML mapping.")
        _check_fields(
            entry,
            {"id", "expected_action", "protocol", "source", "destination"},
            {"destination_port"},
            label,
        )
        identifier = entry["id"]
        if not isinstance(identifier, str) or not identifier.strip():
            raise RequirementsError(f"{label}: id must be a nonempty string.")
        if identifier != identifier.strip():
            raise RequirementsError(f"{label}: id must not have surrounding whitespace.")
        if identifier in seen_ids:
            raise RequirementsError(f"{label}: duplicate requirement id: {identifier}")
        seen_ids.add(identifier)

        if entry["expected_action"] not in ("permit", "deny"):
            raise RequirementsError(f"{label}: expected_action must be permit or deny.")
        protocol = entry["protocol"]
        if protocol not in ("ip", "tcp", "udp", "icmp"):
            raise RequirementsError(f"{label}: unsupported protocol.")
        for field in ("source", "destination"):
            value = entry[field]
            if not isinstance(value, str) or "/" not in value:
                raise RequirementsError(f"{label}: {field} must use IPv4 CIDR notation.")
            try:
                IPv4Network(value, strict=True)
            except ValueError as exc:
                raise RequirementsError(f"{label}: invalid {field} network: {value}") from exc
        if "destination_port" in entry:
            if protocol not in ("tcp", "udp"):
                raise RequirementsError(f"{label}: destination_port requires TCP or UDP.")
            port = entry["destination_port"]
            if type(port) is not int or not 1 <= port <= 65535:
                raise RequirementsError(
                    f"{label}: destination_port must be an integer from 1 to 65535."
                )
    return data


def _check_fields(mapping: dict, required: set, optional: set, label: str) -> None:
    missing = required - mapping.keys()
    unknown = mapping.keys() - required - optional
    if missing:
        raise RequirementsError(f"{label}: missing fields: {', '.join(sorted(missing))}")
    if unknown:
        raise RequirementsError(f"{label}: unknown fields: {', '.join(sorted(unknown))}")
