"""Load policy files and validate their structure and supported rules."""

from ipaddress import IPv4Network
from pathlib import Path

import yaml


class PolicyError(ValueError):
    """A policy cannot be loaded or fails validation."""


class UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate mapping keys."""


def _unique_mapping(loader, node):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node)
        if not isinstance(key, str):
            raise PolicyError("YAML mapping keys must be strings.")
        if key in result:
            raise PolicyError(f"Duplicate YAML key: {key}")
        result[key] = loader.construct_object(value_node)
    return result


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _unique_mapping,
)


def load_policy(path: str | Path) -> dict:
    """Read a policy and validate its structure and supported rule fields."""
    try:
        text = Path(path).read_text(encoding="utf-8")
        policy = yaml.load(text, Loader=UniqueKeyLoader)
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise PolicyError(f"Cannot read policy: {exc}") from exc

    if not isinstance(policy, dict):
        raise PolicyError("Policy must be a YAML mapping.")

    required = {"schema_version", "name", "default_action", "rules"}
    missing = required - policy.keys()
    unknown = policy.keys() - required

    if missing:
        raise PolicyError(f"Missing fields: {', '.join(sorted(missing))}")
    if unknown:
        raise PolicyError(f"Unknown fields: {', '.join(sorted(unknown))}")

    if type(policy["schema_version"]) is not int or policy["schema_version"] != 1:
        raise PolicyError("schema_version must be integer 1.")

    if not isinstance(policy["name"], str) or not policy["name"].strip():
        raise PolicyError("name must be a nonempty string.")

    if policy["default_action"] != "deny":
        raise PolicyError("Version 1 requires default_action: deny.")

    rules = policy["rules"]
    if not isinstance(rules, list) or not rules:
        raise PolicyError("rules must be a nonempty list.")
    if any(not isinstance(rule, dict) for rule in rules):
        raise PolicyError("Each rule must be a YAML mapping.")

    _validate_rules(rules)
    return policy


def _validate_rules(rules: list) -> None:
    """Validate the supported rule subset without changing rule order."""
    required = {"id", "action", "protocol", "source", "destination"}
    allowed = required | {"destination_port"}
    seen_ids = set()

    for position, rule in enumerate(rules, start=1):
        label = f"Rule {position}"
        missing = required - rule.keys()
        unknown = rule.keys() - allowed

        if missing:
            raise PolicyError(
                f"{label}: missing fields: {', '.join(sorted(missing))}"
            )
        if unknown:
            raise PolicyError(
                f"{label}: unknown fields: {', '.join(sorted(unknown))}"
            )

        rule_id = rule["id"]
        if not isinstance(rule_id, str) or not rule_id.strip():
            raise PolicyError(f"{label}: id must be a nonempty string.")
        if rule_id != rule_id.strip():
            raise PolicyError(f"{label}: id must not have surrounding whitespace.")
        if rule_id in seen_ids:
            raise PolicyError(f"{label}: duplicate rule id: {rule_id}")
        seen_ids.add(rule_id)

        if rule["action"] not in ("permit", "deny"):
            raise PolicyError(f"{label}: action must be permit or deny.")

        protocol = rule["protocol"]
        if protocol not in ("ip", "tcp", "udp", "icmp"):
            raise PolicyError(f"{label}: unsupported protocol.")

        for field in ("source", "destination"):
            value = rule[field]
            if not isinstance(value, str) or "/" not in value:
                raise PolicyError(f"{label}: {field} must use IPv4 CIDR notation.")
            try:
                IPv4Network(value, strict=True)
            except ValueError as exc:
                raise PolicyError(
                    f"{label}: invalid {field} network: {value}"
                ) from exc

        if "destination_port" in rule:
            port = rule["destination_port"]
            if protocol not in ("tcp", "udp"):
                raise PolicyError(
                    f"{label}: destination_port requires TCP or UDP."
                )
            if type(port) is not int or not 1 <= port <= 65535:
                raise PolicyError(
                    f"{label}: destination_port must be an integer from 1 to 65535."
                )
