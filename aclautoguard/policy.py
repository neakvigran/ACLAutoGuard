"""Load policy files and validate their top-level structure."""

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
    """Read a policy and check structure; rule validation is pending."""
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

    return policy
