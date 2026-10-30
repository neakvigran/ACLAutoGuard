"""Verify file-to-findings behavior shared by terminal interfaces."""

from pathlib import Path

import pytest

from aclautoguard.analyzer import ShadowFinding
from aclautoguard.application import analyze_policy
from aclautoguard.policy import PolicyError


EXAMPLES = Path(__file__).resolve().parents[1] / "examples" / "policies"


@pytest.mark.parametrize(
    "filename,expected",
    [
        ("shadowed.yaml", [ShadowFinding("rule_20", "rule_10", False)]),
        ("corrected.yaml", []),
    ],
)
def test_analyze_example(filename, expected):
    assert analyze_policy(EXAMPLES / filename) == expected


def test_analyze_string_path_with_spaces(tmp_path):
    path = tmp_path / "shadowed policy.yaml"
    path.write_text(
        (EXAMPLES / "shadowed.yaml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    assert analyze_policy(str(path)) == [
        ShadowFinding("rule_20", "rule_10", False)
    ]


def test_analyze_rejects_invalid_policy(tmp_path):
    path = tmp_path / "invalid.yaml"
    path.write_text("rules: []\n", encoding="utf-8")
    with pytest.raises(PolicyError, match="Missing fields"):
        analyze_policy(path)


def test_analyze_missing_file(tmp_path):
    with pytest.raises(PolicyError, match="Cannot read policy"):
        analyze_policy(tmp_path / "missing.yaml")
