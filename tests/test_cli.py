"""Exercise CLI output and process exit codes through the module entry point."""

from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples" / "policies"


def run_cli(*args):
    return subprocess.run(
        [sys.executable, "-m", "aclautoguard", *map(str, args)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        input="",
        timeout=10,
    )


@pytest.mark.parametrize(
    "filename,code,message",
    [
        ("shadowed.yaml", 1, "rule_20 is fully shadowed by earlier rule rule_10"),
        ("corrected.yaml", 0, "No single-earlier-rule shadows found."),
    ],
)
def test_analyze_examples(filename, code, message):
    result = run_cli("analyze", EXAMPLES / filename)
    assert result.returncode == code
    assert message in result.stdout
    assert "do not prove security" in result.stdout
    assert result.stderr == ""


def test_path_with_spaces(tmp_path):
    path = tmp_path / "corrected policy.yaml"
    path.write_bytes((EXAMPLES / "corrected.yaml").read_bytes())
    result = run_cli("analyze", path)
    assert result.returncode == 0
    assert "No single-earlier-rule shadows found." in result.stdout


@pytest.mark.parametrize("invalid", [False, True])
def test_policy_errors(tmp_path, invalid):
    path = tmp_path / "policy.yaml"
    if invalid:
        path.write_text("rules: []\n", encoding="utf-8")
    result = run_cli("analyze", path)
    assert result.returncode == 2
    assert result.stdout == ""
    assert "Error:" in result.stderr
    assert "Traceback" not in result.stderr


@pytest.mark.parametrize("args", [("analyze",), ("unknown",)])
def test_usage_errors(args):
    result = run_cli(*args)
    assert result.returncode == 2
    assert "usage:" in result.stderr


@pytest.mark.parametrize("args", [("--help",), ("analyze", "--help")])
def test_help(args):
    result = run_cli(*args)
    assert result.returncode == 0
    assert "analyze" in result.stdout
    assert result.stderr == ""
