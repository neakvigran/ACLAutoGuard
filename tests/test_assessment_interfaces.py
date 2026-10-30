"""Verify combined assessment exit codes and interactive recovery."""

from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "examples/requirements/baseline.yaml"


def run(*args, commands=""):
    return subprocess.run(
        [sys.executable, "-m", "aclautoguard", *map(str, args)], cwd=ROOT,
        input=commands, text=True, capture_output=True, timeout=10,
    )


@pytest.mark.parametrize("policy,code,status", [
    ("corrected.yaml", 0, "NO BLOCKING FINDINGS"),
    ("shadowed.yaml", 1, "BLOCKED"),
])
def test_assessment_cli(policy, code, status):
    result = run("assess", ROOT / "examples/policies" / policy, BASELINE, "--ids", "T1", "T2", "T3")
    assert result.returncode == code
    assert f"Static assessment: {status}" in result.stdout
    assert "does not authorize deployment" in result.stdout
    assert result.stderr == ""
    if code:
        assert "Shadow: rule_20" in result.stdout
        assert "T1: MISMATCH" in result.stdout


@pytest.mark.parametrize("args", [[], ["missing", str(BASELINE), "--ids", "T1"]])
def test_invalid_cli(args):
    result = run("assess", *args)
    assert result.returncode == 2
    assert result.stderr
    assert "Static assessment:" not in result.stdout


def test_interactive_assessment():
    result = run(commands=(
        "help assess\nassess --help\nassess\n"
        f"assess examples/policies/shadowed.yaml {BASELINE} --ids T1\n"
        f"assess examples/policies/corrected.yaml {BASELINE} --ids T1 T2 T3\n"
        "help\nexit\n"
    ))
    assert result.returncode == 0
    assert "assess <policy-path>" in result.stdout
    assert "Static assessment: BLOCKED" in result.stdout
    assert "Static assessment: NO BLOCKING FINDINGS" in result.stdout
    assert "Available commands:" in result.stdout
    assert "usage: assess" in result.stderr
    assert "Traceback" not in result.stderr


def test_quoted_paths(tmp_path):
    policy = tmp_path / "policy with spaces.yaml"
    requirements = tmp_path / "requirements with spaces.yaml"
    policy.write_bytes((ROOT / "examples/policies/corrected.yaml").read_bytes())
    requirements.write_bytes(BASELINE.read_bytes())
    result = run(commands=f'assess "{policy}" "{requirements}" --ids T1\nexit\n')
    assert result.returncode == 0
    assert "Static assessment: NO BLOCKING FINDINGS" in result.stdout
    assert result.stderr == ""
