"""Verify requirement-check output and exit codes at the process boundary."""

from pathlib import Path
import subprocess
import sys

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "examples/requirements/baseline.yaml"
CORRECTED = ROOT / "examples/policies/corrected.yaml"


def run_cli(*args):
    return subprocess.run(
        [sys.executable, "-m", "aclautoguard", *map(str, args)],
        cwd=ROOT, input="", capture_output=True, text=True, timeout=10,
    )


def test_corrected_student_checks():
    result = run_cli("check", CORRECTED, BASELINE, "--ids", "T1", "T2", "T3")
    assert result.returncode == 0
    assert "T1: MATCH; expected permit, modeled permit (rule rule_20)" in result.stdout
    assert "T2: MATCH; expected deny, modeled deny (rule rule_10)" in result.stdout
    assert "T3: MATCH; expected deny, modeled deny (default action)" in result.stdout
    assert "Checked 3 selected requirements; 0 mismatches." in result.stdout
    assert "no traffic was sent" in result.stdout
    assert "T4:" not in result.stdout
    assert result.stderr == ""


def test_shadowed_http_mismatch():
    result = run_cli("check", ROOT / "examples/policies/shadowed.yaml", BASELINE, "--ids", "T1")
    assert result.returncode == 1
    assert "T1: MISMATCH; expected permit, modeled deny (rule rule_10)" in result.stdout
    assert "1 mismatches" in result.stdout
    assert result.stderr == ""


def test_forbidden_traffic_permitted(tmp_path):
    policy = yaml.safe_load(CORRECTED.read_text(encoding="utf-8"))
    policy["rules"][1]["action"] = "permit"
    path = tmp_path / "too permissive.yaml"
    path.write_text(yaml.safe_dump(policy), encoding="utf-8")
    result = run_cli("check", path, BASELINE, "--ids", "T2")
    assert result.returncode == 1
    assert "T2: MISMATCH; expected deny, modeled permit" in result.stdout


def test_quoted_paths_and_selection_order(tmp_path):
    policy = tmp_path / "proposed policy.yaml"
    requirements = tmp_path / "access requirements.yaml"
    policy.write_bytes(CORRECTED.read_bytes())
    requirements.write_bytes(BASELINE.read_bytes())
    result = run_cli("check", policy, requirements, "--ids", "T3", "--ids", "T1")
    assert result.returncode == 0
    assert result.stdout.index("T3: MATCH") < result.stdout.index("T1: MATCH")


@pytest.mark.parametrize("args", [
    (), (str(CORRECTED),), (str(CORRECTED), str(BASELINE)),
    (str(CORRECTED), str(BASELINE), "--ids"),
])
def test_usage_errors(args):
    result = run_cli("check", *args)
    assert result.returncode == 2
    assert "usage:" in result.stderr
    assert result.stdout == ""


@pytest.mark.parametrize("kind", [
    "missing_policy", "invalid_policy", "missing_requirements", "invalid_requirements",
    "unknown_id", "duplicate_id", "unsupported", "conflict",
])
def test_input_errors(tmp_path, kind):
    policy, requirements, ids = CORRECTED, BASELINE, ["T1"]
    path = tmp_path / "bad.yaml"
    if kind.endswith("policy"):
        policy = path
        if kind == "invalid_policy":
            path.write_text("{}", encoding="utf-8")
    elif kind.endswith("requirements"):
        requirements = path
        if kind == "invalid_requirements":
            path.write_text("{}", encoding="utf-8")
    elif kind == "unknown_id":
        ids = ["unknown"]
    elif kind == "duplicate_id":
        ids = ["T1", "T1"]
    else:
        document = yaml.safe_load(BASELINE.read_text(encoding="utf-8"))
        if kind == "unsupported":
            document["requirements"][0]["source"] = "192.168.10.0/24"
        else:
            document["requirements"].append({
                **document["requirements"][0], "id": "opposite", "expected_action": "deny"
            })
        path.write_text(yaml.safe_dump(document), encoding="utf-8")
        requirements = path
    result = run_cli("check", policy, requirements, "--ids", *ids)
    assert result.returncode == 2
    assert "Error:" in result.stderr
    assert "Traceback" not in result.stderr
    assert result.stdout == ""


def test_help():
    result = run_cli("check", "--help")
    assert result.returncode == 0
    assert "--ids" in result.stdout
    assert "requirements_path" in result.stdout
    assert result.stderr == ""
