"""Verify requirement checks leave interactive sessions usable."""

from pathlib import Path
import subprocess
import sys

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
POLICY = "examples/policies/corrected.yaml"
REQUIREMENTS = "examples/requirements/baseline.yaml"


def session(commands):
    return subprocess.run(
        [sys.executable, "-m", "aclautoguard"], cwd=ROOT,
        input=commands, capture_output=True, text=True, timeout=10,
    )


def test_help_and_check_results():
    result = session(
        "help check\ncheck --help\n"
        f"check {POLICY} {REQUIREMENTS} --ids T1 T2 T3\n"
        f"check examples/policies/shadowed.yaml {REQUIREMENTS} --ids T1\n"
        "help\nexit\n"
    )
    assert result.returncode == 0
    assert "check <policy-path> <requirements-path> --ids" in result.stdout
    assert "usage: check" in result.stdout
    assert "Checked 3 selected requirements; 0 mismatches." in result.stdout
    assert "T1: MISMATCH; expected permit, modeled deny" in result.stdout
    assert "Available commands: help, analyze, check, assess, exit" in result.stdout
    assert "no traffic was sent" in result.stdout
    assert result.stderr == ""


def test_quoted_paths_and_repeated_selection(tmp_path):
    policy = tmp_path / "proposed policy.yaml"
    requirements = tmp_path / "access requirements.yaml"
    policy.write_bytes((ROOT / POLICY).read_bytes())
    requirements.write_bytes((ROOT / REQUIREMENTS).read_bytes())
    result = session(f'check "{policy}" "{requirements}" --ids T3 --ids T1\nexit\n')
    assert result.returncode == 0
    assert result.stdout.index("T3: MATCH") < result.stdout.index("T1: MATCH")
    assert result.stderr == ""


@pytest.mark.parametrize("args,error", [
    ("", "usage: check"),
    (f"{POLICY} {REQUIREMENTS}", "--ids"),
    (f"{POLICY} {REQUIREMENTS} --ids", "expected at least one argument"),
    (f"{POLICY} {REQUIREMENTS} --ids unknown", "Unknown requirement IDs"),
    (f"{POLICY} {REQUIREMENTS} --ids T1 T1", "must not repeat"),
    (f"missing.yaml {REQUIREMENTS} --ids T1", "Cannot read policy"),
    (f"{POLICY} missing.yaml --ids T1", "Cannot read requirements"),
])
def test_errors_do_not_close_shell(args, error):
    result = session(f"check {args}\nhelp\nexit\n")
    assert result.returncode == 0
    assert error in result.stderr
    assert "Traceback" not in result.stderr
    assert "Available commands:" in result.stdout


@pytest.mark.parametrize("kind", ["invalid", "unsupported", "conflict"])
def test_requirements_errors_keep_shell_open(tmp_path, kind):
    document = yaml.safe_load((ROOT / REQUIREMENTS).read_text(encoding="utf-8"))
    if kind == "invalid":
        document = {}
    elif kind == "unsupported":
        document["requirements"][0]["source"] = "192.168.10.0/24"
    else:
        document["requirements"].append({
            **document["requirements"][0], "id": "opposite", "expected_action": "deny"
        })
    path = tmp_path / "requirements.yaml"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    result = session(f'check {POLICY} "{path}" --ids T1\nhelp\nexit\n')
    assert result.returncode == 0
    assert "Error:" in result.stderr
    assert "Traceback" not in result.stderr
    assert "Available commands:" in result.stdout


def test_eof_after_check():
    result = session(f"check {POLICY} {REQUIREMENTS} --ids T1\n")
    assert result.returncode == 0
    assert "T1: MATCH" in result.stdout
    assert result.stderr == ""
