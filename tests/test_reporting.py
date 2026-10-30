"""Verify truthful static evidence and non-overwriting report exports."""

import json
from pathlib import Path
import subprocess
import sys

import pytest

from aclautoguard.application import assess_policy
from aclautoguard.reporting import ReportError, write_static_report


ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "examples/requirements/baseline.yaml"


@pytest.mark.parametrize("filename,blocked", [("corrected.yaml", False), ("shadowed.yaml", True)])
def test_report_values(tmp_path, filename, blocked):
    assessment = assess_policy(ROOT / "examples/policies" / filename, BASELINE, requirement_ids=["T1"])
    path = tmp_path / "static report.json"
    write_static_report(assessment, path)
    report = json.loads(path.read_text(encoding="utf-8"))
    assert report["blocked"] is blocked
    assert report["traffic_sent"] is False
    assert report["report_type"] == "static_assessment"
    assert report["requirement_results"][0]["requirement_id"] == "T1"
    assert report["requirement_results"][0]["satisfied"] is not blocked
    assert report["limitations"]
    with pytest.raises(ReportError):
        write_static_report(assessment, path)
    assert json.loads(path.read_text(encoding="utf-8")) == report


def test_missing_parent(tmp_path):
    assessment = assess_policy(ROOT / "examples/policies/corrected.yaml", BASELINE, requirement_ids=["T1"])
    with pytest.raises(ReportError):
        write_static_report(assessment, tmp_path / "absent" / "report.json")


@pytest.mark.parametrize("interactive", [False, True])
def test_interface_export_and_refusal(tmp_path, interactive):
    path = tmp_path / "static evidence.json"
    args = ["assess", str(ROOT / "examples/policies/corrected.yaml"), str(BASELINE), "--ids", "T1", "--report", str(path)]
    if interactive:
        import shlex
        command = [sys.executable, "-m", "aclautoguard"]
        commands = shlex.join(args) + "\nexit\n"
    else:
        command = [sys.executable, "-m", "aclautoguard", *args]
        commands = ""
    first = subprocess.run(command, cwd=ROOT, input=commands, text=True, capture_output=True, timeout=10)
    assert first.returncode == 0
    assert first.stderr == ""
    original = path.read_bytes()
    second = subprocess.run(command, cwd=ROOT, input=commands, text=True, capture_output=True, timeout=10)
    assert second.returncode == (0 if interactive else 2)
    assert "Cannot write static report" in second.stderr
    assert path.read_bytes() == original
