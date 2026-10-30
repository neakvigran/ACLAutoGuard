"""Verify interactive sessions through the application entry point."""

from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]


def session(commands):
    return subprocess.run(
        [sys.executable, "-m", "aclautoguard"],
        cwd=ROOT,
        input=commands,
        capture_output=True,
        text=True,
        timeout=10,
    )


def test_help_and_exit():
    result = session("help\nhelp analyze\nexit\nunknown\n")
    assert result.returncode == 0
    assert "ACLAutoGuard> " in result.stdout
    assert "Available commands: help, analyze, check, assess, exit" in result.stdout
    assert "analyze <policy-path>" in result.stdout
    assert result.stderr == ""


def test_general_help_includes_arguments_and_examples_for_every_command():
    result = session("help\nexit\n")
    assert result.returncode == 0
    assert result.stderr == ""
    for usage in (
        "help [command]", "analyze <policy-path>",
        "check <policy-path> <requirements-path> --ids ID [ID ...]",
        "assess <policy-path> <requirements-path> --ids ID [ID ...] [--report PATH]",
        "Close ACLAutoGuard. Takes no arguments.",
    ):
        assert usage in result.stdout
    for detail in (
        "policy-path (required)", "requirements-path (required)",
        "--ids (required)", "--report PATH (optional)", "-h, --help (optional)",
        "Existing files are never overwritten", "Quote paths containing spaces",
        "analyze examples/policies/shadowed.yaml",
        "check examples/policies/corrected.yaml examples/requirements/baseline.yaml --ids T1 T2 T3",
        '--report "static evidence.json"',
    ):
        assert detail in result.stdout
    assert "setup" not in result.stdout
    assert "deploy" not in result.stdout


@pytest.mark.parametrize("command", ["help", "analyze", "check", "assess", "exit"])
def test_command_help_matches_general_help(command):
    from aclautoguard.shell import HELP

    result = session(f"help {command}\nexit\n")
    assert result.returncode == 0
    assert result.stderr == ""
    assert HELP[command] in result.stdout
    assert "Example" in result.stdout


@pytest.mark.parametrize("commands", ["", "\n", "help\n"])
def test_clean_eof(commands):
    result = session(commands)
    assert result.returncode == 0
    assert result.stderr == ""


def test_analysis_results_do_not_end_session():
    result = session(
        "analyze examples/policies/shadowed.yaml\n"
        "analyze examples/policies/corrected.yaml\nexit\n"
    )
    assert result.returncode == 0
    assert "rule_20 is fully shadowed by earlier rule rule_10" in result.stdout
    assert "No single-earlier-rule shadows found." in result.stdout
    assert result.stderr == ""


def test_quoted_path_with_spaces(tmp_path):
    path = tmp_path / "corrected policy.yaml"
    path.write_bytes((ROOT / "examples/policies/corrected.yaml").read_bytes())
    result = session(f'analyze "{path}"\nexit\n')
    assert result.returncode == 0
    assert "No single-earlier-rule shadows found." in result.stdout
    assert result.stderr == ""


@pytest.mark.parametrize(
    "command,error",
    [
        ("unknown", "Unknown command"),
        ("analyze", "Usage: analyze"),
        ("analyze one two", "Usage: analyze"),
        ('analyze "unfinished', "No closing quotation"),
        ("analyze missing-file.yaml", "Cannot read policy"),
        ("exit extra", "Usage: exit"),
        ("help setup", "Usage: help"),
    ],
)
def test_error_keeps_shell_usable(command, error):
    result = session(f"{command}\nhelp\nexit\n")
    assert result.returncode == 0
    assert error in result.stderr
    assert "Traceback" not in result.stderr
    assert "Available commands:" in result.stdout


def test_invalid_policy_keeps_shell_usable(tmp_path):
    path = tmp_path / "invalid.yaml"
    path.write_text("rules: []\n", encoding="utf-8")
    result = session(f'analyze "{path}"\nhelp\nexit\n')
    assert result.returncode == 0
    assert "Missing fields" in result.stderr
    assert "Available commands:" in result.stdout
