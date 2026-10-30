"""Ctrl+C cancels input or local work without terminating the shell."""

from unittest.mock import Mock

import pytest

from aclautoguard import shell


@pytest.mark.parametrize("finish", ["exit", EOFError()])
def test_interrupt_at_prompt_keeps_shell_usable(monkeypatch, capsys, finish):
    reader = Mock(side_effect=[KeyboardInterrupt(), KeyboardInterrupt(), "help", finish])
    monkeypatch.setattr("builtins.input", reader)
    assert shell.run_shell() == 0
    output = capsys.readouterr()
    assert "Cancelled" not in output.out
    assert "Available commands:" in output.out
    assert output.err == ""
    assert reader.call_count == 4


@pytest.mark.parametrize("command,operation", [
    ("analyze policy.yaml", "run_analysis"),
    ("check p.yaml r.yaml --ids T1", "run_requirement_check"),
    ("assess p.yaml r.yaml --ids T1", "run_assessment"),
])
def test_interrupted_command_returns_to_prompt(monkeypatch, capsys, command, operation):
    monkeypatch.setattr("builtins.input", Mock(side_effect=[command, "help", "exit"]))
    runner = Mock(side_effect=KeyboardInterrupt())
    monkeypatch.setattr(shell, operation, runner)
    assert shell.run_shell() == 0
    runner.assert_called_once()
    output = capsys.readouterr()
    assert "Cancelled" not in output.out
    assert "Available commands:" in output.out
    assert output.err == ""
