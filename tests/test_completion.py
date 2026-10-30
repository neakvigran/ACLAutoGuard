"""Verify command context and shell-safe filename completion."""

import shlex

import pytest

from aclautoguard.completion import complete_line


def test_commands_and_help():
    assert complete_line("ana") == ["analyze "]
    assert complete_line("help ass") == ["help assess "]
    assert complete_line("exit ") == []
    assert complete_line("unknown ") == []


def test_options_and_ids():
    assert complete_line("assess --rep") == ["assess --report "]
    assert complete_line("check --rep") == []
    assert complete_line("check p r --ids T") == []


@pytest.mark.parametrize("fragment", ["my", '"my', "'my", "my\\ "])
def test_spaces_in_filenames(tmp_path, monkeypatch, fragment):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "my policy.yaml").touch()
    matches = complete_line("analyze " + fragment)
    assert len(matches) == 1
    assert shlex.split(matches[0]) == ["analyze", "my policy.yaml"]


def test_directory_and_nested_completion(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    folder = tmp_path / "policy examples"
    folder.mkdir()
    (folder / "test.yaml").touch()
    first = complete_line("analyze pol")[0]
    assert shlex.split(first) == ["analyze", "policy examples/"]
    assert shlex.split(complete_line(first + "te")[0]) == ["analyze", "policy examples/test.yaml"]


def test_argument_context_and_hidden_files(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "policy.yaml").touch()
    (tmp_path / ".hidden").touch()
    assert complete_line("analyze ") == ["analyze policy.yaml "]
    assert complete_line("analyze .") == ["analyze .hidden "]
    assert complete_line("analyze policy.yaml ") == []
    assert complete_line("check policy.yaml pol") == ["check policy.yaml policy.yaml "]
    assert complete_line("assess p r --ids T1 --report pol") == ["assess p r --ids T1 --report policy.yaml "]
    assert complete_line("assess p r --ids T1 pol") == []
    assert complete_line("analyze missing/") == []


def test_absolute_paths_and_quotes(tmp_path):
    path = tmp_path / "it's a policy.yaml"
    path.touch()
    matches = complete_line(f"analyze {tmp_path}/it")
    assert shlex.split(matches[0]) == ["analyze", str(path)]
