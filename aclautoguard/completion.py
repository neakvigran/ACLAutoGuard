"""Readline completion with shell-safe path insertion."""

from contextlib import contextmanager
from pathlib import Path
import shlex


COMMANDS = ("help", "analyze", "check", "assess", "exit")


def complete_line(line: str) -> list[str]:
    """Return complete replacements for the input before the cursor."""
    start, quote, escaped = 0, None, False
    for index, character in enumerate(line):
        if escaped:
            escaped = False
        elif character == "\\" and quote != "'":
            escaped = True
        elif quote:
            if character == quote:
                quote = None
        elif character in ("'", '"'):
            quote = character
        elif character.isspace():
            start = index + 1
    if escaped:
        return []
    try:
        previous = shlex.split(line[:start])
        fragment = shlex.split(line[start:] + (quote or ""))
    except ValueError:
        return []
    prefix = fragment[0] if fragment else ""
    before = line[:start]
    if not previous:
        return [before + name + " " for name in COMMANDS if name.startswith(prefix)]
    command, *arguments = previous
    if command == "help":
        return [before + name + " " for name in COMMANDS if not arguments and name.startswith(prefix)]
    if command not in ("analyze", "check", "assess"):
        return []
    options = ["--ids", "--help"] if command != "analyze" else []
    if command == "assess":
        options.append("--report")
    if prefix.startswith("-"):
        return [before + option + " " for option in options if option.startswith(prefix)]

    positionals, mode = 0, None
    for argument in arguments:
        if argument == "--report":
            mode = "report"
        elif argument == "--ids":
            mode = "ids"
        elif argument.startswith("-"):
            mode = "option"
        elif mode == "report":
            mode = None
        elif mode is None:
            positionals += 1
    limit = 1 if command == "analyze" else 2
    if mode != "report" and (mode is not None or positionals >= limit):
        return []

    directory, separator, basename = prefix.rpartition("/")
    parent = Path(directory + separator if separator else ".")
    try:
        children = sorted(parent.iterdir(), key=lambda item: item.name)
        matches = []
        for child in children:
            if not child.name.startswith(basename):
                continue
            if child.name.startswith(".") and not basename.startswith("."):
                continue
            is_directory = child.is_dir()
            candidate = directory + separator + child.name + ("/" if is_directory else "")
            matches.append(before + shlex.quote(candidate) + ("" if is_directory else " "))
        return matches
    except OSError:
        return []


@contextmanager
def terminal_completion():
    """Enable completion where readline exists; restore caller configuration."""
    try:
        import readline
    except ImportError:
        yield False
        return
    previous = readline.get_completer()
    delimiters = readline.get_completer_delims()
    matches = []

    def complete(text, state):
        nonlocal matches
        if state == 0:
            matches = complete_line(readline.get_line_buffer()[:readline.get_endidx()])
        return matches[state] if state < len(matches) else None

    try:
        readline.set_completer_delims("")
        readline.set_completer(complete)
        if getattr(readline, "backend", "readline") == "editline":
            readline.parse_and_bind("bind ^I rl_complete")
        else:
            readline.parse_and_bind("tab: complete")
        yield True
    finally:
        readline.set_completer(previous)
        readline.set_completer_delims(delimiters)
