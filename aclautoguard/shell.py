"""Interactive terminal shell for the currently implemented operations."""

import shlex
import sys

from aclautoguard.terminal import run_analysis


HELP = {
    "help": "help [command]: show available commands or command help.",
    "analyze": 'analyze <policy-path>: validate and find single-rule shadows. '
    'Quote paths containing spaces: analyze "my policies/policy.yaml"',
    "exit": "exit: close ACLAutoGuard. EOF also closes the shell.",
}


def run_shell() -> int:
    """Read commands until exit or EOF; analysis errors keep the shell open."""
    print("ACLAutoGuard — type help for available commands.")
    while True:
        try:
            line = input("ACLAutoGuard> ")
        except EOFError:
            print()
            return 0
        except KeyboardInterrupt:
            print()
            return 130

        try:
            words = shlex.split(line)
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            continue
        if not words:
            continue

        command, *args = words
        if command == "exit":
            if args:
                print("Usage: exit", file=sys.stderr)
            else:
                return 0
        elif command == "help":
            if not args:
                print("Available commands: help, analyze, exit")
            elif len(args) == 1 and args[0] in HELP:
                print(HELP[args[0]])
            else:
                print("Usage: help [help|analyze|exit]", file=sys.stderr)
        elif command == "analyze":
            if len(args) != 1:
                print("Usage: analyze <policy-path>", file=sys.stderr)
            else:
                run_analysis(args[0])
        else:
            print(f"Unknown command: {command}. Type help.", file=sys.stderr)
