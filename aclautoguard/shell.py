"""Interactive terminal shell for the currently implemented operations."""

import argparse
import shlex
import sys

from aclautoguard.arguments import add_check_arguments
from aclautoguard.terminal import run_analysis, run_requirement_check


HELP = {
    "help": "help [command]: show available commands or command help.",
    "analyze": 'analyze <policy-path>: validate and find single-rule shadows. '
    'Quote paths containing spaces: analyze "my policies/policy.yaml"',
    "check": "check <policy-path> <requirements-path> --ids ID [ID ...]: "
    "compare selected host requirements with modeled ACL decisions. "
    "No traffic is sent. Quote paths containing spaces.",
    "exit": "exit: close ACLAutoGuard. EOF also closes the shell.",
}


def run_shell() -> int:
    """Read commands until exit or EOF; analysis errors keep the shell open."""
    print("ACLAutoGuard — type help for available commands.")
    check_parser = argparse.ArgumentParser(prog="check")
    add_check_arguments(check_parser)
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
                print("Available commands: help, analyze, check, exit")
            elif len(args) == 1 and args[0] in HELP:
                print(HELP[args[0]])
            else:
                print("Usage: help [help|analyze|check|exit]", file=sys.stderr)
        elif command == "analyze":
            if len(args) != 1:
                print("Usage: analyze <policy-path>", file=sys.stderr)
            else:
                run_analysis(args[0])
        elif command == "check":
            try:
                parsed = check_parser.parse_args(args)
            except SystemExit:
                # argparse exits for usage errors and --help; keep the shell open.
                continue
            run_requirement_check(parsed.policy_path, parsed.requirements_path, parsed.ids)
        else:
            print(f"Unknown command: {command}. Type help.", file=sys.stderr)
