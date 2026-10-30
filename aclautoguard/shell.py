"""Interactive terminal shell for the currently implemented operations."""

import argparse
import shlex
import sys

from aclautoguard.arguments import add_check_arguments, add_report_argument
from aclautoguard.terminal import run_analysis, run_requirement_check, run_assessment


HELP = {
    "help": (
        "help [command]\n"
        "  Show all commands, arguments, and examples.\n"
        "  command (optional): show help for just that command.\n"
        "  Examples:\n"
        "    help\n"
        "    help assess"
    ),
    "analyze": (
        "analyze <policy-path>\n"
        "  Validate a policy and find single-earlier-rule shadows.\n"
        "  policy-path (required): path to a YAML policy file.\n"
        "  Examples:\n"
        "    analyze examples/policies/shadowed.yaml\n"
        '    analyze "my policies/policy.yaml"'
    ),
    "check": (
        "check <policy-path> <requirements-path> --ids ID [ID ...]\n"
        "  Compare selected host requirements with modeled ACL decisions.\n"
        "  policy-path (required): path to a YAML policy file.\n"
        "  requirements-path (required): path to independent YAML requirements.\n"
        "  --ids (required): one or more applicable requirement IDs, separated by spaces.\n"
        "  -h, --help (optional): show argument help and return to the prompt.\n"
        "  Examples:\n"
        "    check examples/policies/corrected.yaml examples/requirements/baseline.yaml --ids T1 T2 T3\n"
        "    check --help"
    ),
    "assess": (
        "assess <policy-path> <requirements-path> --ids ID [ID ...] [--report PATH]\n"
        "  Combine shadow analysis and selected host requirement checks.\n"
        "  policy-path (required): path to a YAML policy file.\n"
        "  requirements-path (required): path to independent YAML requirements.\n"
        "  --ids (required): one or more applicable requirement IDs, separated by spaces.\n"
        "  --report PATH (optional): create a static JSON report; parent directory must exist.\n"
        "    Existing files are never overwritten.\n"
        "  -h, --help (optional): show argument help and return to the prompt.\n"
        "  Examples:\n"
        "    assess examples/policies/corrected.yaml examples/requirements/baseline.yaml --ids T1 T2 T3\n"
        '    assess examples/policies/shadowed.yaml examples/requirements/baseline.yaml --ids T1 --report "static evidence.json"\n'
        "    assess --help"
    ),
    "exit": (
        "exit\n"
        "  Close ACLAutoGuard. Takes no arguments. EOF also closes the shell.\n"
        "  Example:\n"
        "    exit"
    ),
}


def run_shell() -> int:
    """Read commands until exit or EOF; analysis errors keep the shell open."""
    print("ACLAutoGuard — type help for available commands.")
    check_parser = argparse.ArgumentParser(prog="check")
    add_check_arguments(check_parser)
    assess_parser = argparse.ArgumentParser(prog="assess")
    add_check_arguments(assess_parser)
    add_report_argument(assess_parser)
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
                print("Available commands: help, analyze, check, assess, exit")
                print(
                    "Arguments in <angle brackets> are required; [square brackets] are optional.\n"
                    "Replace placeholders without typing the brackets. Quote paths containing spaces.\n"
                    "Paths are relative to your current directory. These commands send no network traffic.\n"
                    "Selected IDs assert ACL applicability; they do not verify network paths.\n"
                )
                print("\n\n".join(HELP.values()))
            elif len(args) == 1 and args[0] in HELP:
                print(HELP[args[0]])
            else:
                print("Usage: help [help|analyze|check|assess|exit]", file=sys.stderr)
        elif command == "analyze":
            if len(args) != 1:
                print("Usage: analyze <policy-path>", file=sys.stderr)
            else:
                run_analysis(args[0])
        elif command in ("check", "assess"):
            try:
                parsed = (check_parser if command == "check" else assess_parser).parse_args(args)
            except SystemExit:
                # argparse exits for usage errors and --help; keep the shell open.
                continue
            if command == "check":
                run_requirement_check(parsed.policy_path, parsed.requirements_path, parsed.ids)
            else:
                run_assessment(parsed.policy_path, parsed.requirements_path, parsed.ids, report_path=parsed.report)
        else:
            print(f"Unknown command: {command}. Type help.", file=sys.stderr)
