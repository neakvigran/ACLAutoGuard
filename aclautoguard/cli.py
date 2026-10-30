"""Select the interactive shell or a noninteractive command."""

import argparse
import sys

from aclautoguard.arguments import add_check_arguments, add_report_argument
from aclautoguard.shell import run_shell
from aclautoguard.terminal import run_analysis, run_requirement_check, run_assessment


def main(argv: list[str] | None = None) -> int:
    """Open the shell without arguments, otherwise run a CLI command."""
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        return run_shell()
    parser = argparse.ArgumentParser(prog="aclautoguard")
    commands = parser.add_subparsers(dest="command", required=True)
    analyze = commands.add_parser(
        "analyze", help="validate a policy and find single-rule shadows"
    )
    analyze.add_argument("policy_path", help="path to a YAML policy file")
    check = commands.add_parser(
        "check", help="compare selected host requirements with modeled ACL decisions"
    )
    add_check_arguments(check)
    assess = commands.add_parser(
        "assess", help="combine shadow analysis and selected host requirement checks"
    )
    add_check_arguments(assess)
    add_report_argument(assess)
    args = parser.parse_args(argv)

    if args.command == "assess":
        return run_assessment(args.policy_path, args.requirements_path, args.ids, report_path=args.report)
    if args.command == "check":
        return run_requirement_check(args.policy_path, args.requirements_path, args.ids)
    return run_analysis(args.policy_path)
