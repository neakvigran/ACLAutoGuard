"""Select the interactive shell or a noninteractive command."""

import argparse
import sys

from aclautoguard.shell import run_shell
from aclautoguard.terminal import run_analysis


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
    args = parser.parse_args(argv)

    return run_analysis(args.policy_path)
