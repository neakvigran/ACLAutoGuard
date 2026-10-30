"""Argument definitions shared by interactive and noninteractive commands."""

import argparse


def add_check_arguments(parser: argparse.ArgumentParser) -> None:
    """Configure the same explicit requirement selection in both interfaces."""
    parser.add_argument("policy_path", help="path to a YAML policy file")
    parser.add_argument("requirements_path", help="path to an independent requirements file")
    parser.add_argument(
        "--ids", required=True, nargs="+", action="extend", metavar="ID",
        help="explicit requirement IDs applicable to this policy (e.g. T1 T2 T3)",
    )


def add_report_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--report", metavar="PATH", help="create a static JSON report; never overwrite an existing file"
    )
