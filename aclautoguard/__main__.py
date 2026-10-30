"""Allow running ACLAutoGuard with python -m aclautoguard."""

from aclautoguard.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
