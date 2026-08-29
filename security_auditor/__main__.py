"""Allow the package to run with ``python -m security_auditor``."""

from security_auditor.cli import main


if __name__ == "__main__":
    raise SystemExit(main())

