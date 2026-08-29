"""Command-line entry point for the security auditor."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path


class RepositoryPathError(ValueError):
    """Raised when a supplied repository path cannot be accepted."""


def validate_repository_path(raw_path: str) -> Path:
    """Return a normalized repository directory or raise a helpful error."""

    candidate = Path(raw_path).expanduser()

    try:
        repository_path = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise RepositoryPathError(
            f"repository path does not exist or cannot be accessed: {candidate}"
        ) from error

    if not repository_path.is_dir():
        raise RepositoryPathError(
            f"repository path must be a directory: {repository_path}"
        )

    return repository_path


def build_parser() -> argparse.ArgumentParser:
    """Create the argument parser used by the command-line interface."""

    parser = argparse.ArgumentParser(
        prog="security-auditor",
        description="Validate a local repository path for a future security scan.",
    )
    parser.add_argument("repository", help="path to the local repository directory")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Validate CLI input and return a process exit code."""

    args = build_parser().parse_args(argv)

    try:
        repository_path = validate_repository_path(args.repository)
    except RepositoryPathError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    print(f"Repository accepted: {repository_path}")
    return 0

