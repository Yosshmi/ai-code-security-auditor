"""Command-line entry point for the security auditor."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from security_auditor.detectors.python_injection import (
    COMMAND_INJECTION_RULE_ID,
    PATH_TRAVERSAL_RULE_ID,
    XSS_RULE_ID,
    detect_python_injection,
)
from security_auditor.detectors.secrets import detect_secrets
from security_auditor.detectors.sql_injection import detect_sql_injection
from security_auditor.findings import Finding
from security_auditor.inventory import InventoryError, collect_repository_inventory


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


def print_findings(label: str, findings: Sequence[Finding]) -> None:
    """Print one consistently formatted group of deterministic findings."""

    print(f"{label}: {len(findings)}")
    for finding in findings:
        print(
            f"  [{finding.rule_id}] "
            f"{finding.relative_path}:{finding.line_number} - {finding.message}"
        )
        print(f"    Evidence: {finding.evidence}")


def main(argv: Sequence[str] | None = None) -> int:
    """Validate CLI input, build an inventory, and return a process exit code."""

    args = build_parser().parse_args(argv)

    try:
        repository_path = validate_repository_path(args.repository)
    except RepositoryPathError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    try:
        inventory = collect_repository_inventory(repository_path)
    except InventoryError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    print(f"Repository accepted: {repository_path}")
    print(f"Files: {inventory.total_files}")
    print(f"Total size: {inventory.total_size_bytes} bytes")

    print("File inventory:")
    for file in inventory.files:
        print(f"  {file.relative_path} ({file.size_bytes} bytes)")

    print("Extensions:")
    for extension, count in sorted(inventory.extension_counts.items()):
        print(f"  {extension}: {count}")

    if inventory.skipped_directories:
        print("Skipped directories:")
        for directory in inventory.skipped_directories:
            print(f"  {directory}")

    if inventory.skipped_symbolic_links:
        print("Skipped symbolic links:")
        for link in inventory.skipped_symbolic_links:
            print(f"  {link}")

    secret_findings = detect_secrets(repository_path, inventory)
    print_findings("Potential secrets", secret_findings)

    sql_findings = detect_sql_injection(repository_path, inventory)
    print_findings("Potential SQL injection patterns", sql_findings)

    injection_findings = detect_python_injection(repository_path, inventory)
    command_findings = tuple(
        finding
        for finding in injection_findings
        if finding.rule_id == COMMAND_INJECTION_RULE_ID
    )
    path_findings = tuple(
        finding
        for finding in injection_findings
        if finding.rule_id == PATH_TRAVERSAL_RULE_ID
    )
    xss_findings = tuple(
        finding for finding in injection_findings if finding.rule_id == XSS_RULE_ID
    )
    print_findings("Potential command injection patterns", command_findings)
    print_findings("Potential path traversal patterns", path_findings)
    print_findings("Potential XSS patterns", xss_findings)

    return 0
