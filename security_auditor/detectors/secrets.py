"""Detect possible secrets assigned directly in repository text files."""

from __future__ import annotations

import re
from pathlib import Path

from security_auditor.findings import Finding
from security_auditor.inventory import RepositoryInventory
from security_auditor.text_files import (
    MAX_SCANNABLE_FILE_SIZE_BYTES,
    read_repository_text_file,
)


RULE_ID = "SEC001"

SECRET_ASSIGNMENT_PATTERN = re.compile(
    r"""
    (?P<key_quote>["']?)
    (?P<name>api[_-]?key|secret|token|password)
    (?P=key_quote)
    \s*(?P<separator>[:=])\s*
    (?P<value_quote>["'])
    (?P<value>[^"'\r\n]+)
    (?P=value_quote)
    """,
    re.IGNORECASE | re.VERBOSE,
)

PLACEHOLDER_VALUES = frozenset(
    {
        "change-me",
        "changeme",
        "dummy",
        "example",
        "example-key",
        "none",
        "null",
        "password",
        "replace-me",
        "secret",
        "test",
        "token",
        "your-api-key",
        "your-api-key-here",
    }
)


def redact_secret(value: str) -> str:
    """Return a recognizable preview without revealing the full candidate."""

    if len(value) <= 4:
        return "*" * len(value)

    visible_characters = 1 if len(value) < 12 else 3
    return (
        f"{value[:visible_characters]}..."
        f"{value[-visible_characters:]}"
    )


def find_secrets_in_text(text: str, relative_path: str) -> tuple[Finding, ...]:
    """Return redacted findings for hardcoded secret assignments in text."""

    findings: list[Finding] = []

    for line_number, line in enumerate(text.splitlines(), start=1):
        for match in SECRET_ASSIGNMENT_PATTERN.finditer(line):
            name = match.group("name")
            value = match.group("value").strip()

            if value.lower() in PLACEHOLDER_VALUES:
                continue

            redacted_value = redact_secret(value)
            separator = match.group("separator")
            findings.append(
                Finding(
                    rule_id=RULE_ID,
                    relative_path=relative_path,
                    line_number=line_number,
                    evidence=f'{name}{separator} "{redacted_value}"',
                    message=f"Possible hardcoded secret assigned to {name}",
                )
            )

    return tuple(findings)


def scan_file_for_secrets(
    repository_root: Path,
    relative_path: str,
    size_bytes: int,
) -> tuple[Finding, ...]:
    """Read one eligible text file and return possible secret findings."""

    text = read_repository_text_file(repository_root, relative_path, size_bytes)
    if text is None:
        return ()

    return find_secrets_in_text(text, relative_path)



def detect_secrets(
    repository_root: Path,
    inventory: RepositoryInventory,
) -> tuple[Finding, ...]:
    """Run the hardcoded-secret rule across an existing inventory."""

    findings: list[Finding] = []
    for file in inventory.files:
        findings.extend(
            scan_file_for_secrets(
                repository_root=repository_root,
                relative_path=file.relative_path,
                size_bytes=file.size_bytes,
            )
        )
    return tuple(findings)
