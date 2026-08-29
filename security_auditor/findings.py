"""Shared finding records produced by deterministic security rules."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Finding:
    """Evidence that one deterministic security rule matched a file."""

    rule_id: str
    relative_path: str
    line_number: int
    evidence: str
    message: str

