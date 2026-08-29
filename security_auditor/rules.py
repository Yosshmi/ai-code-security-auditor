"""Metadata for deterministic security rules."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RuleDefinition:
    rule_id: str
    name: str
    category: str
    description: str


SECRET_RULE_ID = "SEC001"
SQL_INJECTION_RULE_ID = "SQL001"
COMMAND_INJECTION_RULE_ID = "CMD001"
PATH_TRAVERSAL_RULE_ID = "PATH001"
XSS_RULE_ID = "XSS001"

RULE_DEFINITIONS = (
    RuleDefinition(
        rule_id=SECRET_RULE_ID,
        name="Hardcoded secret",
        category="secrets",
        description="Possible credential assigned directly in repository text.",
    ),
    RuleDefinition(
        rule_id=SQL_INJECTION_RULE_ID,
        name="Dynamic SQL execution",
        category="injection",
        description="Dynamic SQL construction passed directly to a Python database API.",
    ),
    RuleDefinition(
        rule_id=COMMAND_INJECTION_RULE_ID,
        name="Dynamic shell command",
        category="injection",
        description="Dynamic input passed to a Python shell execution API.",
    ),
    RuleDefinition(
        rule_id=PATH_TRAVERSAL_RULE_ID,
        name="Request-controlled filesystem path",
        category="path-traversal",
        description="Direct request input passed to a Python filesystem path sink.",
    ),
    RuleDefinition(
        rule_id=XSS_RULE_ID,
        name="Unsafe request-controlled HTML",
        category="xss",
        description="Direct request input passed to an escaping bypass or template source.",
    ),
)

