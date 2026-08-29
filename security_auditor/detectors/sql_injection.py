"""Detect selected dynamic SQL construction patterns in Python code."""

from __future__ import annotations

import ast
from pathlib import Path

from security_auditor.findings import Finding
from security_auditor.inventory import RepositoryInventory
from security_auditor.rules import SQL_INJECTION_RULE_ID
from security_auditor.text_files import read_repository_text_file


RULE_ID = SQL_INJECTION_RULE_ID
SQL_EXECUTION_METHODS = frozenset({"execute", "executemany"})


def dynamic_query_kind(expression: ast.expr) -> str | None:
    """Describe a directly constructed dynamic query expression."""

    if isinstance(expression, ast.JoinedStr):
        return "f-string"

    if isinstance(expression, ast.BinOp):
        if isinstance(expression.op, ast.Add):
            return "string concatenation"
        if isinstance(expression.op, ast.Mod):
            return "percent formatting"

    if (
        isinstance(expression, ast.Call)
        and isinstance(expression.func, ast.Attribute)
        and expression.func.attr == "format"
    ):
        return "str.format"

    return None


class SQLExecutionVisitor(ast.NodeVisitor):
    """Collect risky SQL execution calls from a Python syntax tree."""

    def __init__(self, relative_path: str) -> None:
        self.relative_path = relative_path
        self.findings: list[Finding] = []

    def visit_Call(self, node: ast.Call) -> None:
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in SQL_EXECUTION_METHODS
            and node.args
        ):
            query_kind = dynamic_query_kind(node.args[0])
            if query_kind is not None:
                method = node.func.attr
                self.findings.append(
                    Finding(
                        rule_id=RULE_ID,
                        relative_path=self.relative_path,
                        line_number=node.lineno,
                        evidence=f"{method}(<dynamic {query_kind} query>)",
                        message=(
                            f"Dynamic SQL built with {query_kind} is passed to "
                            f"{method}; use a parameterized query"
                        ),
                    )
                )

        self.generic_visit(node)


def find_sql_injection_in_python(
    text: str,
    relative_path: str,
) -> tuple[Finding, ...]:
    """Parse Python text and return selected dynamic SQL findings."""

    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return ()

    visitor = SQLExecutionVisitor(relative_path)
    visitor.visit(tree)
    return tuple(visitor.findings)


def detect_sql_injection(
    repository_root: Path,
    inventory: RepositoryInventory,
) -> tuple[Finding, ...]:
    """Run Python SQL-injection rules across an existing inventory."""

    findings: list[Finding] = []
    for file in inventory.files:
        if file.extension != ".py":
            continue

        text = read_repository_text_file(
            repository_root=repository_root,
            relative_path=file.relative_path,
            size_bytes=file.size_bytes,
        )
        if text is None:
            continue

        findings.extend(find_sql_injection_in_python(text, file.relative_path))

    return tuple(findings)
