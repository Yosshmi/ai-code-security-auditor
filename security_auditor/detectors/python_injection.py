"""Detect selected command, path, and XSS injection patterns in Python."""

from __future__ import annotations

import ast
from pathlib import Path

from security_auditor.findings import Finding
from security_auditor.inventory import RepositoryInventory
from security_auditor.rules import (
    COMMAND_INJECTION_RULE_ID,
    PATH_TRAVERSAL_RULE_ID,
    XSS_RULE_ID,
)
from security_auditor.text_files import read_repository_text_file


SHELL_FUNCTIONS = frozenset({"os.system", "os.popen"})
SUBPROCESS_FUNCTIONS = frozenset(
    {
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.Popen",
        "subprocess.run",
    }
)
PATH_SINKS = frozenset(
    {
        "open",
        "Path",
        "pathlib.Path",
        "send_file",
        "flask.send_file",
    }
)
XSS_SINKS = frozenset(
    {
        "Markup",
        "mark_safe",
        "markupsafe.Markup",
        "render_template_string",
        "flask.render_template_string",
    }
)
REQUEST_CONTAINERS = frozenset({"args", "form", "GET", "POST", "values"})


def qualified_name(expression: ast.expr) -> str | None:
    """Return a dotted name such as ``subprocess.run`` when available."""

    if isinstance(expression, ast.Name):
        return expression.id
    if isinstance(expression, ast.Attribute):
        parent = qualified_name(expression.value)
        if parent is not None:
            return f"{parent}.{expression.attr}"
    return None


def is_static_string(expression: ast.expr) -> bool:
    return isinstance(expression, ast.Constant) and isinstance(expression.value, str)


def has_shell_true(call: ast.Call) -> bool:
    return any(
        keyword.arg == "shell"
        and isinstance(keyword.value, ast.Constant)
        and keyword.value.value is True
        for keyword in call.keywords
    )


def is_request_container(expression: ast.expr) -> bool:
    return (
        isinstance(expression, ast.Attribute)
        and isinstance(expression.value, ast.Name)
        and expression.value.id == "request"
        and expression.attr in REQUEST_CONTAINERS
    )


def is_direct_request_input(expression: ast.expr) -> bool:
    """Recognize direct Flask/Django-style request value access."""

    if isinstance(expression, ast.Subscript):
        return is_request_container(expression.value)

    return (
        isinstance(expression, ast.Call)
        and isinstance(expression.func, ast.Attribute)
        and expression.func.attr == "get"
        and is_request_container(expression.func.value)
    )


class PythonInjectionVisitor(ast.NodeVisitor):
    """Collect selected direct source-to-sink injection patterns."""

    def __init__(self, relative_path: str) -> None:
        self.relative_path = relative_path
        self.findings: list[Finding] = []

    def add_finding(
        self,
        rule_id: str,
        line_number: int,
        evidence: str,
        message: str,
    ) -> None:
        self.findings.append(
            Finding(
                rule_id=rule_id,
                relative_path=self.relative_path,
                line_number=line_number,
                evidence=evidence,
                message=message,
            )
        )

    def visit_Call(self, node: ast.Call) -> None:
        function_name = qualified_name(node.func)

        if function_name in SHELL_FUNCTIONS and node.args:
            if not is_static_string(node.args[0]):
                self.add_finding(
                    COMMAND_INJECTION_RULE_ID,
                    node.lineno,
                    f"{function_name}(<dynamic command>)",
                    "Dynamic input reaches a shell command",
                )

        if function_name in SUBPROCESS_FUNCTIONS and node.args:
            if has_shell_true(node) and not is_static_string(node.args[0]):
                self.add_finding(
                    COMMAND_INJECTION_RULE_ID,
                    node.lineno,
                    f"{function_name}(<dynamic command>, shell=True)",
                    "Dynamic input reaches subprocess execution with shell=True",
                )

        if function_name in PATH_SINKS and node.args:
            if is_direct_request_input(node.args[0]):
                self.add_finding(
                    PATH_TRAVERSAL_RULE_ID,
                    node.lineno,
                    f"{function_name}(<request-controlled path>)",
                    "Request input reaches a filesystem path without visible validation",
                )

        if function_name in XSS_SINKS and node.args:
            if is_direct_request_input(node.args[0]):
                self.add_finding(
                    XSS_RULE_ID,
                    node.lineno,
                    f"{function_name}(<request-controlled HTML>)",
                    "Request input reaches an HTML escaping bypass or template source",
                )

        self.generic_visit(node)


def find_python_injection_patterns(
    text: str,
    relative_path: str,
) -> tuple[Finding, ...]:
    """Parse Python text and return selected direct injection findings."""

    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return ()

    visitor = PythonInjectionVisitor(relative_path)
    visitor.visit(tree)
    return tuple(visitor.findings)


def detect_python_injection(
    repository_root: Path,
    inventory: RepositoryInventory,
) -> tuple[Finding, ...]:
    """Run selected Python injection rules across an existing inventory."""

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

        findings.extend(find_python_injection_patterns(text, file.relative_path))

    return tuple(findings)
