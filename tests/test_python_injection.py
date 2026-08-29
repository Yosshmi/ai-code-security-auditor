from __future__ import annotations

import tempfile
import textwrap
import unittest
from pathlib import Path

from security_auditor.detectors.python_injection import (
    COMMAND_INJECTION_RULE_ID,
    PATH_TRAVERSAL_RULE_ID,
    XSS_RULE_ID,
    detect_python_injection,
    find_python_injection_patterns,
)
from security_auditor.inventory import collect_repository_inventory


class FindPythonInjectionPatternsTests(unittest.TestCase):
    def test_finds_dynamic_shell_execution(self) -> None:
        text = textwrap.dedent(
            '''
            os.system(command)
            os.popen(f"grep {term} file.txt")
            subprocess.run("grep " + term, shell=True)
            '''
        )

        findings = find_python_injection_patterns(text, "commands.py")

        self.assertEqual(len(findings), 3)
        self.assertTrue(
            all(finding.rule_id == COMMAND_INJECTION_RULE_ID for finding in findings)
        )
        self.assertEqual([finding.line_number for finding in findings], [2, 3, 4])

    def test_ignores_static_shell_command_and_shell_free_argument_list(self) -> None:
        text = textwrap.dedent(
            '''
            os.system("date")
            subprocess.run(["grep", term, "file.txt"], check=True)
            '''
        )

        findings = find_python_injection_patterns(text, "commands.py")

        self.assertEqual(findings, ())

    def test_finds_direct_request_input_reaching_path_sinks(self) -> None:
        text = textwrap.dedent(
            '''
            open(request.args["filename"])
            Path(request.GET.get("path"))
            flask.send_file(request.form["download"])
            '''
        )

        findings = find_python_injection_patterns(text, "downloads.py")

        self.assertEqual(len(findings), 3)
        self.assertTrue(
            all(finding.rule_id == PATH_TRAVERSAL_RULE_ID for finding in findings)
        )

    def test_ignores_constant_and_indirect_paths(self) -> None:
        text = textwrap.dedent(
            '''
            open("settings.json")
            open(validated_path)
            '''
        )

        findings = find_python_injection_patterns(text, "files.py")

        self.assertEqual(findings, ())

    def test_finds_request_input_reaching_unsafe_html_sinks(self) -> None:
        text = textwrap.dedent(
            '''
            render_template_string(request.args["template"])
            Markup(request.form.get("html"))
            mark_safe(request.POST["content"])
            '''
        )

        findings = find_python_injection_patterns(text, "views.py")

        self.assertEqual(len(findings), 3)
        self.assertTrue(all(finding.rule_id == XSS_RULE_ID for finding in findings))

    def test_ignores_normal_template_rendering(self) -> None:
        text = 'render_template("profile.html", name=request.args.get("name"))'

        findings = find_python_injection_patterns(text, "views.py")

        self.assertEqual(findings, ())

    def test_returns_no_findings_for_malformed_python(self) -> None:
        findings = find_python_injection_patterns("def broken(:", "broken.py")

        self.assertEqual(findings, ())


class DetectPythonInjectionTests(unittest.TestCase):
    def test_scans_python_files_end_to_end(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "commands.py").write_text(
                "os.system(user_command)",
                encoding="utf-8",
            )
            (root / "commands.txt").write_text(
                "os.system(user_command)",
                encoding="utf-8",
            )

            inventory = collect_repository_inventory(root)
            findings = detect_python_injection(root, inventory)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].relative_path, "commands.py")


if __name__ == "__main__":
    unittest.main()

