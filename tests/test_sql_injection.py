from __future__ import annotations

import tempfile
import textwrap
import unittest
from pathlib import Path

from security_auditor.detectors.sql_injection import (
    detect_sql_injection,
    find_sql_injection_in_python,
)
from security_auditor.inventory import collect_repository_inventory


class FindSqlInjectionInPythonTests(unittest.TestCase):
    def test_finds_selected_dynamic_query_patterns(self) -> None:
        text = textwrap.dedent(
            '''
            cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
            cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")
            cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)
            cursor.executemany("INSERT INTO users VALUES ({})".format(value), rows)
            '''
        )

        findings = find_sql_injection_in_python(text, "queries.py")

        self.assertEqual(len(findings), 4)
        self.assertEqual(
            [finding.line_number for finding in findings],
            [2, 3, 4, 5],
        )
        self.assertEqual(
            [finding.evidence for finding in findings],
            [
                "execute(<dynamic f-string query>)",
                "execute(<dynamic string concatenation query>)",
                "execute(<dynamic percent formatting query>)",
                "executemany(<dynamic str.format query>)",
            ],
        )

    def test_ignores_parameterized_and_static_queries(self) -> None:
        text = textwrap.dedent(
            '''
            cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
            cursor.execute("SELECT count(*) FROM users")
            '''
        )

        findings = find_sql_injection_in_python(text, "queries.py")

        self.assertEqual(findings, ())

    def test_returns_no_findings_for_malformed_python(self) -> None:
        findings = find_sql_injection_in_python("def broken(:", "broken.py")

        self.assertEqual(findings, ())


class DetectSqlInjectionTests(unittest.TestCase):
    def test_scans_python_files_but_not_other_extensions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            unsafe_query = 'cursor.execute(f"SELECT {user_input}")'
            (root / "unsafe.py").write_text(unsafe_query, encoding="utf-8")
            (root / "example.txt").write_text(unsafe_query, encoding="utf-8")

            inventory = collect_repository_inventory(root)
            findings = detect_sql_injection(root, inventory)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].relative_path, "unsafe.py")
        self.assertEqual(findings[0].rule_id, "SQL001")


if __name__ == "__main__":
    unittest.main()

