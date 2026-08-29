from __future__ import annotations

import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from security_auditor.cli import main, validate_repository_path


class ValidateRepositoryPathTests(unittest.TestCase):
    def test_accepts_an_existing_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = validate_repository_path(directory)

        self.assertEqual(result, Path(directory).resolve())

    def test_rejects_a_missing_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing_path = Path(directory) / "missing-repository"

            with self.assertRaisesRegex(
                ValueError, "does not exist or cannot be accessed"
            ):
                validate_repository_path(str(missing_path))

    def test_rejects_a_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            file_path = Path(directory) / "not-a-repository.txt"
            file_path.write_text("not a directory", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "must be a directory"):
                validate_repository_path(str(file_path))


class MainTests(unittest.TestCase):
    def test_valid_path_prints_confirmation_and_returns_success(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = io.StringIO()

            with redirect_stdout(output):
                exit_code = main([directory])

        self.assertEqual(exit_code, 0)
        self.assertIn("Repository accepted:", output.getvalue())
        self.assertIn("Files: 0", output.getvalue())
        self.assertIn("Total size: 0 bytes", output.getvalue())
        self.assertIn("Potential secrets: 0", output.getvalue())
        self.assertIn("Potential SQL injection patterns: 0", output.getvalue())
        self.assertIn("Potential command injection patterns: 0", output.getvalue())
        self.assertIn("Potential path traversal patterns: 0", output.getvalue())
        self.assertIn("Potential XSS patterns: 0", output.getvalue())

    def test_invalid_path_prints_helpful_error_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing_path = Path(directory) / "missing-repository"
            error_output = io.StringIO()

            with redirect_stderr(error_output):
                exit_code = main([str(missing_path)])

        message = error_output.getvalue()
        self.assertEqual(exit_code, 2)
        self.assertIn("error:", message)
        self.assertNotIn("Traceback", message)


if __name__ == "__main__":
    unittest.main()
