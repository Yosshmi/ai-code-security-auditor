from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from security_auditor.detectors.secrets import (
    MAX_SCANNABLE_FILE_SIZE_BYTES,
    detect_secrets,
    find_secrets_in_text,
    redact_secret,
)
from security_auditor.inventory import collect_repository_inventory


class RedactSecretTests(unittest.TestCase):
    def test_redacts_short_values_completely(self) -> None:
        self.assertEqual(redact_secret("abcd"), "****")

    def test_redacts_long_values_without_returning_the_original(self) -> None:
        candidate = "fake-secret-value-123456"

        redacted = redact_secret(candidate)

        self.assertEqual(redacted, "fak...456")
        self.assertNotIn(candidate, redacted)


class FindSecretsInTextTests(unittest.TestCase):
    def test_finds_assignment_with_redacted_evidence_and_line_number(self) -> None:
        candidate = "fake-secret-value-123456"
        text = f'normal = True\napi_key = "{candidate}"\n'

        findings = find_secrets_in_text(text, "config.py")

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "SEC001")
        self.assertEqual(findings[0].relative_path, "config.py")
        self.assertEqual(findings[0].line_number, 2)
        self.assertEqual(findings[0].evidence, 'api_key= "fak...456"')
        self.assertNotIn(candidate, findings[0].evidence)

    def test_finds_quoted_json_key(self) -> None:
        findings = find_secrets_in_text(
            '{"token": "fake-json-token-987654"}',
            "config.json",
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].evidence, 'token: "fak...654"')

    def test_ignores_environment_variable_access(self) -> None:
        findings = find_secrets_in_text(
            'api_key = os.getenv("API_KEY")',
            "config.py",
        )

        self.assertEqual(findings, ())

    def test_ignores_obvious_placeholder(self) -> None:
        findings = find_secrets_in_text(
            'password = "replace-me"',
            "config.py",
        )

        self.assertEqual(findings, ())


class DetectSecretsTests(unittest.TestCase):
    def test_skips_binary_and_oversized_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "binary.dat").write_bytes(
                b'password="fake-binary-secret"\x00remaining-binary-data'
            )
            (root / "large.txt").write_bytes(
                b'a' * (MAX_SCANNABLE_FILE_SIZE_BYTES + 1)
            )

            inventory = collect_repository_inventory(root)
            findings = detect_secrets(root, inventory)

        self.assertEqual(findings, ())

    def test_scans_inventory_files_end_to_end(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate = "fake-end-to-end-token-123456"
            (root / "settings.py").write_text(
                f'token = "{candidate}"',
                encoding="utf-8",
            )

            inventory = collect_repository_inventory(root)
            findings = detect_secrets(root, inventory)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].relative_path, "settings.py")
        self.assertNotIn(candidate, findings[0].evidence)


if __name__ == "__main__":
    unittest.main()

