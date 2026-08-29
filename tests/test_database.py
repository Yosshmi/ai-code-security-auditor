from __future__ import annotations

import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from security_auditor.database import (
    SCHEMA_VERSION,
    connect_database,
    initialize_database,
    list_scan_findings,
    record_completed_scan,
)
from security_auditor.detectors.secrets import detect_secrets
from security_auditor.inventory import collect_repository_inventory
from security_auditor.rules import RULE_DEFINITIONS


class InitializeDatabaseTests(unittest.TestCase):
    def test_creates_schema_version_and_rule_records(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "auditor.db"
            with closing(connect_database(database_path)) as connection:
                with connection:
                    initialize_database(connection)

                version = connection.execute("PRAGMA user_version").fetchone()[0]
                rule_count = connection.execute(
                    "SELECT count(*) FROM rules"
                ).fetchone()[0]

        self.assertEqual(version, SCHEMA_VERSION)
        self.assertEqual(rule_count, len(RULE_DEFINITIONS))

    def test_rejects_database_from_newer_schema_version(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "future.db"
            with closing(sqlite3.connect(database_path)) as connection:
                connection.execute("PRAGMA user_version = 999")

                with self.assertRaisesRegex(RuntimeError, "newer than supported"):
                    initialize_database(connection)


class RecordCompletedScanTests(unittest.TestCase):
    def test_stores_repository_scan_and_redacted_findings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repository"
            root.mkdir()
            candidate = "fake-database-secret-123456"
            (root / "config.py").write_text(
                f'api_key = "{candidate}"',
                encoding="utf-8",
            )
            database_path = Path(directory) / "auditor.db"
            inventory = collect_repository_inventory(root)
            findings = detect_secrets(root, inventory)

            scan_id = record_completed_scan(
                database_path,
                root,
                inventory,
                findings,
            )
            stored_findings = list_scan_findings(database_path, scan_id)

        self.assertEqual(scan_id, 1)
        self.assertEqual(len(stored_findings), 1)
        self.assertEqual(stored_findings[0]["rule_id"], "SEC001")
        self.assertNotIn(candidate, stored_findings[0]["evidence"])

    def test_reuses_repository_for_repeated_scans(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repository"
            root.mkdir()
            (root / "README.md").write_text("safe", encoding="utf-8")
            database_path = Path(directory) / "auditor.db"
            inventory = collect_repository_inventory(root)

            first_scan_id = record_completed_scan(
                database_path, root, inventory, ()
            )
            second_scan_id = record_completed_scan(
                database_path, root, inventory, ()
            )

            with closing(connect_database(database_path)) as connection:
                repository_count = connection.execute(
                    "SELECT count(*) FROM repositories"
                ).fetchone()[0]
                scan_count = connection.execute(
                    "SELECT count(*) FROM scans"
                ).fetchone()[0]

        self.assertEqual((first_scan_id, second_scan_id), (1, 2))
        self.assertEqual(repository_count, 1)
        self.assertEqual(scan_count, 2)


if __name__ == "__main__":
    unittest.main()
