"""SQLite persistence for repositories, scans, rules, and findings."""

from __future__ import annotations

import sqlite3
from collections.abc import Sequence
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

from security_auditor.findings import Finding
from security_auditor.inventory import RepositoryInventory
from security_auditor.rules import RULE_DEFINITIONS


SCHEMA_VERSION = 1


class DatabaseError(RuntimeError):
    """Raised when scan results cannot be persisted safely."""


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def connect_database(database_path: Path) -> sqlite3.Connection:
    """Open a SQLite connection with relationships enforced."""

    connection = sqlite3.connect(database_path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_database(connection: sqlite3.Connection) -> None:
    """Create the version-one schema and deterministic rule records."""

    current_version = connection.execute("PRAGMA user_version").fetchone()[0]
    if current_version > SCHEMA_VERSION:
        raise DatabaseError(
            f"database schema version {current_version} is newer than supported "
            f"version {SCHEMA_VERSION}"
        )

    if current_version == 0:
        connection.executescript(
            """
            CREATE TABLE repositories (
                id INTEGER PRIMARY KEY,
                path TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL
            );

            CREATE TABLE rules (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                category TEXT NOT NULL,
                description TEXT NOT NULL
            );

            CREATE TABLE scans (
                id INTEGER PRIMARY KEY,
                repository_id INTEGER NOT NULL REFERENCES repositories(id),
                started_at TEXT NOT NULL,
                finished_at TEXT NOT NULL,
                status TEXT NOT NULL,
                file_count INTEGER NOT NULL,
                total_size_bytes INTEGER NOT NULL
            );

            CREATE TABLE findings (
                id INTEGER PRIMARY KEY,
                scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                repository_id INTEGER NOT NULL REFERENCES repositories(id),
                rule_id TEXT NOT NULL REFERENCES rules(id),
                file TEXT NOT NULL,
                line INTEGER NOT NULL,
                evidence TEXT NOT NULL,
                message TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open'
            );

            CREATE INDEX findings_scan_id_idx ON findings(scan_id);
            CREATE INDEX findings_repository_id_idx ON findings(repository_id);
            CREATE INDEX findings_rule_id_idx ON findings(rule_id);

            PRAGMA user_version = 1;
            """
        )

    connection.executemany(
        """
        INSERT INTO rules(id, name, category, description)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            name = excluded.name,
            category = excluded.category,
            description = excluded.description
        """,
        [
            (rule.rule_id, rule.name, rule.category, rule.description)
            for rule in RULE_DEFINITIONS
        ],
    )


def get_or_create_repository(
    connection: sqlite3.Connection,
    repository_path: Path,
) -> int:
    normalized_path = str(repository_path.resolve(strict=True))
    existing = connection.execute(
        "SELECT id FROM repositories WHERE path = ?",
        (normalized_path,),
    ).fetchone()
    if existing is not None:
        return int(existing["id"])

    cursor = connection.execute(
        "INSERT INTO repositories(path, created_at) VALUES (?, ?)",
        (normalized_path, utc_now()),
    )
    return int(cursor.lastrowid)


def record_completed_scan(
    database_path: Path,
    repository_path: Path,
    inventory: RepositoryInventory,
    findings: Sequence[Finding],
) -> int:
    """Store one completed scan atomically and return its database ID."""

    try:
        database_path.parent.mkdir(parents=True, exist_ok=True)
        with closing(connect_database(database_path)) as connection:
            with connection:
                initialize_database(connection)
                repository_id = get_or_create_repository(connection, repository_path)
                timestamp = utc_now()
                scan_cursor = connection.execute(
                    """
                    INSERT INTO scans(
                        repository_id,
                        started_at,
                        finished_at,
                        status,
                        file_count,
                        total_size_bytes
                    )
                    VALUES (?, ?, ?, 'completed', ?, ?)
                    """,
                    (
                        repository_id,
                        timestamp,
                        timestamp,
                        inventory.total_files,
                        inventory.total_size_bytes,
                    ),
                )
                scan_id = int(scan_cursor.lastrowid)

                connection.executemany(
                    """
                    INSERT INTO findings(
                        scan_id,
                        repository_id,
                        rule_id,
                        file,
                        line,
                        evidence,
                        message
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            scan_id,
                            repository_id,
                            finding.rule_id,
                            finding.relative_path,
                            finding.line_number,
                            finding.evidence,
                            finding.message,
                        )
                        for finding in findings
                    ],
                )

            return scan_id
    except (OSError, sqlite3.Error) as error:
        raise DatabaseError(f"could not store scan results: {error}") from error


def list_scan_findings(
    database_path: Path,
    scan_id: int,
) -> tuple[sqlite3.Row, ...]:
    """Return findings for one scan in stable order."""

    try:
        with closing(connect_database(database_path)) as connection:
            initialize_database(connection)
            rows = connection.execute(
                """
                SELECT id, rule_id, file, line, evidence, message, status
                FROM findings
                WHERE scan_id = ?
                ORDER BY file, line, rule_id
                """,
                (scan_id,),
            ).fetchall()
            return tuple(rows)
    except (OSError, sqlite3.Error) as error:
        raise DatabaseError(f"could not read scan results: {error}") from error
