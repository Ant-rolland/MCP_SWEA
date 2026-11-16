"""SQLite schema and connection management."""
from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = 1

DDL = """
CREATE TABLE IF NOT EXISTS projects (
    project_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    root_path TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    last_indexed_at TEXT,
    status TEXT NOT NULL DEFAULT 'active'
);
CREATE TABLE IF NOT EXISTS project_snapshots (
    snapshot_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(project_id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    file_count INTEGER NOT NULL,
    manifest_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_snapshots_project_created
    ON project_snapshots(project_id, created_at DESC);
CREATE TABLE IF NOT EXISTS components (
    component_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(project_id) ON DELETE CASCADE,
    relative_path TEXT NOT NULL,
    component_type TEXT NOT NULL,
    sha256 TEXT,
    UNIQUE(project_id, relative_path)
);
CREATE TABLE IF NOT EXISTS dependencies (
    dependency_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(project_id) ON DELETE CASCADE,
    source_path TEXT NOT NULL,
    target_name TEXT NOT NULL,
    dependency_type TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tasks (
    task_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(project_id) ON DELETE CASCADE,
    state TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS assessments (
    assessment_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(project_id) ON DELETE CASCADE,
    task_id TEXT,
    domain TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    payload_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(project_id) ON DELETE CASCADE,
    assessment_id TEXT REFERENCES assessments(assessment_id) ON DELETE SET NULL,
    domain TEXT NOT NULL,
    code TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL,
    status TEXT NOT NULL,
    payload_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence (
    evidence_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(project_id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    sha256 TEXT,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS policies (
    policy_id TEXT PRIMARY KEY,
    project_id TEXT REFERENCES projects(project_id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    policy_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tool_executions (
    execution_id TEXT PRIMARY KEY,
    project_id TEXT,
    tool_name TEXT NOT NULL,
    status TEXT NOT NULL,
    duration_ms INTEGER NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS usage_records (
    usage_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(project_id) ON DELETE CASCADE,
    provider TEXT,
    metric TEXT NOT NULL,
    quantity REAL NOT NULL,
    is_estimate INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS error_signatures (
    signature TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(project_id) ON DELETE CASCADE,
    occurrences INTEGER NOT NULL DEFAULT 1,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS approvals (
    approval_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(project_id) ON DELETE CASCADE,
    action TEXT NOT NULL,
    actor TEXT,
    decision TEXT NOT NULL,
    created_at TEXT NOT NULL,
    decided_at TEXT
);
CREATE TABLE IF NOT EXISTS audit_events (
    event_id TEXT PRIMARY KEY,
    project_id TEXT,
    actor TEXT,
    action TEXT NOT NULL,
    outcome TEXT NOT NULL,
    details_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""


MIGRATIONS: dict[int, str] = {1: DDL}


class Database:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        """Yield a configured connection and always close it after commit/rollback."""
        conn = sqlite3.connect(self.path, timeout=10.0)
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("PRAGMA busy_timeout = 10000")
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _initialize(self) -> None:
        with self.connect() as conn:
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations "
                "(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
            )
            current = conn.execute(
                "SELECT COALESCE(MAX(version), 0) FROM schema_migrations"
            ).fetchone()[0]
            if current > SCHEMA_VERSION:
                raise RuntimeError(
                    f"Database schema version {current} is newer than supported version {SCHEMA_VERSION}"
                )
            for version, migration_sql in sorted(MIGRATIONS.items()):
                if version <= current:
                    continue
                conn.executescript(migration_sql)
                conn.execute(
                    "INSERT INTO schema_migrations(version, applied_at) "
                    "VALUES (?, strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
                    (version,),
                )
            applied_version = conn.execute(
                "SELECT COALESCE(MAX(version), 0) FROM schema_migrations"
            ).fetchone()[0]
            if applied_version != SCHEMA_VERSION:
                raise RuntimeError(
                    f"Expected schema version {SCHEMA_VERSION}, found {applied_version}"
                )


    def record_tool_execution(
        self,
        execution_id: str,
        project_id: str | None,
        tool_name: str,
        status: str,
        duration_ms: int,
        payload: dict[str, object],
    ) -> None:
        import json

        with self.connect() as conn:
            conn.execute(
                "INSERT INTO tool_executions "
                "(execution_id, project_id, tool_name, status, duration_ms, payload_json, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    execution_id, project_id, tool_name, status, duration_ms,
                    json.dumps(payload, separators=(",", ":"), default=str),
                    datetime.now(UTC).isoformat(),
                ),
            )

    def record_audit_event(
        self,
        event_id: str,
        project_id: str | None,
        action: str,
        outcome: str,
        details: dict[str, object],
    ) -> None:
        import json

        with self.connect() as conn:
            conn.execute(
                "INSERT INTO audit_events "
                "(event_id, project_id, action, outcome, details_json, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    event_id, project_id, action, outcome,
                    json.dumps(details, separators=(",", ":"), default=str),
                    datetime.now(UTC).isoformat(),
                ),
            )

    def health(self) -> dict[str, object]:
        with self.connect() as conn:
            row = conn.execute("PRAGMA integrity_check").fetchone()
            version = conn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0]
        return {"ok": row[0] == "ok", "integrity": row[0], "schema_version": version}
