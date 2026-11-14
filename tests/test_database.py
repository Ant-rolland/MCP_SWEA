import sqlite3

import pytest

from swea_sentinel.persistence.database import Database


def test_database_initializes_wal_and_schema(tmp_path):
    db = Database(tmp_path / "sentinel.db")
    assert db.health() == {"ok": True, "integrity": "ok", "schema_version": 1}
    with db.connect() as conn:
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert mode == "wal"
    assert {"projects", "components", "dependencies", "findings", "evidence", "approvals", "audit_events"} <= tables


def test_database_connections_are_closed_after_context(tmp_path):
    db = Database(tmp_path / "sentinel.db")
    with db.connect() as conn:
        conn.execute("SELECT 1")
    with pytest.raises(sqlite3.ProgrammingError, match="closed database"):
        conn.execute("SELECT 1")


def test_schema_migrations_are_idempotent(tmp_path):
    path = tmp_path / "sentinel.db"
    Database(path)
    Database(path)
    with sqlite3.connect(path) as conn:
        versions = conn.execute(
            "SELECT version FROM schema_migrations ORDER BY version"
        ).fetchall()
    assert versions == [(1,)]


def test_newer_database_schema_is_rejected(tmp_path):
    path = tmp_path / "sentinel.db"
    Database(path)
    with sqlite3.connect(path) as conn:
        conn.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (2, 'future')"
        )
    with pytest.raises(RuntimeError, match="newer than supported"):
        Database(path)
