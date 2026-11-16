import os
import sqlite3
import stat

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


@pytest.mark.skipif(os.name != "posix", reason="POSIX file permission semantics")
def test_database_file_is_created_with_owner_only_permissions(tmp_path):
    path = tmp_path / "private" / "sentinel.db"
    Database(path)

    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700


@pytest.mark.skipif(os.name != "posix", reason="POSIX symlink semantics")
def test_database_rejects_symlink_paths(tmp_path):
    target = tmp_path / "target.db"
    Database(target)
    link = tmp_path / "linked.db"
    link.symlink_to(target)

    with pytest.raises(ValueError, match="must not be a symlink"):
        Database(link)

    assert Database(target).health()["ok"] is True
