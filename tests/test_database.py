import os
import sqlite3
import stat

import pytest

from swea_sentinel.persistence.database import Database


def test_database_initializes_wal_and_schema(tmp_path):
    db = Database(tmp_path / "sentinel.db")
    assert db.health() == {"ok": True, "integrity": "ok", "schema_version": 2}
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
    assert versions == [(1,), (2,)]


def test_newer_database_schema_is_rejected(tmp_path):
    path = tmp_path / "sentinel.db"
    Database(path)
    with sqlite3.connect(path) as conn:
        conn.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (3, 'future')"
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


def test_workspace_migration_backfills_existing_projects(tmp_path):
    from swea_sentinel.persistence.database import DDL

    path = tmp_path / "legacy.db"
    with sqlite3.connect(path) as conn:
        conn.executescript(DDL)
        conn.execute(
            "CREATE TABLE schema_migrations "
            "(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
        )
        conn.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (1, 'legacy')"
        )
        conn.execute(
            "INSERT INTO projects(project_id,name,root_path,created_at) "
            "VALUES ('legacy-project','Legacy','/legacy','2026-01-01T00:00:00Z')"
        )

    db = Database(path)
    with db.connect() as conn:
        project = conn.execute(
            "SELECT workspace_id FROM projects WHERE project_id = 'legacy-project'"
        ).fetchone()
        membership = conn.execute(
            "SELECT role FROM workspace_memberships "
            "WHERE workspace_id = 'local' AND principal_id = 'local-owner'"
        ).fetchone()
        version = conn.execute(
            "SELECT MAX(version) FROM schema_migrations"
        ).fetchone()[0]

    assert project["workspace_id"] == "local"
    assert membership["role"] == "owner"
    assert version == 2
    assert db.health()["ok"] is True


def test_projects_cannot_be_created_without_workspace_scope(tmp_path):
    db = Database(tmp_path / "sentinel.db")
    with db.connect() as conn, pytest.raises(
        sqlite3.IntegrityError, match="workspace_id is required"
    ):
        conn.execute(
            "INSERT INTO projects(project_id,name,root_path,created_at) "
            "VALUES ('unscoped','Unscoped','/unscoped','2026-01-01T00:00:00Z')"
        )
