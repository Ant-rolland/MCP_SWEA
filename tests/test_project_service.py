from swea_sentinel.config import ProjectIndexSettings
from swea_sentinel.core.project_service import ProjectService
from swea_sentinel.persistence.database import Database


def test_register_refresh_status_and_context(tmp_path):
    project = tmp_path / "sample"
    project.mkdir()
    (project / "main.py").write_text("print('hello')\n", encoding="utf-8")
    (project / "README.md").write_text("# sample\n", encoding="utf-8")
    (project / ".env").write_text("SHOULD_NOT_BE_READ_AS_SECRET\n", encoding="utf-8")
    (project / ".git").mkdir()
    (project / ".git" / "config").write_text("ignored", encoding="utf-8")

    service = ProjectService(Database(tmp_path / "db.sqlite"))
    registered = service.initialize(str(project))
    project_id = registered.project_id
    refreshed = service.refresh(project_id)
    assert refreshed.result["indexed_files"] == 3
    status = service.status(project_id)
    assert status.indexed_files == 3
    context = service.context(project_id)
    assert context["latest_snapshot"]["file_count"] == 3


def test_inventory_respects_file_count_bound(tmp_path):
    project = tmp_path / "bounded"
    project.mkdir()
    for index in range(3):
        (project / f"file-{index}.txt").write_text(f"content-{index}", encoding="utf-8")
    service = ProjectService(
        Database(tmp_path / "db.sqlite"),
        ProjectIndexSettings(max_files=2),
    )
    registered = service.initialize(str(project))
    result = service.refresh(registered.project_id)
    assert result.result["indexed_files"] == 2
    assert result.result["truncated"] is True
    assert result.result["truncated_reason"] == "maximum_file_count"


def test_inventory_stores_hashes_not_source_contents(tmp_path):
    project = tmp_path / "private"
    project.mkdir()
    (project / "main.py").write_text("private-marker-do-not-persist", encoding="utf-8")
    db = Database(tmp_path / "db.sqlite")
    service = ProjectService(db)
    registered = service.initialize(str(project))
    service.refresh(registered.project_id)
    with db.connect() as conn:
        manifest = conn.execute(
            "SELECT manifest_json FROM project_snapshots WHERE project_id = ?",
            (registered.project_id,),
        ).fetchone()[0]
    assert "private-marker-do-not-persist" not in manifest
    assert "sha256" in manifest


def test_initialize_rejects_non_directory(tmp_path):
    file_path = tmp_path / "file.txt"
    file_path.write_text("x")
    service = ProjectService(Database(tmp_path / "db.sqlite"))
    try:
        service.initialize(str(file_path))
    except ValueError as exc:
        assert "existing directory" in str(exc)
    else:
        raise AssertionError("Expected ValueError")


def test_unknown_project_is_rejected(tmp_path):
    service = ProjectService(Database(tmp_path / "db.sqlite"))
    try:
        service.status("not-a-project")
    except ValueError as exc:
        assert "Unknown project_id" in str(exc)
    else:
        raise AssertionError("Expected ValueError")
