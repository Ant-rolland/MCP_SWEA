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



def test_dependency_analysis_persists_manifest_edges_and_evidence(tmp_path):
    project = tmp_path / "multi-ecosystem"
    project.mkdir()
    (project / "package.json").write_text(
        '{"dependencies":{"react":"^19"}}', encoding="utf-8"
    )
    (project / "pyproject.toml").write_text(
        '[project]\ndependencies = ["httpx>=0.27"]\n', encoding="utf-8"
    )
    db = Database(tmp_path / "db.sqlite")
    service = ProjectService(db)
    registered = service.initialize(str(project))

    result = service.analyze_dependencies(registered.project_id)

    assert result.status.value == "completed"
    assert result.result["manifest_count"] == 2
    with db.connect() as conn:
        edges = conn.execute(
            "SELECT source_path, target_name, dependency_type FROM dependencies "
            "WHERE project_id = ? ORDER BY dependency_type",
            (registered.project_id,),
        ).fetchall()
        evidence = conn.execute(
            "SELECT COUNT(*) FROM evidence WHERE project_id = ? AND kind = 'dependency_manifest'",
            (registered.project_id,),
        ).fetchone()[0]
    assert {(row["source_path"], row["target_name"], row["dependency_type"]) for row in edges} == {
        ("package.json", "react", "manifest:node"),
        ("pyproject.toml", "httpx", "manifest:python"),
    }
    assert evidence == 2



def test_dependency_analysis_persists_npm_locked_packages_and_edges(tmp_path):
    project = tmp_path / "npm-project"
    project.mkdir()
    (project / "package.json").write_text(
        '{"dependencies":{"react":"^19"}}', encoding="utf-8"
    )
    (project / "package-lock.json").write_text(
        '{"name":"npm-project","lockfileVersion":3,"packages":'
        '{"":{"dependencies":{"react":"^19"}},'
        '"node_modules/react":{"version":"19.0.0"},'
        '"node_modules/react-dom":{"version":"19.0.0","dependencies":{"react":"^19"}}}}',
        encoding="utf-8",
    )
    db = Database(tmp_path / "db.sqlite")
    service = ProjectService(db)
    registered = service.initialize(str(project))

    result = service.analyze_dependencies(registered.project_id)

    assert result.result["manifest_count"] == 2
    with db.connect() as conn:
        rows = conn.execute(
            "SELECT source_path, target_name, dependency_type FROM dependencies "
            "WHERE project_id = ? ORDER BY dependency_type, source_path, target_name",
            (registered.project_id,),
        ).fetchall()
    assert {(row["source_path"], row["target_name"], row["dependency_type"]) for row in rows} == {
        ("package.json", "react", "manifest:node"),
        ("package-lock.json#node_modules/react", "react@19.0.0", "lockfile:npm:package"),
        ("package-lock.json#node_modules/react-dom", "react-dom@19.0.0", "lockfile:npm:package"),
        ("package-lock.json#node_modules/react-dom", "react", "lockfile:npm:edge"),
    }



def test_dependency_analysis_persists_go_declarations_and_non_node_lockfiles(tmp_path):
    project = tmp_path / "go-project"
    project.mkdir()
    (project / "go.mod").write_text(
        "module example.com/service\n\ngo 1.23\n\n"
        "require (\n example.com/lib v1.2.3\n example.com/helper v0.8.0 // indirect\n)\n",
        encoding="utf-8",
    )
    (project / "go.sum").write_text(
        "example.com/lib v1.2.3 h1:abc=\n"
        "example.com/helper v0.8.0/go.mod h1:def=\n",
        encoding="utf-8",
    )
    db = Database(tmp_path / "db.sqlite")
    service = ProjectService(db)
    registered = service.initialize(str(project))

    result = service.analyze_dependencies(registered.project_id)

    assert result.result["manifest_count"] == 2
    with db.connect() as conn:
        rows = conn.execute(
            "SELECT source_path, target_name, dependency_type FROM dependencies "
            "WHERE project_id = ? ORDER BY dependency_type, source_path, target_name",
            (registered.project_id,),
        ).fetchall()
    stored = {(row["source_path"], row["target_name"], row["dependency_type"]) for row in rows}
    assert ("go.mod#example.com/service", "example.com/lib@v1.2.3", "manifest:go:edge") in stored
    assert ("go.mod#example.com/service", "example.com/helper@v0.8.0", "manifest:go:edge") in stored
    assert ("go.sum#example.com/lib@v1.2.3", "example.com/lib@v1.2.3", "lockfile:go:package") in stored
    assert ("go.sum#example.com/helper@v0.8.0", "example.com/helper@v0.8.0", "lockfile:go:package") in stored


def test_dependency_analysis_persists_python_and_cargo_lockfiles(tmp_path):
    project = tmp_path / "multi-ecosystem"
    project.mkdir()
    (project / "poetry.lock").write_text(
        '[[package]]\nname = "httpx"\nversion = "0.27.2"\n', encoding="utf-8"
    )
    (project / "Cargo.lock").write_text(
        'version = 3\n\n[[package]]\nname = "serde"\nversion = "1.0.210"\n',
        encoding="utf-8",
    )
    db = Database(tmp_path / "db.sqlite")
    service = ProjectService(db)
    registered = service.initialize(str(project))

    service.analyze_dependencies(registered.project_id)

    with db.connect() as conn:
        rows = conn.execute(
            "SELECT source_path, target_name, dependency_type FROM dependencies "
            "WHERE project_id = ?",
            (registered.project_id,),
        ).fetchall()
    stored = {(row["source_path"], row["target_name"], row["dependency_type"]) for row in rows}
    assert ("poetry.lock#httpx@0.27.2", "httpx@0.27.2", "lockfile:python:package") in stored
    assert ("Cargo.lock#serde@1.0.210", "serde@1.0.210", "lockfile:cargo:package") in stored



def test_blast_radius_reports_package_impacts_per_relation_without_crossing_graphs(tmp_path):
    project = tmp_path / "blast-project"
    project.mkdir()
    db = Database(tmp_path / "db.sqlite")
    service = ProjectService(db)
    registered = service.initialize(str(project))

    with db.connect() as conn:
        conn.executemany(
            "INSERT INTO dependencies(dependency_id,project_id,source_path,target_name,dependency_type) "
            "VALUES(?,?,?,?,?)",
            [
                ("dep-1", registered.project_id, "package-lock.json#node_modules/app", "shared-lib@1.0.0", "lockfile:npm:edge"),
                ("dep-2", registered.project_id, "package-lock.json#node_modules/plugin", "app@2.0.0", "lockfile:npm:edge"),
                # Same identifier in another graph layer must not create a cross-layer path.
                ("dep-3", registered.project_id, "Cargo.lock#other", "app@2.0.0", "lockfile:cargo:edge"),
            ],
        )

    result = service.check_blast_radius(registered.project_id, "shared-lib@1.0.0")

    assert result.result["analysis_level"] == "static_dependency_blast_radius"
    npm = result.result["impact_by_relation"]["lockfile:npm:edge"]
    assert npm["direct_dependents"] == ["package-lock.json#node_modules/app"]
    assert npm["impact_count"] == 1
    assert npm["transitive_dependents"] == [
        {"identifier": "package-lock.json#node_modules/app", "distance": 1},
    ]
    assert "lockfile:cargo:edge" not in result.result["impact_by_relation"]
