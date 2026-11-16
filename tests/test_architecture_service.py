import json

from swea_sentinel.core.project_service import ProjectService
from swea_sentinel.persistence.database import Database


def test_architecture_assessment_persists_edges_and_qualified_evidence(tmp_path):
    project = tmp_path / "sample"
    (project / "app").mkdir(parents=True)
    (project / "app" / "main.py").write_text("import app.helper\n", encoding="utf-8")
    (project / "app" / "helper.py").write_text("VALUE = 1\n", encoding="utf-8")
    database = Database(tmp_path / "swea.sqlite")
    service = ProjectService(database)
    registered = service.initialize(str(project))

    result = service.analyze_architecture(registered.project_id)

    assert result.status.value == "completed"
    assert result.result["analysis_level"] == "python_static_import_graph"
    assert len(result.result["local_dependency_edges"]) == 1
    assert len(result.evidence) == 2
    assert all(item.qualification.value == "qualified" for item in result.evidence)

    with database.connect() as conn:
        dependencies = conn.execute(
            "SELECT source_path, target_name, dependency_type FROM dependencies "
            "WHERE project_id = ?",
            (registered.project_id,),
        ).fetchall()
        assessments = conn.execute(
            "SELECT domain, status, payload_json FROM assessments WHERE project_id = ?",
            (registered.project_id,),
        ).fetchall()
        evidence_count = conn.execute(
            "SELECT COUNT(*) FROM evidence WHERE project_id = ?",
            (registered.project_id,),
        ).fetchone()[0]

    assert len(dependencies) == 1
    assert dependencies[0]["source_path"] == "app/main.py"
    assert dependencies[0]["target_name"] == "app/helper.py"
    assert dependencies[0]["dependency_type"] == "python_import"
    assert assessments[0]["domain"] == "architecture"
    assert json.loads(assessments[0]["payload_json"])["analysis_level"] == "python_static_import_graph"
    assert evidence_count == 2


def test_blast_radius_returns_direct_and_transitive_dependents(tmp_path):
    project = tmp_path / "impact"
    (project / "app").mkdir(parents=True)
    (project / "app" / "base.py").write_text("VALUE = 1\n", encoding="utf-8")
    (project / "app" / "core.py").write_text("import app.base\n", encoding="utf-8")
    (project / "app" / "api.py").write_text("import app.core\n", encoding="utf-8")
    service = ProjectService(Database(tmp_path / "impact.sqlite"))
    registered = service.initialize(str(project))
    service.analyze_architecture(registered.project_id)

    result = service.check_blast_radius(registered.project_id, "app/base.py")

    assert result.result["direct_dependents"] == ["app/core.py"]
    assert result.result["transitive_dependents"] == [
        {"path": "app/core.py", "distance": 1},
        {"path": "app/api.py", "distance": 2},
    ]
    assert result.result["impact_count"] == 2
    assert len(result.evidence) == 2


def test_blast_radius_rejects_unsafe_and_unknown_targets(tmp_path):
    project = tmp_path / "safe"
    (project / "app").mkdir(parents=True)
    (project / "app" / "main.py").write_text("VALUE = 1\n", encoding="utf-8")
    service = ProjectService(Database(tmp_path / "safe.sqlite"))
    registered = service.initialize(str(project))
    service.analyze_architecture(registered.project_id)

    for target in ("../outside.py", "/absolute/path.py"):
        try:
            service.check_blast_radius(registered.project_id, target)
        except ValueError as exc:
            assert "project-relative" in str(exc)
        else:
            raise AssertionError("Unsafe path should be rejected")

    try:
        service.check_blast_radius(registered.project_id, "missing.py")
    except ValueError as exc:
        assert "dependency graph" in str(exc)
    else:
        raise AssertionError("Unknown graph target should be rejected")
