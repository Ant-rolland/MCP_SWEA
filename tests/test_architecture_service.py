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
