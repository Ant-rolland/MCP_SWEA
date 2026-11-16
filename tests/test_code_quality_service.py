from swea_sentinel.core.project_service import ProjectService
from swea_sentinel.persistence.database import Database


def test_code_quality_assessment_persists_findings_and_source_evidence(tmp_path):
    project = tmp_path / "sample"
    project.mkdir()
    (project / "app.py").write_text(
        "def bad(items=[]): pass\n"
        "try:\n    run()\nexcept:\n    pass\n",
        encoding="utf-8",
    )
    database = Database(tmp_path / "swea.sqlite")
    service = ProjectService(database)
    registered = service.initialize(str(project))

    result = service.analyze_code_quality(registered.project_id)

    assert result.status.value == "partial"
    assert result.result["analysis_level"] == "static_python_code_quality"
    assert len(result.findings) == 2
    assert len(result.evidence) == 1
    assert all(item.evidence_ids == [result.evidence[0].evidence_id] for item in result.findings)
    with database.connect() as conn:
        assessment = conn.execute(
            "SELECT domain FROM assessments WHERE project_id = ?",
            (registered.project_id,),
        ).fetchone()
        findings = conn.execute(
            "SELECT COUNT(*) FROM findings WHERE project_id = ?",
            (registered.project_id,),
        ).fetchone()[0]
        evidence = conn.execute(
            "SELECT COUNT(*) FROM evidence WHERE project_id = ?",
            (registered.project_id,),
        ).fetchone()[0]
    assert assessment["domain"] == "code_quality"
    assert findings == 2
    assert evidence == 1
