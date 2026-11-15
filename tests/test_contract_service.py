import json

from swea_sentinel.core.project_service import ProjectService
from swea_sentinel.persistence.database import Database


def test_contract_assessment_persists_findings_and_source_evidence(tmp_path):
    project = tmp_path / "sample"
    project.mkdir()
    (project / "schema.json").write_text(json.dumps({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "properties": {"item": {"$ref": "#/$defs/Absent"}},
    }), encoding="utf-8")
    database = Database(tmp_path / "swea.sqlite")
    service = ProjectService(database)
    registered = service.initialize(str(project))

    result = service.analyze_contracts(registered.project_id)

    assert result.status.value == "partial"
    assert result.result["analysis_level"] == "static_api_data_contract_discovery"
    assert len(result.evidence) == 1
    with database.connect() as conn:
        assessment = conn.execute(
            "SELECT domain FROM assessments WHERE project_id = ?", (registered.project_id,)
        ).fetchone()
        finding = conn.execute(
            "SELECT code, severity, confidence FROM findings WHERE project_id = ?",
            (registered.project_id,),
        ).fetchone()
        evidence_count = conn.execute(
            "SELECT COUNT(*) FROM evidence WHERE project_id = ?", (registered.project_id,)
        ).fetchone()[0]
    assert assessment["domain"] == "data_contracts"
    assert finding["code"] == "JSON_SCHEMA_UNRESOLVED_LOCAL_REF"
    assert finding["severity"] == "high"
    assert finding["confidence"] == "HIGH_CONFIDENCE"
    assert evidence_count == 1
