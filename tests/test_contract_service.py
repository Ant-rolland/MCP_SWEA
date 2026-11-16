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
    assert len(result.findings) == 1
    assert result.findings[0].evidence_ids == [result.evidence[0].evidence_id]
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
    with database.connect() as conn:
        finding_payload = conn.execute(
            "SELECT payload_json FROM findings WHERE project_id = ?", (registered.project_id,)
        ).fetchone()["payload_json"]
    assert result.evidence[0].evidence_id in finding_payload


def test_contract_route_mapping_persists_contract_and_python_source_evidence(tmp_path):
    project = tmp_path / "sample"
    project.mkdir()
    (project / "openapi.json").write_text(json.dumps({
        "openapi": "3.1.0",
        "info": {"title": "API", "version": "1"},
        "paths": {
            "/items": {
                "get": {"operationId": "listItems", "responses": {"200": {"description": "ok"}}}
            }
        },
    }), encoding="utf-8")
    (project / "api.py").write_text(
        "@app.get('/items')\ndef list_items(): pass\n", encoding="utf-8"
    )
    database = Database(tmp_path / "swea.sqlite")
    service = ProjectService(database)
    registered = service.initialize(str(project))

    result = service.analyze_contracts(registered.project_id)

    assert result.result["source_mapping_count"] == 1
    assert result.result["source_mappings"][0]["mapping_status"] == "matched"
    assert {item.kind for item in result.evidence} == {
        "api_data_contract", "python_route_source"
    }
    route_evidence = next(item for item in result.evidence if item.kind == "python_route_source")
    assert route_evidence.source_path == "api.py"
    assert len(route_evidence.sha256 or "") == 64
    with database.connect() as conn:
        persisted = conn.execute(
            "SELECT COUNT(*) FROM evidence WHERE project_id = ?",
            (registered.project_id,),
        ).fetchone()[0]
    assert persisted == 2

    impact = service.check_blast_radius(
        registered.project_id, "openapi.json#operation:GET /items"
    )
    contract_impact = impact.result["impact_by_relation"]["api_contract_graph"]
    assert contract_impact["direct_dependents"] == ["api.py"]
    assert impact.evidence[0].kind == "python_route_source"


def test_contract_assessment_is_partial_when_python_route_scan_has_parse_errors(tmp_path):
    project = tmp_path / "sample"
    project.mkdir()
    (project / "openapi.json").write_text(json.dumps({
        "openapi": "3.1.0",
        "info": {"title": "API", "version": "1"},
        "paths": {
            "/items": {
                "get": {"responses": {"200": {"description": "ok"}}}
            }
        },
    }), encoding="utf-8")
    (project / "broken.py").write_text(
        "@app.get('/items')\ndef broken(:\n", encoding="utf-8"
    )
    service = ProjectService(Database(tmp_path / "swea.sqlite"))
    registered = service.initialize(str(project))

    result = service.analyze_contracts(registered.project_id)

    assert result.status.value == "partial"
    assert result.result["route_scan"]["parse_errors"][0]["path"] == "broken.py"
    assert result.result["source_mappings"][0]["route_scan_complete"] is False


def test_contract_mapping_uses_composed_fastapi_router_prefixes(tmp_path):
    project = tmp_path / "sample"
    project.mkdir()
    (project / "openapi.json").write_text(json.dumps({
        "openapi": "3.1.0",
        "info": {"title": "API", "version": "1"},
        "paths": {
            "/api/v1/items": {
                "get": {"responses": {"200": {"description": "ok"}}}
            }
        },
    }), encoding="utf-8")
    (project / "api.py").write_text(
        "from fastapi import APIRouter, FastAPI\n"
        "app = FastAPI()\n"
        "router = APIRouter(prefix='/items')\n"
        "@router.get('/')\n"
        "def list_items(): pass\n"
        "app.include_router(router, prefix='/api/v1')\n",
        encoding="utf-8",
    )
    service = ProjectService(Database(tmp_path / "swea.sqlite"))
    registered = service.initialize(str(project))

    result = service.analyze_contracts(registered.project_id)

    assert result.result["source_mapping_count"] == 1
    mapping = result.result["source_mappings"][0]
    assert mapping["mapping_status"] == "matched"
    assert mapping["path"] == "/api/v1/items"
    assert mapping["sources"][0]["source_path"] == "api.py"
