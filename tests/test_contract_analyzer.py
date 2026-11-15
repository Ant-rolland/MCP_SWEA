import json

from swea_sentinel.core.contract_analyzer import analyze_contracts


def test_discovers_openapi_and_json_schema_and_checks_local_refs(tmp_path):
    (tmp_path / "openapi.yaml").write_text(
        "openapi: 3.0.3\ninfo:\n  title: Demo\n  version: '1'\npaths:\n"
        "  /items:\n    get:\n      operationId: listItems\n",
        encoding="utf-8",
    )
    (tmp_path / "schema.json").write_text(json.dumps({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$defs": {"Item": {"type": "object"}},
        "properties": {"item": {"$ref": "#/$defs/Item"}, "bad": {"$ref": "#/$defs/Missing"}},
    }), encoding="utf-8")

    report = analyze_contracts(tmp_path)

    assert report["contract_count"] == 2
    assert report["openapi_count"] == 1
    assert report["json_schema_count"] == 1
    assert any(f["code"] == "JSON_SCHEMA_UNRESOLVED_LOCAL_REF" for f in report["findings"])
    schema = next(item for item in report["contracts"] if item["kind"] == "json_schema")
    assert schema["unresolved_local_refs"] == 1


def test_reports_invalid_contract_file_without_executing_code(tmp_path):
    (tmp_path / "bad.yaml").write_text("openapi: [", encoding="utf-8")
    (tmp_path / "ordinary.json").write_text('{"hello": "world"}', encoding="utf-8")

    report = analyze_contracts(tmp_path)

    assert report["contract_count"] == 0
    assert report["findings"][0]["code"] == "CONTRACT_PARSE_ERROR"
    assert report["files_inspected"] == 1
