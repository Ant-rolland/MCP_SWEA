import json

from swea_sentinel.core.contract_analyzer import analyze_contracts


def test_discovers_openapi_and_json_schema_and_checks_local_refs(tmp_path):
    (tmp_path / "openapi.yaml").write_text(
        "openapi: 3.0.3\\ninfo:\\n  title: Demo\\n  version: '1'\\npaths:\\n"
        "  /items:\\n    get:\\n      operationId: listItems\\n",
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


def test_yaml_alias_cycle_does_not_recurse_forever(tmp_path):
    (tmp_path / "cyclic.yaml").write_text(
        "$schema: https://json-schema.org/draft/2020-12/schema\\n"
        "properties: &props\\n  self: *props\\n",
        encoding="utf-8",
    )

    report = analyze_contracts(tmp_path)

    assert report["contract_count"] == 1
    assert report["json_schema_count"] == 1


def test_openapi_reports_unresolved_local_refs_and_invalid_operation_ids(tmp_path):
    (tmp_path / "openapi.json").write_text(json.dumps({
        "openapi": "3.1.0",
        "info": {"title": "API", "version": "1"},
        "paths": {
            "/items": {
                "get": {"operationId": ["not", "a", "string"], "responses": {
                    "200": {"description": "ok", "content": {
                        "application/json": {"schema": {"$ref": "#/components/schemas/Missing"}}
                    }}
                }},
                "post": {"operationId": "createItem", "responses": {"201": {"description": "created"}}},
            }
        },
        "components": {"schemas": {"Item": {"type": "object"}}},
    }), encoding="utf-8")

    report = analyze_contracts(tmp_path)
    codes = [finding["code"] for finding in report["findings"]]
    openapi = report["contracts"][0]

    assert "OPENAPI_INVALID_OPERATION_ID" in codes
    assert "OPENAPI_UNRESOLVED_LOCAL_REF" in codes
    assert openapi["reference_count"] == 1
    assert openapi["unresolved_local_refs"] == 1


def test_openapi_detects_duplicate_operation_ids_without_crashing_on_bad_values(tmp_path):
    (tmp_path / "openapi.yaml").write_text(
        "openapi: 3.0.3\\ninfo: {title: API, version: '1'}\\npaths:\\n"
        "  /a: {get: {operationId: same}}\\n"
        "  /b: {post: {operationId: same}}\\n",
        encoding="utf-8",
    )
    report = analyze_contracts(tmp_path)
    assert any(f["code"] == "OPENAPI_DUPLICATE_OPERATION_ID" for f in report["findings"])
