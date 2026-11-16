import json

from swea_sentinel.core import contract_analyzer
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


def test_yaml_alias_cycle_does_not_recurse_forever(tmp_path):
    (tmp_path / "cyclic.yaml").write_text(
        "$schema: https://json-schema.org/draft/2020-12/schema\n"
        "properties: &props\n  self: *props\n",
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
        "openapi: 3.0.3\ninfo: {title: API, version: '1'}\npaths:\n"
        "  /a: {get: {operationId: same}}\n"
        "  /b: {post: {operationId: same}}\n",
        encoding="utf-8",
    )
    report = analyze_contracts(tmp_path)
    assert any(f["code"] == "OPENAPI_DUPLICATE_OPERATION_ID" for f in report["findings"])



def test_contract_scan_prunes_generated_dirs_and_bounds_candidates(tmp_path, monkeypatch):
    generated = tmp_path / "node_modules"
    generated.mkdir()
    (generated / "ignored.json").write_text('{"$schema": "ignored"}', encoding="utf-8")
    (tmp_path / "one.json").write_text('{"$schema": "one"}', encoding="utf-8")
    (tmp_path / "two.json").write_text('{"$schema": "two"}', encoding="utf-8")
    monkeypatch.setattr(contract_analyzer, "MAX_FILES", 1)

    report = analyze_contracts(tmp_path)

    assert report["files_considered"] == 2
    assert report["files_inspected"] == 1
    assert report["truncated"] is True
    assert report["truncated_reason"] == "maximum_file_count"
    assert all(item["path"] != "node_modules/ignored.json" for item in report["contracts"])



def test_malformed_candidates_count_toward_aggregate_byte_budget(tmp_path, monkeypatch):
    (tmp_path / "a.json").write_text("{bad", encoding="utf-8")
    (tmp_path / "b.json").write_text("{bad", encoding="utf-8")
    monkeypatch.setattr(contract_analyzer, "MAX_TOTAL_BYTES", 5)

    report = analyze_contracts(tmp_path)

    assert report["bytes_inspected"] == 4
    assert report["files_considered"] == 2
    assert report["truncated"] is True
    assert report["truncated_reason"] == "maximum_total_bytes"
    assert len(report["findings"]) == 1
    assert report["findings"][0]["code"] == "CONTRACT_PARSE_ERROR"


def test_contract_scan_stops_at_time_budget(tmp_path, monkeypatch):
    (tmp_path / "a.json").write_text(
        '{"$schema": "https://json-schema.org/draft/2020-12/schema"}',
        encoding="utf-8",
    )
    (tmp_path / "b.json").write_text(
        '{"$schema": "https://json-schema.org/draft/2020-12/schema"}',
        encoding="utf-8",
    )
    ticks = iter([0.0, 0.0, 6.0, 6.0])
    monkeypatch.setattr(contract_analyzer, "MAX_SCAN_SECONDS", 5.0)
    monkeypatch.setattr(contract_analyzer.time, "monotonic", lambda: next(ticks))

    report = analyze_contracts(tmp_path)

    assert report["contract_count"] == 1
    assert report["files_considered"] == 1
    assert report["truncated"] is True
    assert report["truncated_reason"] == "maximum_scan_duration"



def test_openapi_checks_path_template_parameters(tmp_path):
    (tmp_path / "openapi.json").write_text(json.dumps({
        "openapi": "3.1.0",
        "info": {"title": "API", "version": "1"},
        "paths": {
            "/items/{itemId}": {
                "get": {"responses": {"200": {"description": "ok"}}},
                "post": {
                    "parameters": [
                        {"name": "itemId", "in": "path", "required": False, "schema": {"type": "string"}}
                    ],
                    "responses": {"200": {"description": "ok"}},
                },
            }
        },
    }), encoding="utf-8")

    report = analyze_contracts(tmp_path)
    codes = [finding["code"] for finding in report["findings"]]

    assert "OPENAPI_PATH_PARAMETER_MISSING" in codes
    assert "OPENAPI_PATH_PARAMETER_NOT_REQUIRED" in codes



def test_openapi_checks_operation_responses_and_inline_descriptions(tmp_path):
    (tmp_path / "openapi.json").write_text(json.dumps({
        "openapi": "3.1.0",
        "info": {"title": "API", "version": "1"},
        "paths": {
            "/missing": {
                "get": {},
            },
            "/invalid": {
                "get": {"responses": {"200": "ok"}},
            },
            "/undocumented": {
                "get": {"responses": {"200": {"content": {}}}},
            },
            "/valid": {
                "get": {"responses": {
                    "200": {"description": "successful response"},
                    "default": {"$ref": "#/components/responses/Failure"},
                }},
            },
        },
        "components": {
            "responses": {"Failure": {"description": "failure"}}
        },
    }), encoding="utf-8")

    report = analyze_contracts(tmp_path)
    codes = [finding["code"] for finding in report["findings"]]

    assert "OPENAPI_RESPONSES_MISSING" in codes
    assert "OPENAPI_RESPONSE_INVALID" in codes
    assert "OPENAPI_RESPONSE_DESCRIPTION_MISSING" in codes
    assert codes.count("OPENAPI_RESPONSES_MISSING") == 1


def test_openapi_operations_map_only_to_exact_static_python_routes(tmp_path):
    (tmp_path / "openapi.json").write_text(json.dumps({
        "openapi": "3.1.0",
        "info": {"title": "API", "version": "1"},
        "paths": {
            "/items": {
                "get": {"operationId": "listItems", "responses": {"200": {"description": "ok"}}},
            },
            "/ambiguous": {
                "post": {"operationId": "createAmbiguous", "responses": {"201": {"description": "created"}}},
            },
            "/unmapped": {
                "get": {"operationId": "getUnmapped", "responses": {"200": {"description": "ok"}}},
            },
        },
    }), encoding="utf-8")
    (tmp_path / "api.py").write_text(
        "@app.get('/items')\n"
        "def list_items(): pass\n"
        "@app.post('/ambiguous')\n"
        "def create_one(): pass\n"
        "@router.post('/ambiguous')\n"
        "def create_two(): pass\n"
        "PATH = '/unmapped'\n"
        "@app.get(PATH)\n"
        "def dynamic_unmapped(): pass\n",
        encoding="utf-8",
    )

    report = analyze_contracts(tmp_path)

    mappings = {(item["method"], item["path"]): item for item in report["source_mappings"]}
    assert mappings[("GET", "/items")]["mapping_status"] == "matched"
    assert mappings[("GET", "/items")]["sources"][0]["source_path"] == "api.py"
    assert mappings[("POST", "/ambiguous")]["mapping_status"] == "ambiguous"
    assert mappings[("POST", "/ambiguous")]["confidence"] == "UNKNOWN"
    assert mappings[("GET", "/unmapped")]["mapping_status"] == "unmapped"
    assert report["source_mapping_count"] == 1
    assert report["ambiguous_operation_count"] == 1
    assert report["unmapped_operation_count"] == 1


def test_contract_mapping_marks_truncated_route_scan_as_incomplete(tmp_path, monkeypatch):
    (tmp_path / "openapi.json").write_text(json.dumps({
        "openapi": "3.1.0",
        "info": {"title": "API", "version": "1"},
        "paths": {
            "/items": {
                "get": {"responses": {"200": {"description": "ok"}}}
            }
        },
    }), encoding="utf-8")
    monkeypatch.setattr(
        contract_analyzer,
        "discover_python_routes",
        lambda root: {
            "routes": [],
            "parse_errors": [],
            "files_scanned": 1,
            "bytes_scanned": 10,
            "truncated": True,
            "truncated_reason": "maximum_file_count",
            "duration_ms": 1,
            "limitations": [],
        },
    )

    report = analyze_contracts(tmp_path)

    assert report["truncated"] is True
    assert report["truncated_reason"] == "python_route_scan:maximum_file_count"
    assert report["source_mappings"][0]["mapping_status"] == "unmapped"
    assert report["source_mappings"][0]["route_scan_complete"] is False


def test_contract_mapping_marks_python_syntax_errors_as_incomplete(tmp_path):
    (tmp_path / "openapi.json").write_text(json.dumps({
        "openapi": "3.1.0",
        "info": {"title": "API", "version": "1"},
        "paths": {
            "/items": {
                "get": {"responses": {"200": {"description": "ok"}}}
            }
        },
    }), encoding="utf-8")
    (tmp_path / "broken.py").write_text(
        "@app.get('/items')\ndef broken(:\n", encoding="utf-8"
    )

    report = analyze_contracts(tmp_path)

    assert report["route_scan"]["parse_errors"][0]["path"] == "broken.py"
    assert report["source_mappings"][0]["mapping_status"] == "unmapped"
    assert report["source_mappings"][0]["route_scan_complete"] is False
