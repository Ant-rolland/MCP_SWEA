"""Bounded, read-only discovery and structural checks for API/data contracts."""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
from pathlib import Path
from typing import Any

import yaml

from swea_sentinel.core.contract_source_mapper import discover_python_routes

CONTRACT_SUFFIXES = {".json", ".yaml", ".yml"}
HTTP_METHODS = {"get", "put", "post", "delete", "options", "head", "patch", "trace"}
MAX_FILES = 500
MAX_FILE_BYTES = 1_000_000
MAX_TOTAL_BYTES = 10_000_000
MAX_SCAN_SECONDS = 5.0
IGNORED_DIRS = {".git", ".venv", "venv", "node_modules", "dist", "build"}


def _load_document(path: Path, raw: bytes) -> Any:
    text = raw.decode("utf-8")
    if path.suffix.lower() == ".json":
        return json.loads(text)
    return yaml.safe_load(text)


def _is_openapi(document: Any) -> bool:
    return isinstance(document, dict) and (
        isinstance(document.get("openapi"), str)
        or isinstance(document.get("swagger"), str)
    )


def _is_json_schema(document: Any) -> bool:
    return isinstance(document, dict) and (
        "$schema" in document
        or "$defs" in document
        or "definitions" in document
        or ("properties" in document and ("type" in document or "$ref" in document))
    )


def _walk_refs(document: Any) -> list[str]:
    """Collect $ref strings without recursion; tolerate YAML alias cycles."""
    refs: list[str] = []
    pending: list[Any] = [document]
    visited_containers: set[int] = set()
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            identity = id(value)
            if identity in visited_containers:
                continue
            visited_containers.add(identity)
            ref = value.get("$ref")
            if isinstance(ref, str):
                refs.append(ref)
            pending.extend(value.values())
        elif isinstance(value, list):
            identity = id(value)
            if identity in visited_containers:
                continue
            visited_containers.add(identity)
            pending.extend(value)
    return refs


def _resolve_local_ref(document: Any, reference: str) -> bool:
    """Resolve a local JSON Pointer fragment; external refs are out of scope."""
    if not reference.startswith("#/"):
        return True
    current = document
    for part in reference[2:].split("/"):
        key = part.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, dict) or key not in current:
            return False
        current = current[key]
    return True


def _append_unresolved_refs(
    findings: list[dict[str, str]], *, path: str, refs: list[str], document: Any, code: str
) -> int:
    unresolved = [ref for ref in refs if ref.startswith("#/") and not _resolve_local_ref(document, ref)]
    for ref in unresolved:
        findings.append({
            "code": code,
            "severity": "high",
            "path": path,
            "message": f"Local reference does not resolve: {ref}",
        })
    return len(unresolved)



def _append_path_parameter_findings(
    findings: list[dict[str, str]], *, path: str, route: str, path_item: dict[str, Any]
) -> None:
    """Check inline OpenAPI path parameters against route-template placeholders."""
    placeholders = set(re.findall(r"\{([^{}]+)\}", route))
    if not placeholders:
        return

    path_parameters = path_item.get("parameters", [])
    if not isinstance(path_parameters, list):
        path_parameters = []

    for method in sorted(HTTP_METHODS):
        operation = path_item.get(method)
        if not isinstance(operation, dict):
            continue
        operation_parameters = operation.get("parameters", [])
        if not isinstance(operation_parameters, list):
            operation_parameters = []
        parameters = path_parameters + operation_parameters

        # Parameter references are not dereferenced in this structural pass.
        if any(isinstance(item, dict) and "$ref" in item for item in parameters):
            continue

        inline_parameters = [item for item in parameters if isinstance(item, dict)]
        for placeholder in sorted(placeholders):
            matches = [
                item for item in inline_parameters
                if item.get("name") == placeholder and item.get("in") == "path"
            ]
            if not matches:
                findings.append({
                    "code": "OPENAPI_PATH_PARAMETER_MISSING",
                    "severity": "medium",
                    "path": path,
                    "message": (
                        f"Route {route} uses path parameter '{placeholder}' "
                        f"without a matching inline path parameter on {method.upper()}."
                    ),
                })
            elif not any(item.get("required") is True for item in matches):
                findings.append({
                    "code": "OPENAPI_PATH_PARAMETER_NOT_REQUIRED",
                    "severity": "medium",
                    "path": path,
                    "message": (
                        f"Path parameter '{placeholder}' on {method.upper()} "
                        "must declare required: true."
                    ),
                })


def _append_response_findings(
    findings: list[dict[str, str]], *, path: str, route: str, method: str,
    operation: dict[str, Any],
) -> None:
    """Check required OpenAPI operation responses and inline response descriptions."""
    responses = operation.get("responses")
    if not isinstance(responses, dict) or not responses:
        findings.append({
            "code": "OPENAPI_RESPONSES_MISSING",
            "severity": "high",
            "path": path,
            "message": f"Operation {method.upper()} {route} has no non-empty responses object.",
        })
        return

    for status_code, response in responses.items():
        if not isinstance(response, dict):
            findings.append({
                "code": "OPENAPI_RESPONSE_INVALID",
                "severity": "medium",
                "path": path,
                "message": (
                    f"Response '{status_code}' on {method.upper()} {route} "
                    "is not an object."
                ),
            })
            continue
        # Response references are handled by the shared local-reference checker.
        if "$ref" in response:
            continue
        description = response.get("description")
        if not isinstance(description, str) or not description.strip():
            findings.append({
                "code": "OPENAPI_RESPONSE_DESCRIPTION_MISSING",
                "severity": "medium",
                "path": path,
                "message": (
                    f"Response '{status_code}' on {method.upper()} {route} "
                    "has no non-empty description."
                ),
            })

def analyze_contracts(root: Path) -> dict[str, Any]:
    """Inspect JSON/YAML OpenAPI and JSON Schema documents without executing project code."""
    started = time.monotonic()
    findings: list[dict[str, str]] = []
    contracts: list[dict[str, Any]] = []
    inspected = 0
    files_considered = 0
    total_bytes = 0
    truncated_reason: str | None = None

    for current, dirs, filenames in os.walk(root, followlinks=False):
        dirs[:] = sorted(
            name for name in dirs
            if name not in IGNORED_DIRS and not (Path(current) / name).is_symlink()
        )
        for filename in sorted(filenames):
            if time.monotonic() - started > MAX_SCAN_SECONDS:
                truncated_reason = "maximum_scan_duration"
                break
            path = Path(current) / filename
            if path.is_symlink() or path.suffix.lower() not in CONTRACT_SUFFIXES:
                continue
            files_considered += 1
            if files_considered > MAX_FILES:
                truncated_reason = "maximum_file_count"
                break
            relative = path.relative_to(root).as_posix()
            try:
                size = path.stat().st_size
                if size > MAX_FILE_BYTES:
                    findings.append({
                        "code": "CONTRACT_FILE_TOO_LARGE", "severity": "info",
                        "path": relative,
                        "message": "Contract candidate skipped because it exceeds the per-file size limit.",
                    })
                    continue
                if total_bytes + size > MAX_TOTAL_BYTES:
                    truncated_reason = "maximum_total_bytes"
                    break
                # Read at most the configured per-file budget, even if the file
                # changes after stat(); account bytes before parsing so malformed
                # candidates cannot bypass the aggregate budget.
                with path.open("rb") as stream:
                    raw = stream.read(MAX_FILE_BYTES + 1)
                if len(raw) > MAX_FILE_BYTES:
                    findings.append({
                        "code": "CONTRACT_FILE_TOO_LARGE", "severity": "info",
                        "path": relative,
                        "message": "Contract candidate skipped because it exceeds the per-file size limit.",
                    })
                    continue
                if total_bytes + len(raw) > MAX_TOTAL_BYTES:
                    truncated_reason = "maximum_total_bytes"
                    break
                total_bytes += len(raw)
                digest = hashlib.sha256(raw).hexdigest()
                document = _load_document(path, raw)
                inspected += 1
            except (OSError, UnicodeDecodeError, json.JSONDecodeError, yaml.YAMLError) as exc:
                findings.append({
                    "code": "CONTRACT_PARSE_ERROR", "severity": "medium",
                    "path": relative,
                    "message": f"Contract candidate could not be parsed ({type(exc).__name__}).",
                })
                continue

            if _is_openapi(document):
                version = str(document.get("openapi") or document.get("swagger"))
                paths = document.get("paths") if isinstance(document.get("paths"), dict) else {}
                operations: list[tuple[str, str, dict[str, Any]]] = []
                for route, path_item in paths.items():
                    if not isinstance(path_item, dict):
                        continue
                    for method, operation in path_item.items():
                        if isinstance(method, str) and method.lower() in HTTP_METHODS and isinstance(operation, dict):
                            operations.append((str(route), method.lower(), operation))
                            _append_response_findings(
                                findings, path=relative, route=str(route),
                                method=method.lower(), operation=operation,
                            )
                    _append_path_parameter_findings(
                        findings, path=relative, route=str(route), path_item=path_item
                    )

                if version.startswith("3.") and not isinstance(document.get("info"), dict):
                    findings.append({
                        "code": "OPENAPI_INFO_MISSING", "severity": "medium", "path": relative,
                        "message": "OpenAPI document has no info object.",
                    })

                operation_ids = [
                    operation.get("operationId")
                    for _, _, operation in operations
                    if "operationId" in operation
                ]
                invalid_ids = [value for value in operation_ids if not isinstance(value, str) or not value.strip()]
                if invalid_ids:
                    findings.append({
                        "code": "OPENAPI_INVALID_OPERATION_ID", "severity": "medium", "path": relative,
                        "message": "One or more operationId values are not non-empty strings.",
                    })
                valid_ids = [value for value in operation_ids if isinstance(value, str) and value.strip()]
                if len(valid_ids) != len(set(valid_ids)):
                    findings.append({
                        "code": "OPENAPI_DUPLICATE_OPERATION_ID", "severity": "medium", "path": relative,
                        "message": "OpenAPI document contains duplicate operationId values.",
                    })
                if not operations:
                    findings.append({
                        "code": "OPENAPI_NO_OPERATIONS", "severity": "low", "path": relative,
                        "message": "OpenAPI document declares no HTTP operations under paths.",
                    })

                refs = _walk_refs(document)
                unresolved_refs = _append_unresolved_refs(
                    findings, path=relative, refs=refs, document=document,
                    code="OPENAPI_UNRESOLVED_LOCAL_REF",
                )
                components = document.get("components")
                schemas = components.get("schemas", {}) if isinstance(components, dict) else {}
                contracts.append({
                    "path": relative, "kind": "openapi", "version": version,
                    "operation_count": len(operations),
                    "schema_count": len(schemas) if isinstance(schemas, dict) else 0,
                    "reference_count": len(refs),
                    "unresolved_local_refs": unresolved_refs,
                    "sha256": digest,
                    "operations": [
                        {
                            "method": method.upper(),
                            "path": route,
                            "operation_id": operation.get("operationId")
                            if isinstance(operation.get("operationId"), str) else None,
                        }
                        for route, method, operation in operations
                    ],
                })
            elif _is_json_schema(document):
                refs = _walk_refs(document)
                unresolved_refs = _append_unresolved_refs(
                    findings, path=relative, refs=refs, document=document,
                    code="JSON_SCHEMA_UNRESOLVED_LOCAL_REF",
                )
                contracts.append({
                    "path": relative, "kind": "json_schema",
                    "reference_count": len(refs), "unresolved_local_refs": unresolved_refs,
                    "sha256": digest,
                })

        if truncated_reason:
            break

    openapi_contracts = [item for item in contracts if item["kind"] == "openapi"]
    route_report = discover_python_routes(root) if openapi_contracts else {
        "routes": [], "files_scanned": 0, "bytes_scanned": 0,
        "truncated": False, "truncated_reason": None, "duration_ms": 0,
        "limitations": [],
    }
    routes_by_signature: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for route_item in route_report["routes"]:
        routes_by_signature.setdefault(
            (route_item["method"], route_item["path"]), []
        ).append(route_item)
    source_mappings: list[dict[str, Any]] = []
    for contract in openapi_contracts:
        for operation in contract.get("operations", []):
            candidates = routes_by_signature.get(
                (operation["method"], operation["path"]), []
            )
            source_mappings.append({
                "contract_path": contract["path"],
                "method": operation["method"],
                "path": operation["path"],
                "operation_id": operation["operation_id"],
                "mapping_status": (
                    "matched" if len(candidates) == 1 else
                    "ambiguous" if len(candidates) > 1 else "unmapped"
                ),
                "confidence": "HIGH_CONFIDENCE" if len(candidates) == 1 else "UNKNOWN",
                "sources": candidates,
                "matching_rule": "exact_static_http_method_and_literal_path",
            })
    for contract in openapi_contracts:
        contract["source_mapping_count"] = sum(
            item["contract_path"] == contract["path"]
            and item["mapping_status"] == "matched"
            for item in source_mappings
        )
    return {
        "analysis_level": "static_api_data_contract_discovery",
        "contracts": contracts,
        "source_mappings": source_mappings,
        "source_mapping_count": sum(item["mapping_status"] == "matched" for item in source_mappings),
        "unmapped_operation_count": sum(item["mapping_status"] == "unmapped" for item in source_mappings),
        "ambiguous_operation_count": sum(item["mapping_status"] == "ambiguous" for item in source_mappings),
        "route_scan": {
            key: route_report[key] for key in (
                "files_scanned", "bytes_scanned", "truncated", "truncated_reason", "duration_ms"
            )
        },
        "contract_count": len(contracts),
        "openapi_count": sum(item["kind"] == "openapi" for item in contracts),
        "json_schema_count": sum(item["kind"] == "json_schema" for item in contracts),
        "files_considered": files_considered,
        "files_inspected": inspected,
        "bytes_inspected": total_bytes,
        "truncated": truncated_reason is not None or route_report["truncated"],
        "truncated_reason": (
            truncated_reason
            if truncated_reason is not None
            else f"python_route_scan:{route_report['truncated_reason']}"
            if route_report["truncated"] else None
        ),
        "findings": findings,
        "duration_ms": max(0, int((time.monotonic() - started) * 1000)),
        "limitations": [
            "Discovery is limited to JSON and YAML files that resemble OpenAPI or JSON Schema documents.",
            "File count, per-file bytes, aggregate bytes, and scan duration are bounded; malformed files count toward the byte budget.",
            "External references are not fetched or validated; only local JSON Pointer references are checked.",
            "Path-parameter checks cover inline definitions; operations using parameter $ref entries are skipped rather than guessed.",
            "Response checks verify the responses object and inline descriptions; response $ref targets are not expanded.",
            "This is structural discovery, not full OpenAPI/JSON Schema specification validation.",
            "Python source mapping requires an exact HTTP-method and literal-path match between OpenAPI operations and recognized Python route decorators; dynamic paths and router-prefix composition are not inferred.",
            "Multiple matching Python route declarations are reported as ambiguous; no single implementation is selected.",
            "No project code is executed and no files are modified.",
        ],
    }
