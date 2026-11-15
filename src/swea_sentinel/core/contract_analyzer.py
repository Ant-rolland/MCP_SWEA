"""Bounded, read-only discovery and structural checks for API/data contracts."""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

import yaml

CONTRACT_SUFFIXES = {".json", ".yaml", ".yml"}
MAX_FILES = 500
MAX_FILE_BYTES = 1_000_000
MAX_TOTAL_BYTES = 10_000_000


def _load_document(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
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


def _resolve_local_ref(document: Any, reference: str) -> bool:
    if not reference.startswith("#/"):
        return True
    current = document
    for part in reference[2:].split("/"):
        key = part.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, dict) or key not in current:
            return False
        current = current[key]
    return True


def analyze_contracts(root: Path) -> dict[str, Any]:
    """Inspect JSON/YAML OpenAPI and JSON Schema documents without executing project code."""
    started = time.monotonic()
    findings: list[dict[str, str]] = []
    contracts: list[dict[str, Any]] = []
    inspected = 0
    total_bytes = 0
    truncated_reason: str | None = None

    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink() or path.suffix.lower() not in CONTRACT_SUFFIXES:
            continue
        if any(part in {".git", ".venv", "venv", "node_modules", "dist", "build"} for part in path.parts):
            continue
        if inspected >= MAX_FILES:
            truncated_reason = "maximum_file_count"
            break
        try:
            size = path.stat().st_size
            if size > MAX_FILE_BYTES:
                findings.append({
                    "code": "CONTRACT_FILE_TOO_LARGE", "severity": "info",
                    "path": path.relative_to(root).as_posix(),
                    "message": "Contract candidate skipped because it exceeds the per-file size limit.",
                })
                continue
            if total_bytes + size > MAX_TOTAL_BYTES:
                truncated_reason = "maximum_total_bytes"
                break
            raw = path.read_bytes()
            digest = hashlib.sha256(raw).hexdigest()
            document = _load_document(path)
            inspected += 1
            total_bytes += size
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, yaml.YAMLError) as exc:
            findings.append({
                "code": "CONTRACT_PARSE_ERROR", "severity": "medium",
                "path": path.relative_to(root).as_posix(),
                "message": f"Contract candidate could not be parsed ({type(exc).__name__}).",
            })
            continue

        relative = path.relative_to(root).as_posix()
        if _is_openapi(document):
            version = str(document.get("openapi") or document.get("swagger"))
            paths = document.get("paths") if isinstance(document.get("paths"), dict) else {}
            operations: list[tuple[str, str, dict[str, Any]]] = []
            for route, path_item in paths.items():
                if not isinstance(path_item, dict):
                    continue
                for method, operation in path_item.items():
                    if method.lower() in {"get", "put", "post", "delete", "options", "head", "patch", "trace"} and isinstance(operation, dict):
                        operations.append((str(route), method.lower(), operation))
            if version.startswith("3.") and not isinstance(document.get("info"), dict):
                findings.append({
                    "code": "OPENAPI_INFO_MISSING", "severity": "medium", "path": relative,
                    "message": "OpenAPI document has no info object.",
                })
            operation_ids = [op.get("operationId") for _, _, op in operations if op.get("operationId")]
            if len(operation_ids) != len(set(operation_ids)):
                findings.append({
                    "code": "OPENAPI_DUPLICATE_OPERATION_ID", "severity": "medium", "path": relative,
                    "message": "OpenAPI document contains duplicate operationId values.",
                })
            if not operations:
                findings.append({
                    "code": "OPENAPI_NO_OPERATIONS", "severity": "low", "path": relative,
                    "message": "OpenAPI document declares no HTTP operations under paths.",
                })
            contracts.append({
                "path": relative, "kind": "openapi", "version": version,
                "operation_count": len(operations),
                "schema_count": len((document.get("components") or {}).get("schemas", {}))
                    if isinstance(document.get("components"), dict) else 0,
                "sha256": digest,
            })
        elif _is_json_schema(document):
            refs: list[str] = []
            def walk(value: Any) -> None:
                if isinstance(value, dict):
                    ref = value.get("$ref")
                    if isinstance(ref, str):
                        refs.append(ref)
                    for child in value.values():
                        walk(child)
                elif isinstance(value, list):
                    for child in value:
                        walk(child)
            walk(document)
            unresolved = [ref for ref in refs if ref.startswith("#/") and not _resolve_local_ref(document, ref)]
            for ref in unresolved:
                findings.append({
                    "code": "JSON_SCHEMA_UNRESOLVED_LOCAL_REF", "severity": "high",
                    "path": relative, "message": f"Local JSON Schema reference does not resolve: {ref}",
                })
            contracts.append({
                "path": relative, "kind": "json_schema",
                "reference_count": len(refs), "unresolved_local_refs": len(unresolved),
                "sha256": digest,
            })

    return {
        "analysis_level": "static_api_data_contract_discovery",
        "contracts": contracts,
        "contract_count": len(contracts),
        "openapi_count": sum(item["kind"] == "openapi" for item in contracts),
        "json_schema_count": sum(item["kind"] == "json_schema" for item in contracts),
        "files_inspected": inspected,
        "bytes_inspected": total_bytes,
        "truncated": truncated_reason is not None,
        "truncated_reason": truncated_reason,
        "findings": findings,
        "duration_ms": max(0, int((time.monotonic() - started) * 1000)),
        "limitations": [
            "Discovery is limited to JSON and YAML files that resemble OpenAPI or JSON Schema documents.",
            "External references are not fetched or validated; only local JSON Pointer references are checked.",
            "This is structural discovery, not full OpenAPI/JSON Schema specification validation.",
            "No project code is executed and no files are modified.",
        ],
    }
