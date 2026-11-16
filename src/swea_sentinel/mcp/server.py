"""MCP server factory with per-tool execution and audit records."""
from __future__ import annotations

import os
import time
from collections.abc import Callable
from functools import wraps
from pathlib import Path
from typing import Any
from uuid import uuid4

from swea_sentinel.config import Settings, load_settings
from swea_sentinel.core.project_service import ProjectService
from swea_sentinel.models import (
    ProjectImpactInput,
    ProjectInitializeInput,
    ProjectReferenceInput,
    ProjectRefreshInput,
)
from swea_sentinel.persistence.database import Database


def _audit_tool(database: Database, tool_name: str) -> Callable[..., Any]:
    """Wrap a tool with minimal, privacy-conscious execution and audit persistence."""
    def decorate(function: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(function)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            started = time.perf_counter()
            execution_id = str(uuid4())
            project_id = kwargs.get("project_id")
            try:
                result = function(*args, **kwargs)
            except Exception as exc:
                duration_ms = max(0, int((time.perf_counter() - started) * 1000))
                details = {
                    "execution_id": execution_id,
                    "tool_name": tool_name,
                    "duration_ms": duration_ms,
                    "error_type": type(exc).__name__,
                }
                try:
                    database.record_tool_execution(
                        execution_id, str(project_id) if project_id else None,
                        tool_name, "failed", duration_ms, {"error_type": type(exc).__name__},
                    )
                    database.record_audit_event(
                        execution_id, str(project_id) if project_id else None,
                        f"mcp.tool.{tool_name}", "failure", details,
                    )
                except Exception as audit_error:  # noqa: BLE001 - preserve the original tool failure
                    exc.add_note(f"Audit persistence also failed: {type(audit_error).__name__}")
                raise

            if isinstance(result, dict):
                project_id = project_id or result.get("project_id")
                if not project_id and isinstance(result.get("project"), dict):
                    project_id = result["project"].get("project_id")
                result_status = str(result.get("status", "completed"))
                result_keys = sorted(result.keys())
            else:
                result_status = "completed"
                result_keys = []
            duration_ms = max(0, int((time.perf_counter() - started) * 1000))
            details = {
                "execution_id": execution_id,
                "tool_name": tool_name,
                "duration_ms": duration_ms,
                "result_status": result_status,
            }
            database.record_tool_execution(
                execution_id, str(project_id) if project_id else None,
                tool_name, result_status, duration_ms,
                {"result_status": result_status, "result_keys": result_keys},
            )
            database.record_audit_event(
                execution_id, str(project_id) if project_id else None,
                f"mcp.tool.{tool_name}", "success", details,
            )
            return result

        return wrapped
    return decorate


def build_server(db_path: str | None = None, settings: Settings | None = None) -> Any:
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:
        raise RuntimeError(
            "MCP SDK missing. Install with: python -m pip install -e '.[dev]'"
        ) from exc

    runtime_settings = settings or load_settings()
    path = (
        db_path
        if db_path is not None
        else os.getenv("SWEA_DB_PATH") or runtime_settings.storage.path
    )
    database = Database(Path(path).expanduser())
    service = ProjectService(database, runtime_settings.project_index)
    mcp = FastMCP(runtime_settings.server.name)

    @mcp.tool()
    @_audit_tool(database, "swea_initialize_project")
    def swea_initialize_project(path: str, name: str | None = None) -> dict[str, Any]:
        """Register an existing local project directory; does not modify project files."""
        payload = ProjectInitializeInput(path=path, name=name)
        return service.initialize(payload.path, payload.name).model_dump(mode="json")

    @mcp.tool()
    @_audit_tool(database, "swea_analyze_project")
    def swea_analyze_project(project_id: str) -> dict[str, Any]:
        """Run the current bounded filesystem-inventory analysis for a registered project."""
        payload = ProjectReferenceInput(project_id=project_id)
        return service.analyze(payload.project_id).model_dump(mode="json")


    @mcp.tool()
    @_audit_tool(database, "swea_assess_project")
    def swea_assess_project(
        project_id: str, refresh_index: bool = False
    ) -> dict[str, Any]:
        """Run all current bounded project analyses and return a consolidated risk summary."""
        payload = ProjectReferenceInput(project_id=project_id)
        return service.assess_project(
            payload.project_id, refresh_index=refresh_index
        ).model_dump(mode="json")

    @mcp.tool()
    @_audit_tool(database, "swea_analyze_architecture")
    def swea_analyze_architecture(project_id: str) -> dict[str, Any]:
        """Build and persist a bounded static Python import graph for a registered project."""
        payload = ProjectReferenceInput(project_id=project_id)
        return service.analyze_architecture(payload.project_id).model_dump(mode="json")


    @mcp.tool()
    @_audit_tool(database, "swea_analyze_dependencies")
    def swea_analyze_dependencies(project_id: str) -> dict[str, Any]:
        """Discover dependency manifests across supported ecosystems without package execution."""
        payload = ProjectReferenceInput(project_id=project_id)
        return service.analyze_dependencies(payload.project_id).model_dump(mode="json")

    @mcp.tool()
    @_audit_tool(database, "swea_get_risk_summary")
    def swea_get_risk_summary(project_id: str) -> dict[str, Any]:
        """Summarize the latest assessment findings and evidence by engineering domain."""
        payload = ProjectReferenceInput(project_id=project_id)
        return service.get_risk_summary(payload.project_id).model_dump(mode="json")

    @mcp.tool()
    @_audit_tool(database, "swea_analyze_security")
    def swea_analyze_security(project_id: str) -> dict[str, Any]:
        """Run bounded static Python security checks without executing project code."""
        payload = ProjectReferenceInput(project_id=project_id)
        return service.analyze_security(payload.project_id).model_dump(mode="json")

    @mcp.tool()
    @_audit_tool(database, "swea_analyze_code_quality")
    def swea_analyze_code_quality(project_id: str) -> dict[str, Any]:
        """Run bounded static Python code-quality checks without executing project code."""
        payload = ProjectReferenceInput(project_id=project_id)
        return service.analyze_code_quality(payload.project_id).model_dump(mode="json")

    @mcp.tool()
    @_audit_tool(database, "swea_analyze_contracts")
    def swea_analyze_contracts(project_id: str) -> dict[str, Any]:
        """Discover OpenAPI and JSON Schema contracts in a registered project."""
        payload = ProjectReferenceInput(project_id=project_id)
        return service.analyze_contracts(payload.project_id).model_dump(mode="json")

    @mcp.tool()
    @_audit_tool(database, "swea_check_blast_radius")
    def swea_check_blast_radius(project_id: str, target_path: str) -> dict[str, Any]:
        """List direct and transitive dependents from persisted per-ecosystem dependency graphs."""
        payload = ProjectImpactInput(project_id=project_id, target_path=target_path)
        return service.check_blast_radius(
            payload.project_id, payload.target_path
        ).model_dump(mode="json")

    @mcp.tool()
    @_audit_tool(database, "swea_get_project_context")
    def swea_get_project_context(project_id: str) -> dict[str, Any]:
        """Return the latest indexed project context and file-type summary."""
        payload = ProjectReferenceInput(project_id=project_id)
        return service.context(payload.project_id)

    @mcp.tool()
    @_audit_tool(database, "swea_get_project_status")
    def swea_get_project_status(project_id: str) -> dict[str, Any]:
        """Return registration and indexing status for a registered project."""
        payload = ProjectReferenceInput(project_id=project_id)
        return service.status(payload.project_id).model_dump(mode="json")

    @mcp.tool()
    @_audit_tool(database, "swea_refresh_project_index")
    def swea_refresh_project_index(project_id: str) -> dict[str, Any]:
        """Refresh the bounded filesystem manifest for a registered project."""
        payload = ProjectRefreshInput(project_id=project_id)
        return service.refresh(payload.project_id).model_dump(mode="json")

    return mcp
