"""Project discovery and inventory services (bounded, evidence-aware P1 baseline)."""
from __future__ import annotations

import hashlib
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from swea_sentinel.config import ProjectIndexSettings
from swea_sentinel.core.architecture_analyzer import analyze_python_imports
from swea_sentinel.models import (
    DataOrigin, Evidence, ExecutionStatus, ProjectStatus, QualificationStatus,
    SWEADomain, ToolResult,
)
from swea_sentinel.persistence.database import Database

IGNORED_DIRS = {
    ".git", ".venv", "venv", "node_modules", "__pycache__", ".mypy_cache", ".pytest_cache",
    ".next", ".turbo", "dist", "build", "coverage",
}


class ProjectService:
    def __init__(
        self, database: Database, index_settings: ProjectIndexSettings | None = None
    ) -> None:
        self.db = database
        self.index_settings = index_settings or ProjectIndexSettings()

    @staticmethod
    def _safe_root(raw_path: str) -> Path:
        root = Path(raw_path).expanduser().resolve(strict=True)
        if not root.is_dir():
            raise ValueError("Project path must be an existing directory")
        return root

    def initialize(self, raw_path: str, name: str | None = None) -> ToolResult:
        root = self._safe_root(raw_path)
        project_id = str(uuid4())
        now = datetime.now(timezone.utc).isoformat()
        project_name = name or root.name or "project"
        with self.db.connect() as conn:
            existing = conn.execute(
                "SELECT * FROM projects WHERE root_path = ?", (str(root),)
            ).fetchone()
            if existing:
                project_id = existing["project_id"]
                project_name = existing["name"]
            else:
                conn.execute(
                    "INSERT INTO projects(project_id,name,root_path,created_at) VALUES(?,?,?,?)",
                    (project_id, project_name, str(root), now),
                )
        return ToolResult(
            project_id=project_id,
            status=ExecutionStatus.COMPLETED,
            result={
                "name": project_name,
                "root_path": str(root),
                "already_registered": bool(existing),
            },
            limitations=["Project registration does not grant permission to modify project files."],
        )

    def _project(self, project_id: str):
        with self.db.connect() as conn:
            row = conn.execute(
                "SELECT * FROM projects WHERE project_id = ?", (project_id,)
            ).fetchone()
        if row is None:
            raise ValueError(f"Unknown project_id: {project_id}")
        root = Path(row["root_path"]).resolve(strict=True)
        if not root.is_dir():
            raise ValueError("Registered project root is no longer an accessible directory")
        return row, root

    def refresh(self, project_id: str) -> ToolResult:
        _, root = self._project(project_id)
        manifest: list[dict[str, str | int]] = []
        total_bytes = 0
        started = time.monotonic()
        truncated_reason: str | None = None
        excluded = IGNORED_DIRS | set(self.index_settings.excluded_directories)

        for current, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = sorted(
                d for d in dirs
                if d not in excluded and not (Path(current) / d).is_symlink()
            )
            for filename in sorted(files):
                if len(manifest) >= self.index_settings.max_files:
                    truncated_reason = "maximum_file_count"
                    break
                if time.monotonic() - started > self.index_settings.max_scan_seconds:
                    truncated_reason = "maximum_scan_duration"
                    break
                path = Path(current) / filename
                if path.is_symlink():
                    continue
                try:
                    rel = path.relative_to(root).as_posix()
                    stat = path.stat()
                    if not path.is_file() or stat.st_size > self.index_settings.max_file_bytes:
                        continue
                    if total_bytes + stat.st_size > self.index_settings.max_total_bytes:
                        truncated_reason = "maximum_total_bytes"
                        break
                    digest = hashlib.sha256()
                    with path.open("rb") as handle:
                        for chunk in iter(lambda: handle.read(65536), b""):
                            digest.update(chunk)
                    manifest.append({
                        "path": rel,
                        "size": stat.st_size,
                        "sha256": digest.hexdigest(),
                    })
                    total_bytes += stat.st_size
                except (OSError, ValueError):
                    continue
            if truncated_reason:
                break

        now = datetime.now(timezone.utc).isoformat()
        snapshot_id = str(uuid4())
        with self.db.connect() as conn:
            conn.execute(
                "INSERT INTO project_snapshots(snapshot_id,project_id,created_at,file_count,manifest_json) "
                "VALUES(?,?,?,?,?)",
                (snapshot_id, project_id, now, len(manifest), json.dumps(manifest, separators=(",", ":"))),
            )
            conn.execute("DELETE FROM components WHERE project_id = ?", (project_id,))
            conn.executemany(
                "INSERT INTO components(component_id,project_id,relative_path,component_type,sha256) "
                "VALUES(?,?,?,?,?)",
                [
                    (
                        str(uuid4()), project_id, str(item["path"]),
                        Path(str(item["path"])).suffix.lower() or "[no extension]",
                        str(item["sha256"]),
                    )
                    for item in manifest
                ],
            )
            conn.execute(
                "UPDATE projects SET last_indexed_at = ? WHERE project_id = ?", (now, project_id)
            )
        return ToolResult(
            project_id=project_id,
            status=ExecutionStatus.COMPLETED,
            result={
                "snapshot_id": snapshot_id,
                "indexed_files": len(manifest),
                "indexed_bytes": total_bytes,
                "truncated": truncated_reason is not None,
                "truncated_reason": truncated_reason,
            },
            limitations=[
                "This is a filesystem inventory, not semantic code analysis.",
                "File contents are hashed but not stored or transmitted.",
                "Oversized files, symlinks, and configured dependency/cache directories are excluded.",
            ],
            duration_ms=max(0, int((time.monotonic() - started) * 1000)),
        )

    def status(self, project_id: str) -> ProjectStatus:
        row, _ = self._project(project_id)
        with self.db.connect() as conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM components WHERE project_id = ?", (project_id,)
            ).fetchone()[0]
        return ProjectStatus(
            project_id=row["project_id"],
            name=row["name"],
            root_path=row["root_path"],
            created_at=datetime.fromisoformat(row["created_at"]),
            last_indexed_at=(
                datetime.fromisoformat(row["last_indexed_at"]) if row["last_indexed_at"] else None
            ),
            indexed_files=count,
            status=row["status"],
        )

    def context(self, project_id: str) -> dict[str, object]:
        status = self.status(project_id)
        with self.db.connect() as conn:
            latest = conn.execute(
                "SELECT snapshot_id, created_at, file_count FROM project_snapshots "
                "WHERE project_id = ? ORDER BY created_at DESC LIMIT 1",
                (project_id,),
            ).fetchone()
            types = conn.execute(
                "SELECT component_type, COUNT(*) AS n FROM components WHERE project_id = ? "
                "GROUP BY component_type ORDER BY n DESC",
                (project_id,),
            ).fetchall()
        return {
            "project": status.model_dump(mode="json"),
            "latest_snapshot": dict(latest) if latest else None,
            "file_types": [dict(item) for item in types],
        }


    def analyze_architecture(self, project_id: str) -> ToolResult:
        """Persist a bounded, read-only static Python import graph assessment."""
        _, root = self._project(project_id)
        report = analyze_python_imports(root, self.index_settings)
        assessment_id = str(uuid4())
        now = datetime.now(timezone.utc).isoformat()
        file_hashes = report.pop("file_hashes")
        evidence = [
            Evidence(
                kind="python_source_file",
                description="Python source file inspected for static import relationships",
                origin=DataOrigin.VERIFIED_SOURCE,
                qualification=QualificationStatus.QUALIFIED,
                source_path=relative,
                sha256=digest,
            )
            for relative, digest in sorted(file_hashes.items())
        ]
        status = (
            ExecutionStatus.PARTIAL
            if report["truncated"] or report["parse_errors"]
            else ExecutionStatus.COMPLETED
        )
        with self.db.connect() as conn:
            conn.execute(
                "INSERT INTO assessments(assessment_id,project_id,task_id,domain,status,created_at,payload_json) "
                "VALUES(?,?,?,?,?,?,?)",
                (
                    assessment_id, project_id, None, SWEADomain.ARCHITECTURE.value,
                    status.value, now, json.dumps(report, separators=(",", ":")),
                ),
            )
            conn.execute("DELETE FROM dependencies WHERE project_id = ?", (project_id,))
            conn.executemany(
                "INSERT INTO dependencies(dependency_id,project_id,source_path,target_name,dependency_type) "
                "VALUES(?,?,?,?,?)",
                [
                    (
                        str(uuid4()), project_id, edge["source"], edge["target"],
                        "python_import",
                    )
                    for edge in report["local_dependency_edges"]
                ],
            )
            conn.executemany(
                "INSERT INTO evidence(evidence_id,project_id,kind,sha256,payload_json,created_at) "
                "VALUES(?,?,?,?,?,?)",
                [
                    (
                        item.evidence_id, project_id, item.kind, item.sha256,
                        item.model_dump_json(), now,
                    )
                    for item in evidence
                ],
            )
        return ToolResult(
            project_id=project_id,
            status=status,
            result={"assessment_id": assessment_id, **report},
            evidence=evidence,
            limitations=list(report["limitations"]),
            duration_ms=int(report["duration_ms"]),
        )

    def analyze(self, project_id: str) -> ToolResult:
        context = self.context(project_id)
        duration = 0
        if context["latest_snapshot"] is None:
            indexed = self.refresh(project_id)
            context = self.context(project_id)
            duration = indexed.duration_ms
        return ToolResult(
            project_id=project_id,
            status=ExecutionStatus.PARTIAL,
            result={"inventory": context, "analysis_level": "filesystem_inventory"},
            limitations=[
                "No architecture, security, compliance, performance, dependency, or test conclusions are produced in P1.",
                "No source files are sent to external services.",
            ],
            duration_ms=duration,
        )
