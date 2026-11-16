"""Project discovery and inventory services (bounded, evidence-aware P1 baseline)."""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
from collections import deque
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any
from uuid import uuid4

from swea_sentinel.config import ProjectIndexSettings
from swea_sentinel.core.architecture_analyzer import analyze_python_imports
from swea_sentinel.models import (
    Confidence,
    DataOrigin,
    Evidence,
    ExecutionStatus,
    Finding,
    FindingStatus,
    ProjectStatus,
    QualificationStatus,
    Severity,
    SWEADomain,
    ToolResult,
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
        now = datetime.now(UTC).isoformat()
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

    def _project(self, project_id: str) -> tuple[Any, Path]:
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

        now = datetime.now(UTC).isoformat()
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
        now = datetime.now(UTC).isoformat()
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
            conn.execute(
                "DELETE FROM dependencies WHERE project_id = ? AND dependency_type = 'python_import'",
                (project_id,),
            )
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


    def check_blast_radius(self, project_id: str, target_path: str) -> ToolResult:
        """Return per-relation transitive dependents from persisted static dependency graphs.

        Graph layers are traversed independently so equal identifiers from different
        ecosystems cannot create accidental cross-ecosystem paths.
        """
        self._project(project_id)
        normalized = PurePosixPath(target_path.replace("\\", "/"))
        if normalized.is_absolute() or ".." in normalized.parts or not normalized.parts:
            raise ValueError("target_path must be a safe project-relative path or dependency identifier")
        target = normalized.as_posix()

        with self.db.connect() as conn:
            rows = conn.execute(
                "SELECT source_path, target_name, dependency_type FROM dependencies "
                "WHERE project_id = ?",
                (project_id,),
            ).fetchall()
            evidence_rows = conn.execute(
                "SELECT payload_json FROM evidence WHERE project_id = ? "
                "AND kind IN ('python_source_file', 'python_route_source')",
                (project_id,),
            ).fetchall()

        graphs: dict[str, dict[str, set[str]]] = {}
        known_by_type: dict[str, set[str]] = {}
        for row in rows:
            relation = row["dependency_type"]
            source, dependency = row["source_path"], row["target_name"]
            reverse = graphs.setdefault(relation, {})
            known = known_by_type.setdefault(relation, set())
            known.update((source, dependency))
            reverse.setdefault(dependency, set()).add(source)

        impact_by_relation: dict[str, dict[str, Any]] = {}
        evidence_paths: set[str] = set()
        for relation in sorted(graphs):
            if target not in known_by_type[relation]:
                continue
            distances: dict[str, int] = {}
            pending = deque([(target, 0)])
            while pending:
                current, distance = pending.popleft()
                for dependent in sorted(graphs[relation].get(current, set())):
                    if dependent == target or dependent in distances:
                        continue
                    distances[dependent] = distance + 1
                    pending.append((dependent, distance + 1))
            if relation in {"python_import", "api_contract_graph"}:
                evidence_paths.update(distances)
            impact_by_relation[relation] = {
                "direct_dependents": sorted(
                    path for path, depth in distances.items() if depth == 1
                ),
                "transitive_dependents": [
                    {"identifier": path, "distance": distances[path]}
                    for path in sorted(distances, key=lambda item: (distances[item], item))
                ],
                "impact_count": len(distances),
            }

        if not impact_by_relation:
            raise ValueError(
                "target_path or dependency identifier is not present in any persisted dependency graph"
            )

        evidence_by_path: dict[str, Evidence] = {}
        for row in evidence_rows:
            try:
                item = Evidence.model_validate_json(row["payload_json"])
            except ValueError:
                continue
            if item.source_path:
                evidence_by_path[item.source_path] = item
        evidence = [
            evidence_by_path[path]
            for path in sorted(evidence_paths)
            if path in evidence_by_path
        ]
        python_impact = impact_by_relation.get("python_import", {})
        return ToolResult(
            project_id=project_id,
            status=ExecutionStatus.PARTIAL,
            result={
                "analysis_level": "static_dependency_blast_radius",
                "target_identifier": target,
                "impact_by_relation": impact_by_relation,
                "direct_dependents": python_impact.get("direct_dependents", []),
                "transitive_dependents": [
                    {"path": item["identifier"], "distance": item["distance"]}
                    for item in python_impact.get("transitive_dependents", [])
                ],
                "impact_count": python_impact.get("impact_count", 0),
            },
            evidence=evidence,
            limitations=[
                "Impact is calculated independently for each persisted dependency relation; graph layers are not joined across ecosystems.",
                "Python imports and declared/locked package relationships are static observations, not proof of runtime use.",
                "Manifest and lockfile edges describe package relationships; they do not identify which source files import or execute a package.",
                "API contract impact includes only unique exact matches to literal Python route decorators; dynamic routes, router-prefix composition, registration calls, and non-Python implementations remain unresolved.",
                "Dynamic imports, runtime dependency injection, generated modules and unresolved package identifiers are not inferred.",
            ],
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


    def analyze_dependencies(self, project_id: str) -> ToolResult:
        """Discover and persist bounded dependency manifests without resolving packages."""
        from swea_sentinel.core.dependency_analyzer import analyze_dependency_manifests
        from swea_sentinel.core.go_source_import_analyzer import analyze_go_source_imports
        from swea_sentinel.core.node_source_import_analyzer import analyze_node_source_imports

        _, root = self._project(project_id)
        report = analyze_dependency_manifests(root, self.index_settings)
        python_import_report = analyze_python_imports(root, self.index_settings)
        node_import_report = analyze_node_source_imports(root, self.index_settings)
        go_import_report = analyze_go_source_imports(root, self.index_settings)
        report["node_source_imports"] = node_import_report
        report["go_source_imports"] = go_import_report
        report["limitations"] = [
            *report["limitations"],
            *node_import_report["limitations"],
            *go_import_report["limitations"],
        ]
        report["duration_ms"] = (
            int(report["duration_ms"])
            + int(node_import_report["duration_ms"])
            + int(go_import_report["duration_ms"])
        )
        assessment_id = str(uuid4())
        now = datetime.now(UTC).isoformat()
        evidence = [
            Evidence(
                kind="dependency_manifest",
                description=f"Static {item['ecosystem']} {item['kind']} discovered",
                origin=DataOrigin.VERIFIED_SOURCE,
                qualification=QualificationStatus.QUALIFIED,
                source_path=item["path"],
                sha256=item["sha256"],
            )
            for item in report["manifests"]
        ]
        evidence.extend(
            Evidence(
                kind="node_source_imports",
                description="JavaScript/TypeScript source file inspected for literal external package imports",
                origin=DataOrigin.VERIFIED_SOURCE,
                qualification=QualificationStatus.QUALIFIED,
                source_path=source_path,
                sha256=digest,
            )
            for source_path, digest in node_import_report["file_hashes"].items()
        )
        evidence.extend(
            Evidence(
                kind="go_source_imports",
                description="Go source file inspected for literal module import paths",
                origin=DataOrigin.VERIFIED_SOURCE,
                qualification=QualificationStatus.QUALIFIED,
                source_path=source_path,
                sha256=digest,
            )
            for source_path, digest in go_import_report["file_hashes"].items()
        )
        status = (
            ExecutionStatus.PARTIAL
            if (
                report["truncated"]
                or report["parse_errors"]
                or node_import_report["truncated"]
                or go_import_report["truncated"]
            )
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
            conn.execute(
                "DELETE FROM dependencies WHERE project_id = ? "
                "AND (dependency_type LIKE 'manifest:%' OR dependency_type LIKE 'lockfile:%' "
                "OR dependency_type IN ('python_package_graph', 'node_package_graph', 'go_package_graph'))",
                (project_id,),
            )
            dependency_rows = [
                (
                    str(uuid4()), project_id, item["path"], dependency,
                    f"manifest:{item['ecosystem']}",
                )
                for item in report["manifests"]
                for dependency in item["declared_dependency_names"]
            ]
            for item in report["manifests"]:
                for edge in item.get("declared_dependency_edges", []):
                    dependency_rows.append((
                        str(uuid4()), project_id,
                        f"{item['path']}#{edge['source']}",
                        f"{edge['target']}@{edge.get('requested_version', 'unspecified')}",
                        f"manifest:{item['ecosystem']}:edge",
                    ))
                if item["kind"] != "lockfile":
                    continue
                lockfile_path = item["path"]
                lock_name = Path(lockfile_path).name
                lockfile_format = (
                    "pnpm" if lock_name == "pnpm-lock.yaml" else
                    "yarn" if lock_name == "yarn.lock" else
                    "python" if lock_name in {"poetry.lock", "Pipfile.lock"} else
                    "cargo" if lock_name == "Cargo.lock" else
                    "go" if lock_name == "go.sum" else
                    "npm" if item["ecosystem"] == "node" else
                    item["ecosystem"]
                )
                packages = item.get("locked_packages", [])
                package_by_install_path = {
                    package["install_path"]: package
                    for package in packages
                    if isinstance(package.get("install_path"), str)
                }
                packages_by_name: dict[str, list[dict[str, str]]] = {}
                for package in packages:
                    packages_by_name.setdefault(package["name"], []).append(package)

                def package_node(
                    package: dict[str, str],
                    current_lockfile_path: str = lockfile_path,
                ) -> str:
                    coordinate = f"{package['name']}@{package['version']}"
                    return f"{current_lockfile_path}#package:{coordinate}"

                for package in packages:
                    node = package_node(package)
                    dependency_rows.append((
                        str(uuid4()), project_id, node, node,
                        f"lockfile:{lockfile_format}:package",
                    ))
                for edge in item.get("locked_dependency_edges", []):
                    source_package = package_by_install_path.get(edge["source_install_path"])
                    if source_package is None:
                        continue
                    candidates = packages_by_name.get(edge["target"], [])
                    # A name-only lockfile edge is safe to connect only when it
                    # identifies one locked version. Ambiguous versions stay unlinked.
                    if len(candidates) != 1:
                        continue
                    relation_type = (
                        "python_package_graph"
                        if lockfile_format == "python"
                        else "node_package_graph"
                        if item["ecosystem"] == "node"
                        else f"lockfile:{lockfile_format}:edge"
                    )
                    dependency_rows.append((
                        str(uuid4()), project_id,
                        package_node(source_package),
                        package_node(candidates[0]),
                        relation_type,
                    ))

            # Link source imports to a Python package only when the normalized
            # import root exactly matches one uniquely locked distribution name.
            # Import aliases (for example PIL -> Pillow) are deliberately not guessed.
            def normalize_python_name(value: str) -> str:
                return re.sub(r"[-_.]+", "-", value).lower()

            locked_python_packages: list[tuple[str, str, str]] = []
            for manifest_item in report["manifests"]:
                if manifest_item["ecosystem"] != "python" or manifest_item["kind"] != "lockfile":
                    continue
                lock_path = manifest_item["path"]
                for package in manifest_item.get("locked_packages", []):
                    locked_python_packages.append((
                        normalize_python_name(package["name"]),
                        lock_path,
                        f"{lock_path}#package:{package['name']}@{package['version']}",
                    ))
            for import_edge in python_import_report.get("external_import_edges", []):
                python_candidates = [
                    package for package in locked_python_packages
                    if package[0] == normalize_python_name(import_edge["import_root"])
                ]
                if len(python_candidates) != 1:
                    continue
                dependency_rows.append((
                    str(uuid4()), project_id,
                    import_edge["source"], python_candidates[0][2],
                    "python_package_graph",
                ))

            # Link JS/TS source imports only to one exact, uniquely locked npm package.
            # Package aliases and ambiguous package versions are deliberately skipped.
            locked_node_packages: list[tuple[str, str, str]] = []
            for manifest_item in report["manifests"]:
                if (
                    manifest_item["ecosystem"] != "node"
                    or manifest_item["kind"] != "lockfile"
                ):
                    continue
                lock_path = manifest_item["path"]
                for package in manifest_item.get("locked_packages", []):
                    locked_node_packages.append((
                        package["name"],
                        lock_path,
                        f"{lock_path}#package:{package['name']}@{package['version']}",
                    ))
            for import_edge in node_import_report["edges"]:
                node_candidates = [
                    package for package in locked_node_packages
                    if package[0] == import_edge["import_root"]
                ]
                if len(node_candidates) != 1:
                    continue
                dependency_rows.append((
                    str(uuid4()), project_id,
                    import_edge["source"], node_candidates[0][2],
                    "node_package_graph",
                ))
            # Resolve Go import paths to the longest exact go.sum module prefix.
            # Only one candidate (including version and lockfile) is accepted.
            locked_go_packages: list[tuple[str, str, str]] = []
            for manifest_item in report["manifests"]:
                if (
                    manifest_item["ecosystem"] != "go"
                    or manifest_item["kind"] != "lockfile"
                    or Path(manifest_item["path"]).name != "go.sum"
                ):
                    continue
                lock_path = manifest_item["path"]
                for package in manifest_item.get("locked_packages", []):
                    locked_go_packages.append((
                        package["name"],
                        lock_path,
                        f"{lock_path}#package:{package['name']}@{package['version']}",
                    ))
            for import_edge in go_import_report["edges"]:
                import_path = import_edge["import_path"]
                module_candidates = [
                    module_candidate
                    for module_candidate in locked_go_packages
                    if (
                        import_path == module_candidate[0]
                        or import_path.startswith(module_candidate[0] + "/")
                    )
                ]
                if not module_candidates:
                    continue
                longest_prefix = max(
                    len(module_candidate[0]) for module_candidate in module_candidates
                )
                longest_candidates = [
                    module_candidate
                    for module_candidate in module_candidates
                    if len(module_candidate[0]) == longest_prefix
                ]
                if len(longest_candidates) != 1:
                    continue
                dependency_rows.append((
                    str(uuid4()), project_id,
                    import_edge["source"], longest_candidates[0][2],
                    "go_package_graph",
                ))
            conn.executemany(
                "INSERT INTO dependencies(dependency_id,project_id,source_path,target_name,dependency_type) "
                "VALUES(?,?,?,?,?)",
                dependency_rows,
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

    def get_risk_summary(self, project_id: str) -> ToolResult:
        """Summarize open findings from the latest assessment in each domain."""
        started = time.monotonic()
        self._project(project_id)
        with self.db.connect() as conn:
            assessment_rows = conn.execute(
                "SELECT assessment_id, domain, status, created_at, payload_json "
                "FROM assessments WHERE project_id = ? "
                "ORDER BY created_at DESC, assessment_id DESC",
                (project_id,),
            ).fetchall()
            finding_rows = conn.execute(
                "SELECT assessment_id, payload_json FROM findings "
                "WHERE project_id = ? AND status = 'open'",
                (project_id,),
            ).fetchall()
            evidence_rows = conn.execute(
                "SELECT payload_json FROM evidence WHERE project_id = ?",
                (project_id,),
            ).fetchall()

        latest_by_domain: dict[str, Any] = {}
        for row in assessment_rows:
            latest_by_domain.setdefault(row["domain"], row)
        latest_assessment_ids = {
            row["assessment_id"] for row in latest_by_domain.values()
        }
        findings: list[Finding] = []
        for row in finding_rows:
            if row["assessment_id"] not in latest_assessment_ids:
                continue
            try:
                findings.append(Finding.model_validate_json(row["payload_json"]))
            except ValueError:
                continue
        findings.sort(key=lambda item: (
            item.domain.value, item.severity.value, item.code, item.location or ""
        ))

        severity_counts = {item.value: 0 for item in Severity}
        confidence_counts = {item.value: 0 for item in Confidence}
        domain_counts: dict[str, dict[str, Any]] = {}
        for finding in findings:
            severity_counts[finding.severity.value] += 1
            confidence_counts[finding.confidence.value] += 1
            counts = domain_counts.setdefault(
                finding.domain.value,
                {
                    "finding_count": 0,
                    "severity_counts": {item.value: 0 for item in Severity},
                    "confidence_counts": {item.value: 0 for item in Confidence},
                },
            )
            counts["finding_count"] += 1
            counts["severity_counts"][finding.severity.value] += 1
            counts["confidence_counts"][finding.confidence.value] += 1

        domains: list[dict[str, Any]] = []
        incomplete_domains: list[str] = []
        for domain, row in sorted(latest_by_domain.items()):
            try:
                payload = json.loads(row["payload_json"])
            except (TypeError, ValueError):
                payload = {}
            if not isinstance(payload, dict):
                payload = {}
            route_scan = payload.get("route_scan", {})
            scan_complete = not (
                payload.get("truncated", False)
                or payload.get("parse_errors")
                or (
                    isinstance(route_scan, dict)
                    and route_scan.get("parse_errors")
                )
                or row["status"] == ExecutionStatus.FAILED.value
            )
            if not scan_complete:
                incomplete_domains.append(domain)
            counts = domain_counts.get(
                domain,
                {
                    "finding_count": 0,
                    "severity_counts": {item.value: 0 for item in Severity},
                    "confidence_counts": {item.value: 0 for item in Confidence},
                },
            )
            domains.append({
                "domain": domain,
                "assessment_id": row["assessment_id"],
                "assessment_status": row["status"],
                "created_at": row["created_at"],
                "scan_complete": scan_complete,
                **counts,
            })

        evidence_ids = {
            evidence_id
            for finding in findings
            for evidence_id in finding.evidence_ids
        }
        evidence: list[Evidence] = []
        for row in evidence_rows:
            try:
                item = Evidence.model_validate_json(row["payload_json"])
            except ValueError:
                continue
            if item.evidence_id in evidence_ids:
                evidence.append(item)
        evidence.sort(key=lambda item: item.source_path or "")

        domains_not_assessed = sorted(
            item.value for item in SWEADomain if item.value not in latest_by_domain
        )
        status = (
            ExecutionStatus.PARTIAL
            if not latest_by_domain or incomplete_domains
            else ExecutionStatus.COMPLETED
        )
        return ToolResult(
            project_id=project_id,
            status=status,
            result={
                "analysis_level": "latest_domain_risk_summary",
                "domains_assessed": len(domains),
                "domains_incomplete": incomplete_domains,
                "domains_not_assessed": domains_not_assessed,
                "overall": {
                    "open_finding_count": len(findings),
                    "severity_counts": severity_counts,
                    "confidence_counts": confidence_counts,
                },
                "domains": domains,
            },
            findings=findings,
            evidence=evidence,
            limitations=[
                "The summary includes only the latest assessment per domain; historical assessments are not aggregated.",
                "Counts are descriptive, not a calibrated risk score or proof of exploitability.",
                "A finding may be structurally valid while runtime impact remains unknown; inspect its confidence and evidence.",
                "Domains without a recorded assessment are not treated as assessed.",
            ],
            duration_ms=max(0, int((time.monotonic() - started) * 1000)),
        )

    def analyze_security(self, project_id: str) -> ToolResult:
        """Run bounded, read-only Python security pattern checks and persist evidence."""
        from swea_sentinel.core.security_analyzer import analyze_python_security

        _, root = self._project(project_id)
        report = analyze_python_security(root, self.index_settings)
        assessment_id = str(uuid4())
        now = datetime.now(UTC).isoformat()
        evidence_by_path = {
            relative: Evidence(
                kind="python_security_source",
                description="Python source file inspected by static security pattern checks",
                origin=DataOrigin.VERIFIED_SOURCE,
                qualification=QualificationStatus.QUALIFIED,
                source_path=relative,
                sha256=digest,
            )
            for relative, digest in report["file_hashes"].items()
        }
        evidence = list(evidence_by_path.values())
        findings = [
            Finding(
                domain=SWEADomain.SECURITY,
                code=item["code"],
                severity=Severity(item["severity"]),
                confidence=Confidence(item["confidence"]),
                title=item["message"][:300],
                location=f"{item['path']}:{item['line']}",
                evidence_ids=(
                    [evidence_by_path[item["path"]].evidence_id]
                    if item["path"] in evidence_by_path else []
                ),
                recommendation=item["recommendation"],
                status=FindingStatus.OPEN,
            )
            for item in report["findings"]
        ]
        status = (
            ExecutionStatus.PARTIAL
            if report["truncated"] or report["parse_errors"] or findings
            else ExecutionStatus.COMPLETED
        )
        with self.db.connect() as conn:
            conn.execute(
                "INSERT INTO assessments(assessment_id,project_id,task_id,domain,status,created_at,payload_json) "
                "VALUES(?,?,?,?,?,?,?)",
                (
                    assessment_id, project_id, None, SWEADomain.SECURITY.value,
                    status.value, now, json.dumps(report, separators=(",", ":")),
                ),
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
            for finding in findings:
                conn.execute(
                    "INSERT INTO findings(finding_id,project_id,assessment_id,domain,code,severity,confidence,status,payload_json) "
                    "VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        finding.finding_id, project_id, assessment_id,
                        finding.domain.value, finding.code, finding.severity.value,
                        finding.confidence.value, finding.status.value,
                        finding.model_dump_json(),
                    ),
                )
        return ToolResult(
            project_id=project_id,
            status=status,
            result={"assessment_id": assessment_id, **report},
            findings=findings,
            evidence=evidence,
            limitations=list(report["limitations"]),
            duration_ms=int(report["duration_ms"]),
        )

    def analyze_code_quality(self, project_id: str) -> ToolResult:
        """Run bounded, read-only Python code-quality checks and persist evidence."""
        from swea_sentinel.core.code_quality_analyzer import analyze_python_code_quality

        _, root = self._project(project_id)
        report = analyze_python_code_quality(root, self.index_settings)
        assessment_id = str(uuid4())
        now = datetime.now(UTC).isoformat()
        evidence_by_path = {
            relative: Evidence(
                kind="python_code_quality_source",
                description="Python source file inspected by static code-quality checks",
                origin=DataOrigin.VERIFIED_SOURCE,
                qualification=QualificationStatus.QUALIFIED,
                source_path=relative,
                sha256=digest,
            )
            for relative, digest in report["file_hashes"].items()
        }
        evidence = list(evidence_by_path.values())
        findings = [
            Finding(
                domain=SWEADomain.CODE_QUALITY,
                code=item["code"],
                severity=Severity(item["severity"]),
                confidence=Confidence(item["confidence"]),
                title=item["message"][:300],
                location=f"{item['path']}:{item['line']}",
                evidence_ids=(
                    [evidence_by_path[item["path"]].evidence_id]
                    if item["path"] in evidence_by_path else []
                ),
                recommendation=item["recommendation"],
                status=FindingStatus.OPEN,
            )
            for item in report["findings"]
        ]
        status = (
            ExecutionStatus.PARTIAL
            if report["truncated"] or report["parse_errors"] or findings
            else ExecutionStatus.COMPLETED
        )
        with self.db.connect() as conn:
            conn.execute(
                "INSERT INTO assessments(assessment_id,project_id,task_id,domain,status,created_at,payload_json) "
                "VALUES(?,?,?,?,?,?,?)",
                (
                    assessment_id, project_id, None, SWEADomain.CODE_QUALITY.value,
                    status.value, now, json.dumps(report, separators=(",", ":")),
                ),
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
            for finding in findings:
                conn.execute(
                    "INSERT INTO findings(finding_id,project_id,assessment_id,domain,code,severity,confidence,status,payload_json) "
                    "VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        finding.finding_id, project_id, assessment_id,
                        finding.domain.value, finding.code, finding.severity.value,
                        finding.confidence.value, finding.status.value,
                        finding.model_dump_json(),
                    ),
                )
        return ToolResult(
            project_id=project_id,
            status=status,
            result={"assessment_id": assessment_id, **report},
            findings=findings,
            evidence=evidence,
            limitations=list(report["limitations"]),
            duration_ms=int(report["duration_ms"]),
        )

    def analyze_contracts(self, project_id: str) -> ToolResult:
        """Discover and assess bounded OpenAPI and JSON Schema documents."""
        from swea_sentinel.core.contract_analyzer import analyze_contracts

        _, root = self._project(project_id)
        report = analyze_contracts(root)
        assessment_id = str(uuid4())
        now = datetime.now(UTC).isoformat()
        evidence_by_path = {
            item["path"]: Evidence(
                kind="api_data_contract",
                description=f"Static {item['kind']} contract document inspected",
                origin=DataOrigin.VERIFIED_SOURCE,
                qualification=QualificationStatus.QUALIFIED,
                source_path=item["path"],
                sha256=item["sha256"],
            )
            for item in report["contracts"]
        }
        evidence = list(evidence_by_path.values())
        route_evidence_by_path: dict[str, Evidence] = {}
        for mapping in report.get("source_mappings", []):
            for source in mapping.get("sources", []):
                source_path = source.get("source_path")
                source_hash = source.get("sha256")
                if (
                    isinstance(source_path, str)
                    and isinstance(source_hash, str)
                    and source_path not in route_evidence_by_path
                ):
                    route_evidence_by_path[source_path] = Evidence(
                        kind="python_route_source",
                        description="Python source file containing an exact static HTTP route declaration",
                        origin=DataOrigin.VERIFIED_SOURCE,
                        qualification=QualificationStatus.QUALIFIED,
                        source_path=source_path,
                        sha256=source_hash,
                    )
        evidence.extend(route_evidence_by_path.values())
        findings: list[Finding] = []
        for item in report["findings"]:
            evidence_item = evidence_by_path.get(item["path"])
            finding = Finding(
                domain=SWEADomain.DATA_CONTRACTS,
                code=item["code"],
                severity=Severity(item["severity"]),
                confidence=Confidence.HIGH_CONFIDENCE,
                title=item["message"][:300],
                location=item["path"],
                evidence_ids=[evidence_item.evidence_id] if evidence_item else [],
                recommendation=(
                    "Review the reported contract structure and correct it if the "
                    "document is intended to be authoritative."
                ),
                status=FindingStatus.OPEN,
            )
            findings.append(finding)

        status = (
            ExecutionStatus.PARTIAL
            if report["truncated"] or report["route_scan"]["parse_errors"] or findings
            else ExecutionStatus.COMPLETED
        )
        contract_dependency_rows = [
            (
                str(uuid4()),
                project_id,
                source["source_path"],
                f"{mapping['contract_path']}#operation:{mapping['method']} {mapping['path']}",
                "api_contract_graph",
            )
            for mapping in report.get("source_mappings", [])
            if mapping["mapping_status"] == "matched"
            for source in mapping["sources"]
        ]
        with self.db.connect() as conn:
            conn.execute(
                "INSERT INTO assessments(assessment_id,project_id,task_id,domain,status,created_at,payload_json) "
                "VALUES(?,?,?,?,?,?,?)",
                (
                    assessment_id, project_id, None, SWEADomain.DATA_CONTRACTS.value,
                    status.value, now, json.dumps(report, separators=(",", ":")),
                ),
            )
            conn.execute(
                "DELETE FROM dependencies WHERE project_id = ? AND dependency_type = 'api_contract_graph'",
                (project_id,),
            )
            conn.executemany(
                "INSERT INTO dependencies(dependency_id,project_id,source_path,target_name,dependency_type) "
                "VALUES(?,?,?,?,?)",
                contract_dependency_rows,
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
            for finding in findings:
                conn.execute(
                    "INSERT INTO findings(finding_id,project_id,assessment_id,domain,code,severity,confidence,status,payload_json) "
                    "VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        finding.finding_id, project_id, assessment_id,
                        finding.domain.value, finding.code, finding.severity.value,
                        finding.confidence.value, finding.status.value,
                        finding.model_dump_json(),
                    ),
                )
        return ToolResult(
            project_id=project_id,
            status=status,
            result={"assessment_id": assessment_id, **report},
            findings=findings,
            evidence=evidence,
            limitations=list(report["limitations"]),
            duration_ms=int(report["duration_ms"]),
        )

