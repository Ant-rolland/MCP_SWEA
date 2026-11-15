"""Bounded, read-only Python import graph analysis for P2."""
from __future__ import annotations

import ast
import os
import time
from pathlib import Path
from typing import Any

from swea_sentinel.config import ProjectIndexSettings

IGNORED_DIRS = {
    ".git", ".venv", "venv", "node_modules", "__pycache__", ".mypy_cache",
    ".pytest_cache", ".next", ".turbo", "dist", "build", "coverage",
}


def _module_name(relative_path: str) -> str:
    path = Path(relative_path)
    parts = list(path.with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def analyze_python_imports(
    root: Path, settings: ProjectIndexSettings
) -> dict[str, Any]:
    """Build a local Python import graph without executing or modifying project code."""
    started = time.monotonic()
    excluded = IGNORED_DIRS | set(settings.excluded_directories)
    python_files: list[tuple[Path, str]] = []
    total_bytes = 0
    truncated_reason: str | None = None

    for current, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(
            name for name in dirs
            if name not in excluded and not (Path(current) / name).is_symlink()
        )
        for filename in sorted(files):
            if time.monotonic() - started > settings.max_scan_seconds:
                truncated_reason = "maximum_scan_duration"
                break
            path = Path(current) / filename
            if path.is_symlink() or path.suffix != ".py":
                continue
            if len(python_files) >= settings.max_files:
                truncated_reason = "maximum_file_count"
                break
            try:
                stat = path.stat()
                if not path.is_file() or stat.st_size > settings.max_file_bytes:
                    continue
                if total_bytes + stat.st_size > settings.max_total_bytes:
                    truncated_reason = "maximum_total_bytes"
                    break
                relative = path.relative_to(root).as_posix()
                python_files.append((path, relative))
                total_bytes += stat.st_size
            except (OSError, ValueError):
                continue
        if truncated_reason:
            break

    modules: dict[str, str] = {}
    for _, relative in python_files:
        name = _module_name(relative)
        if name:
            modules[name] = relative

    local_edges: set[tuple[str, str, str]] = set()
    external_imports: set[str] = set()
    parse_errors: list[dict[str, str]] = []
    file_hashes: dict[str, str] = {}

    import hashlib

    for path, relative in python_files:
        if time.monotonic() - started > settings.max_scan_seconds:
            truncated_reason = truncated_reason or "maximum_scan_duration"
            break
        try:
            raw = path.read_bytes()
            file_hashes[relative] = hashlib.sha256(raw).hexdigest()
            tree = ast.parse(raw, filename=relative)
        except (OSError, UnicodeError) as exc:
            parse_errors.append({"path": relative, "error": type(exc).__name__})
            continue
        except SyntaxError as exc:
            parse_errors.append({
                "path": relative,
                "error": "SyntaxError",
                "line": str(exc.lineno or 0),
            })
            continue

        source_module = _module_name(relative)
        for node in ast.walk(tree):
            imported: list[str] = []
            if isinstance(node, ast.Import):
                imported.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                base = node.module or ""
                if node.level:
                    package = source_module.split(".")[:-1]
                    if node.level > len(package) + 1:
                        continue
                    package = package[: len(package) - node.level + 1]
                    base = ".".join([*package, base]).strip(".")
                if base:
                    imported.append(base)
                    imported.extend(f"{base}.{alias.name}" for alias in node.names)

            for target in imported:
                match = next(
                    (candidate for candidate in sorted(modules, key=len, reverse=True)
                     if target == candidate or target.startswith(candidate + ".")),
                    None,
                )
                if match and source_module and source_module != match:
                    local_edges.add((relative, modules[match], target))
                elif not match and target:
                    external_imports.add(target.split(".")[0])

    return {
        "analysis_level": "python_static_import_graph",
        "files_scanned": len(file_hashes),
        "indexed_python_files": len(python_files),
        "indexed_bytes": total_bytes,
        "local_dependency_edges": [
            {"source": source, "target": target, "import": imported}
            for source, target, imported in sorted(local_edges)
        ],
        "external_import_roots": sorted(external_imports),
        "parse_errors": parse_errors,
        "truncated": truncated_reason is not None,
        "truncated_reason": truncated_reason,
        "duration_ms": max(0, int((time.monotonic() - started) * 1000)),
        "file_hashes": file_hashes,
        "limitations": [
            "Static import resolution is approximate and does not execute project code.",
            "Dynamic imports, plugin loading, runtime dependency injection and generated modules are not resolved.",
            "External import roots are names observed in source, not a validated package inventory.",
            "A detected local import edge does not prove that the dependency is used at runtime.",
        ],
    }
}
