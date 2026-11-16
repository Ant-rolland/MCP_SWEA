"""Bounded static Go import discovery."""
from __future__ import annotations

import hashlib
import os
import re
import time
from pathlib import Path
from typing import Any

from swea_sentinel.config import ProjectIndexSettings

IGNORED_DIRS = {
    ".git", ".venv", "venv", "node_modules", "vendor", "__pycache__",
    ".mypy_cache", ".pytest_cache", ".next", ".turbo", "dist", "build",
    "coverage",
}
SINGLE_IMPORT = re.compile(
    r"""^\s*import\s+(?:(?:[A-Za-z_]\w*|_|\.)\s+)?["`]([^"`]+)["`]"""
)
GROUP_START = re.compile(r"""^\s*import\s*\(""")
GROUP_IMPORT = re.compile(
    r"""^\s*(?:(?:[A-Za-z_]\w*|_|\.)\s+)?["`]([^"`]+)["`]"""
)


def analyze_go_source_imports(
    root: Path, settings: ProjectIndexSettings
) -> dict[str, Any]:
    """Find literal Go import paths without invoking the Go toolchain."""
    started = time.monotonic()
    excluded = IGNORED_DIRS | set(settings.excluded_directories)
    edges: list[dict[str, str]] = []
    file_hashes: dict[str, str] = {}
    files_scanned = 0
    bytes_scanned = 0
    truncated_reason: str | None = None

    for current, dirs, filenames in os.walk(root, followlinks=False):
        dirs[:] = sorted(
            name for name in dirs
            if name not in excluded and not (Path(current) / name).is_symlink()
        )
        for filename in sorted(filenames):
            if time.monotonic() - started > settings.max_scan_seconds:
                truncated_reason = "maximum_scan_duration"
                break
            path = Path(current) / filename
            if path.is_symlink() or path.suffix.lower() != ".go":
                continue
            if files_scanned >= settings.max_files:
                truncated_reason = "maximum_file_count"
                break
            try:
                size = path.stat().st_size
                if not path.is_file() or size > settings.max_file_bytes:
                    continue
                if bytes_scanned + size > settings.max_total_bytes:
                    truncated_reason = "maximum_total_bytes"
                    break
                with path.open("rb") as stream:
                    raw = stream.read(settings.max_file_bytes + 1)
                if len(raw) > settings.max_file_bytes:
                    continue
                if bytes_scanned + len(raw) > settings.max_total_bytes:
                    truncated_reason = "maximum_total_bytes"
                    break
                source = path.relative_to(root).as_posix()
                text = raw.decode("utf-8")
            except (OSError, UnicodeError, ValueError):
                continue

            files_scanned += 1
            bytes_scanned += len(raw)
            imports: set[str] = set()
            in_group = False
            for line in text.splitlines():
                stripped = line.lstrip()
                if stripped.startswith(("//", "/*", "*")):
                    continue
                if in_group:
                    if stripped.startswith(")"):
                        in_group = False
                        continue
                    match = GROUP_IMPORT.match(line)
                    if match:
                        imports.add(match.group(1))
                    continue
                if GROUP_START.match(line):
                    in_group = True
                    continue
                match = SINGLE_IMPORT.match(line)
                if match:
                    imports.add(match.group(1))

            if imports:
                file_hashes[source] = hashlib.sha256(raw).hexdigest()
                edges.extend(
                    {
                        "source": source,
                        "import_path": import_path,
                    }
                    for import_path in sorted(imports)
                )
        if truncated_reason:
            break

    edges.sort(key=lambda item: (item["source"], item["import_path"]))
    return {
        "analysis_level": "static_go_import_paths",
        "files_scanned": files_scanned,
        "bytes_scanned": bytes_scanned,
        "edge_count": len(edges),
        "edges": edges,
        "file_hashes": file_hashes,
        "truncated": truncated_reason is not None,
        "truncated_reason": truncated_reason,
        "duration_ms": max(0, int((time.monotonic() - started) * 1000)),
        "limitations": [
            "Only literal single-line and grouped Go import declarations are recognized; this is not a Go parser.",
            "Build tags, generated code, cgo resolution, vendored dependencies, and dynamic plugin loading are not resolved.",
            "An import path is linked to a Go module only when one uniquely locked go.sum module is the longest exact path prefix; multiple versions remain ambiguous.",
            "go.sum records checksums and versions but does not establish the selected module graph or package-level runtime use.",
            "Project source is never compiled, imported, or executed and is not modified.",
        ],
    }
