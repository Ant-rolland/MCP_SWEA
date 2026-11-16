"""Bounded static Rust crate import discovery."""
from __future__ import annotations

import hashlib
import os
import re
import time
from pathlib import Path
from typing import Any

from swea_sentinel.config import ProjectIndexSettings

IGNORED_DIRS = {
    ".git", ".venv", "venv", "node_modules", "vendor", "target", "__pycache__",
    ".mypy_cache", ".pytest_cache", "dist", "build", "coverage",
}
LOCAL_ROOTS = {"crate", "self", "super", "std", "core", "alloc", "proc_macro", "test"}
USE_IMPORT = re.compile(
    r"""^\s*(?:pub(?:\([^)]*\))?\s+)?use\s+(?:::)?([A-Za-z_]\w*)(?:::|\s+as\s+|;)"""
)
EXTERN_CRATE = re.compile(
    r"""^\s*extern\s+crate\s+([A-Za-z_]\w*)\s*;"""
)


def analyze_rust_source_imports(
    root: Path, settings: ProjectIndexSettings
) -> dict[str, Any]:
    """Find literal Rust crate roots without invoking Cargo or compiling the project."""
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
            if path.is_symlink() or path.suffix.lower() != ".rs":
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
            for line in text.splitlines():
                stripped = line.lstrip()
                if stripped.startswith(("//", "/*", "*", "///", "//!")):
                    continue
                match = USE_IMPORT.match(line) or EXTERN_CRATE.match(line)
                if match:
                    crate = match.group(1)
                    if crate not in LOCAL_ROOTS:
                        imports.add(crate)

            if imports:
                file_hashes[source] = hashlib.sha256(raw).hexdigest()
                edges.extend(
                    {"source": source, "import_root": crate}
                    for crate in sorted(imports)
                )
        if truncated_reason:
            break

    edges.sort(key=lambda item: (item["source"], item["import_root"]))
    return {
        "analysis_level": "static_rust_crate_import_roots",
        "files_scanned": files_scanned,
        "bytes_scanned": bytes_scanned,
        "edge_count": len(edges),
        "edges": edges,
        "file_hashes": file_hashes,
        "truncated": truncated_reason is not None,
        "truncated_reason": truncated_reason,
        "duration_ms": max(0, int((time.monotonic() - started) * 1000)),
        "limitations": [
            "Only literal single-line use and extern crate declarations are recognized; this is not a Rust parser.",
            "Local module resolution, macro expansion, conditional compilation, build scripts, and generated code are not resolved.",
            "Crate names are matched to Cargo.lock package names after hyphen-to-underscore normalization only when one locked version is unique.",
            "An import declaration is structural evidence, not proof that a crate is used at runtime.",
            "Project source is never compiled, imported, or executed and is not modified.",
        ],
    }
