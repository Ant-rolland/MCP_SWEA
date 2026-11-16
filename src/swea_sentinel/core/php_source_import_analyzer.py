"""Bounded static PHP class import discovery for Composer namespace attribution."""
from __future__ import annotations

import hashlib
import os
import re
import time
from pathlib import Path
from typing import Any

from swea_sentinel.config import ProjectIndexSettings

IGNORED_DIRS = {
    ".git", ".venv", "venv", "vendor", "node_modules", "__pycache__",
    ".mypy_cache", ".pytest_cache", "build", "dist", "coverage",
}
SINGLE_USE = re.compile(
    r"""^use\s+(?!function\b|const\b)([A-Za-z_][A-Za-z0-9_\\]*(?:\s+as\s+[A-Za-z_]\w*)?)\s*;"""
)
GROUP_USE = re.compile(
    r"""^use\s+(?!function\b|const\b)([A-Za-z_][A-Za-z0-9_\\]*)\\\{([^}]+)\}\s*;"""
)


def _class_imports(source: str) -> set[str]:
    imports: set[str] = set()
    for line in source.splitlines():
        stripped = line.lstrip()
        if stripped.startswith(("//", "/*", "*", "#")):
            continue
        group = GROUP_USE.match(line)
        if group:
            prefix, members = group.groups()
            for member in members.split(","):
                name = re.split(r"\s+as\s+", member.strip(), maxsplit=1, flags=re.IGNORECASE)[0]
                if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_\\]*", name):
                    imports.add(prefix + "\\" + name)
            continue
        match = SINGLE_USE.match(line)
        if match:
            imported = re.split(
                r"\s+as\s+", match.group(1).strip(), maxsplit=1, flags=re.IGNORECASE
            )[0]
            imports.add(imported)
    return imports


def analyze_php_source_imports(
    root: Path, settings: ProjectIndexSettings
) -> dict[str, Any]:
    """Find literal PHP class imports without loading Composer or executing project code."""
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
            if path.is_symlink() or path.suffix.lower() != ".php":
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
                source_path = path.relative_to(root).as_posix()
                source = raw.decode("utf-8")
            except (OSError, UnicodeError, ValueError):
                continue

            files_scanned += 1
            bytes_scanned += len(raw)
            imports = _class_imports(source)
            if imports:
                file_hashes[source_path] = hashlib.sha256(raw).hexdigest()
                edges.extend(
                    {"source": source_path, "import_name": imported}
                    for imported in sorted(imports)
                )
        if truncated_reason:
            break

    edges.sort(key=lambda item: (item["source"], item["import_name"]))
    return {
        "analysis_level": "static_php_class_imports",
        "files_scanned": files_scanned,
        "bytes_scanned": bytes_scanned,
        "edge_count": len(edges),
        "edges": edges,
        "file_hashes": file_hashes,
        "truncated": truncated_reason is not None,
        "truncated_reason": truncated_reason,
        "duration_ms": max(0, int((time.monotonic() - started) * 1000)),
        "limitations": [
            "Only column-zero, single-line PHP class use statements and grouped imports are recognized; this avoids treating normally indented class trait uses as package imports but may miss braced-namespace imports. This is not a PHP parser.",
            "Function and constant imports, dynamic class names, aliases, traits, attributes, and runtime autoload behavior are not resolved.",
            "Package attribution uses only explicit PSR-4 namespace prefixes recorded in Composer lock metadata; PSR-0 and inferred namespace conventions are excluded.",
            "A namespace import is structural evidence, not proof that the imported class is instantiated or used at runtime.",
            "Project source is never loaded, executed, or modified.",
        ],
    }
