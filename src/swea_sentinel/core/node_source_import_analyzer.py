"""Bounded static JavaScript/TypeScript external import discovery."""
from __future__ import annotations

import hashlib
import os
import re
import time
from pathlib import Path
from typing import Any

from swea_sentinel.config import ProjectIndexSettings

IGNORED_DIRS = {
    ".git", ".venv", "venv", "node_modules", "__pycache__", ".mypy_cache",
    ".pytest_cache", ".next", ".turbo", "dist", "build", "coverage",
}
SOURCE_SUFFIXES = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}
NODE_BUILTINS = {
    "assert", "async_hooks", "buffer", "child_process", "cluster", "console",
    "constants", "crypto", "dgram", "diagnostics_channel", "dns", "domain",
    "events", "fs", "http", "http2", "https", "inspector", "module", "net",
    "os", "path", "perf_hooks", "process", "punycode", "querystring",
    "readline", "repl", "stream", "string_decoder", "sys", "timers", "tls",
    "trace_events", "tty", "url", "util", "v8", "vm", "wasi", "worker_threads",
    "zlib", "test",
}
IMPORT_FROM = re.compile(
    r"""^\s*(?:import|export)\b[^;\n]*?\bfrom\s*['"]([^'"]+)['"]"""
)
SIDE_EFFECT_IMPORT = re.compile(r"""^\s*import\s*['"]([^'"]+)['"]""")
REQUIRE_IMPORT = re.compile(
    r"""^\s*(?:(?:const|let|var)\s+(?:[\w$]+|\{[^}\n]*\}|\[[^\]\n]*\])\s*=|module\.exports\s*=)\s*require\(\s*['"]([^'"]+)['"]\s*\)"""
)
DYNAMIC_IMPORT = re.compile(r"""\bimport\(\s*['"]([^'"]+)['"]\s*\)""")


def _package_root(specifier: str) -> str | None:
    """Return an npm package root, excluding relative paths, URLs, and Node builtins."""
    if (
        not specifier
        or specifier.startswith((".", "/", "#", "node:"))
        or "://" in specifier
    ):
        return None
    parts = specifier.split("/")
    root = "/".join(parts[:2]) if specifier.startswith("@") and len(parts) >= 2 else parts[0]
    if not root or root in NODE_BUILTINS:
        return None
    return root


def analyze_node_source_imports(
    root: Path, settings: ProjectIndexSettings
) -> dict[str, Any]:
    """Find literal JS/TS package imports without parsing or executing project code."""
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
            if path.is_symlink() or path.suffix.lower() not in SOURCE_SUFFIXES:
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
            source_edges: set[tuple[str, str]] = set()
            for line in text.splitlines():
                stripped = line.lstrip()
                if stripped.startswith(("//", "/*", "*")):
                    continue
                specifiers: list[str] = []
                for pattern in (IMPORT_FROM, SIDE_EFFECT_IMPORT, REQUIRE_IMPORT, DYNAMIC_IMPORT):
                    match = pattern.search(line)
                    if match:
                        specifiers.append(match.group(1))
                for specifier in specifiers:
                    package = _package_root(specifier)
                    if package is not None:
                        source_edges.add((package, specifier))

            if source_edges:
                file_hashes[source] = hashlib.sha256(raw).hexdigest()
                edges.extend(
                    {
                        "source": source,
                        "import_root": package,
                        "import": specifier,
                    }
                    for package, specifier in sorted(source_edges)
                )
        if truncated_reason:
            break

    edges.sort(key=lambda item: (item["source"], item["import_root"], item["import"]))
    return {
        "analysis_level": "static_javascript_typescript_import_specifiers",
        "files_scanned": files_scanned,
        "bytes_scanned": bytes_scanned,
        "edge_count": len(edges),
        "edges": edges,
        "file_hashes": file_hashes,
        "truncated": truncated_reason is not None,
        "truncated_reason": truncated_reason,
        "duration_ms": max(0, int((time.monotonic() - started) * 1000)),
        "limitations": [
            "Only single-line literal ES import/export, require, and dynamic import specifiers are recognized; this is not a JavaScript or TypeScript parser.",
            "Relative imports, URL imports, Node builtins, computed specifiers, multiline import declarations, and aliased package names are not resolved.",
            "An import statement is structural evidence, not proof that the imported package is used at runtime.",
            "Package attribution requires one exact matching package name and one unique locked package version across discovered Node lockfiles.",
            "Project source is never imported or executed and is not modified.",
        ],
    }
