"""Bounded, read-only mapping of static Python HTTP routes to API contracts."""
from __future__ import annotations

import ast
import hashlib
import os
import time
from pathlib import Path
from typing import Any

HTTP_METHODS = {"GET", "PUT", "POST", "DELETE", "OPTIONS", "HEAD", "PATCH", "TRACE"}
IGNORED_DIRS = {
    ".git", ".venv", "venv", "node_modules", "__pycache__", ".mypy_cache",
    ".pytest_cache", ".next", ".turbo", "dist", "build", "coverage",
}


def _literal_methods(value: ast.expr) -> list[str] | None:
    if not isinstance(value, (ast.List, ast.Tuple, ast.Set)):
        return None
    methods: list[str] = []
    for item in value.elts:
        if not isinstance(item, ast.Constant) or not isinstance(item.value, str):
            return None
        method = item.value.upper()
        if method not in HTTP_METHODS:
            return None
        methods.append(method)
    return sorted(set(methods))


def _decorator_routes(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[dict[str, Any]]:
    routes: list[dict[str, Any]] = []
    for decorator in node.decorator_list:
        if not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute):
            continue
        name = decorator.func.attr.lower()
        if name not in {"get", "put", "post", "delete", "options", "head", "patch", "trace", "route", "api_route"}:
            continue
        if not decorator.args or not isinstance(decorator.args[0], ast.Constant):
            continue
        route = decorator.args[0].value
        if not isinstance(route, str) or not route.startswith("/"):
            continue

        method_keyword = next((kw.value for kw in decorator.keywords if kw.arg == "methods"), None)
        if name in {method.lower() for method in HTTP_METHODS}:
            methods = [name.upper()]
        elif method_keyword is not None:
            parsed = _literal_methods(method_keyword)
            if parsed is None:
                continue
            methods = parsed
        elif name in {"route", "api_route"}:
            methods = ["GET"]
        else:
            continue

        for method in methods:
            routes.append({
                "method": method,
                "path": route,
                "source_path": "",
                "function": node.name,
                "line": node.lineno,
                "framework_pattern": name,
            })
    return routes


def discover_python_routes(
    root: Path,
    *,
    max_files: int = 500,
    max_file_bytes: int = 1_000_000,
    max_total_bytes: int = 10_000_000,
    max_scan_seconds: float = 5.0,
) -> dict[str, Any]:
    """Find only explicit, literal route decorators; never import or execute project code."""
    started = time.monotonic()
    routes: list[dict[str, Any]] = []
    files_scanned = 0
    bytes_scanned = 0
    truncated_reason: str | None = None

    for current, dirs, filenames in os.walk(root, followlinks=False):
        dirs[:] = sorted(
            name for name in dirs
            if name not in IGNORED_DIRS and not (Path(current) / name).is_symlink()
        )
        for filename in sorted(filenames):
            if time.monotonic() - started > max_scan_seconds:
                truncated_reason = "maximum_scan_duration"
                break
            path = Path(current) / filename
            if path.is_symlink() or path.suffix != ".py":
                continue
            if files_scanned >= max_files:
                truncated_reason = "maximum_file_count"
                break
            try:
                size = path.stat().st_size
                if size > max_file_bytes:
                    continue
                if bytes_scanned + size > max_total_bytes:
                    truncated_reason = "maximum_total_bytes"
                    break
                with path.open("rb") as stream:
                    raw = stream.read(max_file_bytes + 1)
                if len(raw) > max_file_bytes:
                    continue
                if bytes_scanned + len(raw) > max_total_bytes:
                    truncated_reason = "maximum_total_bytes"
                    break
                bytes_scanned += len(raw)
                files_scanned += 1
                digest = hashlib.sha256(raw).hexdigest()
                tree = ast.parse(raw, filename=path.relative_to(root).as_posix())
            except (OSError, UnicodeError, SyntaxError):
                continue

            relative = path.relative_to(root).as_posix()
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    for route in _decorator_routes(node):
                        route["source_path"] = relative
                        route["sha256"] = digest
                        routes.append(route)
        if truncated_reason:
            break

    unique = {
        (item["method"], item["path"], item["source_path"], item["function"], item["line"], item["framework_pattern"]): item
        for item in routes
    }
    return {
        "routes": [unique[key] for key in sorted(unique)],
        "files_scanned": files_scanned,
        "bytes_scanned": bytes_scanned,
        "truncated": truncated_reason is not None,
        "truncated_reason": truncated_reason,
        "duration_ms": max(0, int((time.monotonic() - started) * 1000)),
        "limitations": [
            "Only literal route paths and statically literal HTTP methods in Python decorators are recognized.",
            "Dynamic route expressions, router prefix composition, framework registration calls, and non-Python routes are not resolved.",
            "Route declarations are structural evidence, not proof that a route is registered or reachable at runtime.",
            "Project code is parsed as syntax only; it is never imported or executed.",
        ],
    }
