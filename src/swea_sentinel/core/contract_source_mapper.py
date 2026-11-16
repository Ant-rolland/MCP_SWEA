"""Bounded, read-only mapping of static Python HTTP routes to API contracts."""
from __future__ import annotations

import ast
import hashlib
import os
import time
from pathlib import Path
from typing import Any

HTTP_METHODS = {
    "GET", "PUT", "POST", "DELETE", "OPTIONS", "HEAD", "PATCH", "TRACE",
}
DECORATOR_METHODS = {method.lower() for method in HTTP_METHODS}
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


def _literal_path(value: ast.expr | None) -> str | None:
    if (
        isinstance(value, ast.Constant)
        and isinstance(value.value, str)
        and (value.value == "" or value.value.startswith("/"))
    ):
        return value.value
    return None


def _join_paths(*parts: str) -> str:
    segments = [part.strip("/") for part in parts if part.strip("/")]
    return "/" + "/".join(segments) if segments else "/"


def _router_prefixes(tree: ast.Module) -> dict[str, list[str] | None]:
    """Resolve literal APIRouter prefixes and nested same-file mounts."""
    router_bases: dict[str, str | None] = {}
    mounts_by_parent: dict[str | None, list[tuple[str, str | None]]] = {}
    invalid_routers: set[str] = set()

    for statement in tree.body:
        targets: list[ast.expr] = []
        value: ast.expr | None = None
        if isinstance(statement, ast.Assign):
            targets = statement.targets
            value = statement.value
        elif isinstance(statement, ast.AnnAssign):
            targets = [statement.target]
            value = statement.value
        if not isinstance(value, ast.Call):
            continue
        is_router = (
            isinstance(value.func, ast.Name) and value.func.id == "APIRouter"
        ) or (
            isinstance(value.func, ast.Attribute) and value.func.attr == "APIRouter"
        )
        if not is_router:
            continue
        prefix_node = next(
            (item.value for item in value.keywords if item.arg == "prefix"), None
        )
        prefix = "" if prefix_node is None else _literal_path(prefix_node)
        for target in targets:
            if isinstance(target, ast.Name):
                router_bases[target.id] = prefix

    for node in ast.walk(tree):
        if (
            not isinstance(node, ast.Call)
            or not isinstance(node.func, ast.Attribute)
            or node.func.attr != "include_router"
            or not node.args
        ):
            continue
        child = node.args[0]
        if not isinstance(child, ast.Name) or child.id not in router_bases:
            continue
        parent = (
            node.func.value.id
            if isinstance(node.func.value, ast.Name)
            and node.func.value.id in router_bases
            else None
        )
        prefix_node = next(
            (item.value for item in node.keywords if item.arg == "prefix"), None
        )
        mount_prefix = "" if prefix_node is None else _literal_path(prefix_node)
        if mount_prefix is None:
            invalid_routers.add(child.id)
        mounts_by_parent.setdefault(parent, []).append((child.id, mount_prefix))

    resolved_sets: dict[str, set[str]] = {}
    mounted_as_child = {
        child
        for mounts in mounts_by_parent.values()
        for child, _prefix in mounts
    }

    def resolve(
        name: str, inherited_prefix: str, active: tuple[str, ...]
    ) -> None:
        if name in active:
            cycle_start = active.index(name)
            invalid_routers.update(active[cycle_start:])
            return
        base_prefix = router_bases.get(name)
        if base_prefix is None or name in invalid_routers:
            invalid_routers.add(name)
            return
        effective_prefix = _join_paths(inherited_prefix, base_prefix)
        resolved_sets.setdefault(name, set()).add(effective_prefix)
        next_active = (*active, name)
        for child_name, mount_prefix in mounts_by_parent.get(name, []):
            if mount_prefix is None:
                invalid_routers.add(child_name)
                continue
            resolve(child_name, _join_paths(effective_prefix, mount_prefix), next_active)

    for child_name, mount_prefix in mounts_by_parent.get(None, []):
        if mount_prefix is None:
            invalid_routers.add(child_name)
            continue
        resolve(child_name, mount_prefix, ())

    # A router not mounted by another router is a root in this file. This also
    # supports factories where the final app mount is outside the scanned file.
    for name in router_bases:
        if name not in mounted_as_child and name not in resolved_sets:
            resolve(name, "", ())

    return {
        name: None if name in invalid_routers else sorted(prefixes)
        for name, prefixes in resolved_sets.items()
    } | {
        name: None
        for name in invalid_routers
        if name not in resolved_sets
    }




def _decorator_routes(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    router_prefixes: dict[str, list[str] | None],
) -> list[dict[str, Any]]:
    routes: list[dict[str, Any]] = []
    for decorator in node.decorator_list:
        if not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute):
            continue
        name = decorator.func.attr.lower()
        if name not in DECORATOR_METHODS | {"route", "api_route"}:
            continue
        if not decorator.args or not isinstance(decorator.args[0], ast.Constant):
            continue
        route = decorator.args[0].value
        if not isinstance(route, str) or not route.startswith("/"):
            continue

        method_keyword = next(
            (kw.value for kw in decorator.keywords if kw.arg == "methods"), None
        )
        if name in DECORATOR_METHODS:
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

        router_name = (
            decorator.func.value.id
            if isinstance(decorator.func.value, ast.Name)
            else None
        )
        prefixes = router_prefixes.get(router_name, [""]) if router_name else [""]
        if prefixes is None:
            continue
        for method in methods:
            for prefix in prefixes:
                routes.append({
                    "method": method,
                    "path": _join_paths(prefix, route),
                    "source_path": "",
                    "function": node.name,
                    "line": node.lineno,
                    "framework_pattern": name,
                })
    return routes


def _expression_label(node: ast.expr | None) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _registration_routes(
    node: ast.Call,
    router_prefixes: dict[str, list[str] | None],
) -> list[dict[str, Any]]:
    """Recognize literal FastAPI/Flask/Starlette-style registration calls."""
    if not isinstance(node.func, ast.Attribute):
        return []
    name = node.func.attr
    if name not in {"add_api_route", "add_url_rule", "add_route"}:
        return []
    if not node.args:
        return []
    route = _literal_path(node.args[0])
    if route is None or not route.startswith("/"):
        return []

    method_keyword = next(
        (item.value for item in node.keywords if item.arg == "methods"), None
    )
    if method_keyword is None or (
        isinstance(method_keyword, ast.Constant) and method_keyword.value is None
    ):
        methods = ["GET"]
    else:
        parsed = _literal_methods(method_keyword)
        if parsed is None:
            return []
        methods = parsed

    endpoint_node = next(
        (
            item.value for item in node.keywords
            if item.arg in {"view_func", "endpoint"}
        ),
        None,
    )
    if endpoint_node is None:
        if name == "add_url_rule":
            if len(node.args) > 2:
                endpoint_node = node.args[2]
            elif len(node.args) > 1:
                endpoint_node = node.args[1]
        elif len(node.args) > 1:
            endpoint_node = node.args[1]
    endpoint = _expression_label(endpoint_node)
    router_name = node.func.value.id if isinstance(node.func.value, ast.Name) else None
    prefixes = router_prefixes.get(router_name, [""]) if router_name else [""]
    if prefixes is None:
        return []

    routes: list[dict[str, Any]] = []
    for method in methods:
        for prefix in prefixes:
            routes.append({
                "method": method,
                "path": _join_paths(prefix, route),
                "source_path": "",
                "function": endpoint,
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
    """Find explicit literal Python route decorators and registration calls without execution."""
    started = time.monotonic()
    routes: list[dict[str, Any]] = []
    parse_errors: list[dict[str, str]] = []
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
            except SyntaxError as exc:
                parse_errors.append({
                    "path": path.relative_to(root).as_posix(),
                    "error": "SyntaxError",
                    "line": str(exc.lineno or 0),
                })
                continue
            except (OSError, UnicodeError):
                continue

            relative = path.relative_to(root).as_posix()
            router_prefixes = _router_prefixes(tree)
            for node in ast.walk(tree):
                discovered: list[dict[str, Any]] = []
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    discovered.extend(_decorator_routes(node, router_prefixes))
                elif isinstance(node, ast.Call):
                    discovered.extend(_registration_routes(node, router_prefixes))
                for route in discovered:
                    route["source_path"] = relative
                    route["sha256"] = digest
                    routes.append(route)
        if truncated_reason:
            break

    unique = {
        (
            item["method"], item["path"], item["source_path"],
            item["function"], item["line"], item["framework_pattern"],
        ): item
        for item in routes
    }
    return {
        "routes": [unique[key] for key in sorted(unique)],
        "parse_errors": parse_errors,
        "files_scanned": files_scanned,
        "bytes_scanned": bytes_scanned,
        "truncated": truncated_reason is not None,
        "truncated_reason": truncated_reason,
        "duration_ms": max(0, int((time.monotonic() - started) * 1000)),
        "limitations": [
            "Only literal route paths and statically literal HTTP methods in Python decorators or add_api_route/add_url_rule/add_route registration calls are recognized.",
            "Dynamic route expressions or methods, dynamic router prefixes, cross-module router mounts, and non-Python routes are not resolved. Literal APIRouter prefixes and include_router prefixes are composed only within one Python file.",
            "Route declarations are structural evidence, not proof that a route is registered or reachable at runtime.",
            "Project code is parsed as syntax only; it is never imported or executed.",
        ],
    }
