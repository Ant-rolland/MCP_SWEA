"""Bounded, read-only Python code-quality checks based on the AST."""
from __future__ import annotations

import ast
import hashlib
import os
import time
from pathlib import Path
from typing import Any

from swea_sentinel.config import ProjectIndexSettings

IGNORED_DIRS = {
    ".git", ".venv", "venv", "node_modules", "__pycache__", ".mypy_cache",
    ".pytest_cache", ".next", ".turbo", "dist", "build", "coverage",
}


def _is_mutable_default(node: ast.expr) -> bool:
    if isinstance(node, (ast.List, ast.Dict, ast.Set)):
        return True
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in {"list", "dict", "set"}
    )


def _catches_broad_exception(node: ast.expr | None) -> bool:
    if isinstance(node, ast.Name):
        return node.id in {"Exception", "BaseException"}
    if isinstance(node, (ast.Tuple, ast.List)):
        return any(_catches_broad_exception(item) for item in node.elts)
    return False


class _QualityVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[dict[str, Any]] = []

    def _add(
        self,
        *,
        code: str,
        severity: str,
        line: int,
        message: str,
        recommendation: str,
    ) -> None:
        self.findings.append({
            "code": code,
            "severity": severity,
            "confidence": "HIGH_CONFIDENCE",
            "path": self.path,
            "line": line,
            "message": message,
            "recommendation": recommendation,
        })

    def _visit_function(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> None:
        defaults = [*node.args.defaults, *[
            value for value in node.args.kw_defaults if value is not None
        ]]
        for default in defaults:
            if _is_mutable_default(default):
                self._add(
                    code="PYTHON_MUTABLE_DEFAULT_ARGUMENT",
                    severity="medium",
                    line=getattr(default, "lineno", node.lineno),
                    message=(
                        f"Function '{node.name}' uses a mutable default argument; "
                        "the same object may be shared between calls."
                    ),
                    recommendation=(
                        "Use None as the default and create a new mutable value "
                        "inside the function."
                    ),
                )
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if len(node.body) == 1 and (
            isinstance(node.body[0], ast.Pass)
            or (
                isinstance(node.body[0], ast.Expr)
                and isinstance(node.body[0].value, ast.Constant)
                and node.body[0].value.value is Ellipsis
            )
        ):
            self._add(
                code="PYTHON_SWALLOWED_EXCEPTION",
                severity="medium",
                line=node.lineno,
                message="Exception handler ignores the caught exception without handling or reporting it.",
                recommendation=(
                    "Handle the expected failure explicitly, record useful context, "
                    "or re-raise the exception."
                ),
            )
        if node.type is None:
            self._add(
                code="PYTHON_BARE_EXCEPT",
                severity="medium",
                line=node.lineno,
                message="Bare except catches every exception, including process-control exceptions.",
                recommendation="Catch the narrow exception types the handler can recover from.",
            )
        elif _catches_broad_exception(node.type):
            self._add(
                code="PYTHON_BROAD_EXCEPTION_CATCH",
                severity="low",
                line=node.lineno,
                message="Exception handler catches Exception or BaseException broadly.",
                recommendation=(
                    "Prefer specific exception types; if broad handling is intentional, "
                    "re-raise unexpected failures."
                ),
            )
        self.generic_visit(node)


def analyze_python_code_quality(
    root: Path, settings: ProjectIndexSettings
) -> dict[str, Any]:
    """Inspect Python syntax without importing or executing project code."""
    started = time.monotonic()
    excluded = IGNORED_DIRS | set(settings.excluded_directories)
    findings: list[dict[str, Any]] = []
    parse_errors: list[dict[str, str]] = []
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
            if path.is_symlink() or path.suffix != ".py":
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
                relative = path.relative_to(root).as_posix()
                bytes_scanned += len(raw)
                files_scanned += 1
                file_hashes[relative] = hashlib.sha256(raw).hexdigest()
                tree = ast.parse(raw, filename=relative)
            except SyntaxError as exc:
                parse_errors.append({
                    "path": path.relative_to(root).as_posix(),
                    "error": "SyntaxError",
                    "line": str(exc.lineno or 0),
                })
                continue
            except (OSError, UnicodeError, ValueError):
                continue

            visitor = _QualityVisitor(relative)
            visitor.visit(tree)
            findings.extend(visitor.findings)
        if truncated_reason:
            break

    findings.sort(key=lambda item: (
        item["path"], item["line"], item["code"], item["message"]
    ))
    return {
        "analysis_level": "static_python_code_quality",
        "files_scanned": files_scanned,
        "bytes_scanned": bytes_scanned,
        "finding_count": len(findings),
        "findings": findings,
        "parse_errors": parse_errors,
        "truncated": truncated_reason is not None,
        "truncated_reason": truncated_reason,
        "duration_ms": max(0, int((time.monotonic() - started) * 1000)),
        "file_hashes": file_hashes,
        "limitations": [
            "Checks are limited to explicit Python AST patterns: mutable defaults, bare except, broad Exception/BaseException catches, and exception handlers that only pass or use an ellipsis.",
            "This is not a complete linter, type checker, security audit, or proof of runtime behavior.",
            "Findings do not account for project-specific exception policies or intentional mutable defaults.",
            "Dynamic behavior and non-Python source files are not inspected.",
            "No project code is imported or executed and no files are modified.",
        ],
    }
