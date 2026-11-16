"""Bounded, read-only Python security pattern checks based on the AST."""
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
SUBPROCESS_FUNCTIONS = {"run", "call", "Popen", "check_call", "check_output"}


def _is_name(node: ast.expr | None, name: str) -> bool:
    return isinstance(node, ast.Name) and node.id == name


def _is_attribute(node: ast.expr | None, owner: str, attribute: str) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and node.attr == attribute
        and _is_name(node.value, owner)
    )


def _keyword(node: ast.Call, name: str) -> ast.expr | None:
    return next((item.value for item in node.keywords if item.arg == name), None)


def _literal_true(node: ast.expr | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _safe_yaml_loader(node: ast.expr | None) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and node.attr in {"SafeLoader", "CSafeLoader"}
        and _is_name(node.value, "yaml")
    ) or _is_name(node, "SafeLoader") or _is_name(node, "CSafeLoader")


class _SecurityVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[dict[str, Any]] = []

    def _add(
        self,
        *,
        code: str,
        severity: str,
        confidence: str,
        node: ast.AST,
        message: str,
        recommendation: str,
    ) -> None:
        self.findings.append({
            "code": code,
            "severity": severity,
            "confidence": confidence,
            "path": self.path,
            "line": getattr(node, "lineno", 0),
            "message": message,
            "recommendation": recommendation,
        })

    def visit_Call(self, node: ast.Call) -> None:
        function = node.func
        if isinstance(function, ast.Name) and function.id in {"eval", "exec"}:
            self._add(
                code="PYTHON_DYNAMIC_CODE_EXECUTION",
                severity="high",
                confidence="HIGH_CONFIDENCE",
                node=node,
                message=f"Call to built-in {function.id} dynamically evaluates or executes code.",
                recommendation=(
                    "Avoid dynamic code execution; use an explicit parser, registry, "
                    "or constrained dispatch table."
                ),
            )
        elif _is_attribute(function, "os", "system") or _is_attribute(function, "os", "popen"):
            self._add(
                code="PYTHON_OS_COMMAND_EXECUTION",
                severity="high",
                confidence="HIGH_CONFIDENCE",
                node=node,
                message="Call to os.system/os.popen starts a command through the system shell.",
                recommendation=(
                    "Prefer a subprocess API with an argument list, explicit executable, "
                    "timeout, and controlled environment."
                ),
            )
        elif (
            isinstance(function, ast.Attribute)
            and _is_name(function.value, "subprocess")
            and function.attr in SUBPROCESS_FUNCTIONS
            and _literal_true(_keyword(node, "shell"))
        ):
            self._add(
                code="PYTHON_SUBPROCESS_SHELL_TRUE",
                severity="high",
                confidence="HIGH_CONFIDENCE",
                node=node,
                message=f"subprocess.{function.attr} is called with shell=True.",
                recommendation=(
                    "Pass an argument sequence with shell=False; validate arguments "
                    "and enforce timeouts and output limits."
                ),
            )
        elif _is_attribute(function, "yaml", "unsafe_load"):
            self._add(
                code="PYTHON_UNSAFE_YAML_LOAD",
                severity="high",
                confidence="HIGH_CONFIDENCE",
                node=node,
                message="yaml.unsafe_load can construct arbitrary Python objects from YAML.",
                recommendation="Use yaml.safe_load for untrusted or externally supplied YAML.",
            )
        elif _is_attribute(function, "yaml", "load") and not _safe_yaml_loader(
            _keyword(node, "Loader")
        ):
            self._add(
                code="PYTHON_YAML_LOAD_WITHOUT_SAFE_LOADER",
                severity="high",
                confidence="HIGH_CONFIDENCE",
                node=node,
                message="yaml.load is used without an explicit SafeLoader.",
                recommendation="Use yaml.safe_load or pass yaml.SafeLoader explicitly.",
            )
        elif (
            isinstance(function, ast.Attribute)
            and _is_name(function.value, "pickle")
            and function.attr in {"load", "loads"}
        ):
            self._add(
                code="PYTHON_PICKLE_DESERIALIZATION",
                severity="medium",
                confidence="HEURISTIC",
                node=node,
                message=(
                    f"pickle.{function.attr} deserializes Python objects; untrusted "
                    "pickle data can execute code."
                ),
                recommendation=(
                    "Never deserialize untrusted pickle data; prefer a data-only format "
                    "such as JSON when possible."
                ),
            )
        self.generic_visit(node)


def analyze_python_security(
    root: Path, settings: ProjectIndexSettings
) -> dict[str, Any]:
    """Inspect Python syntax for selected risky APIs without executing project code."""
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

            visitor = _SecurityVisitor(relative)
            visitor.visit(tree)
            findings.extend(visitor.findings)
        if truncated_reason:
            break

    findings.sort(key=lambda item: (
        item["path"], item["line"], item["code"], item["message"]
    ))
    return {
        "analysis_level": "static_python_security_patterns",
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
            "Checks cover selected Python AST patterns only: dynamic code execution, shell command APIs, unsafe YAML loading, and pickle deserialization.",
            "The analyzer does not perform taint analysis, data-flow analysis, import alias resolution, or prove that arguments are attacker-controlled.",
            "pickle findings are heuristic because exploitability depends on the trust boundary of the input.",
            "The analyzer does not inspect non-Python code, dependencies, runtime configuration, or deployed environments.",
            "No project code is imported or executed and no files are modified.",
        ],
    }
