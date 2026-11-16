"""Bounded, read-only Python security pattern checks based on the AST."""
from __future__ import annotations

import ast
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
SUBPROCESS_FUNCTIONS = {"run", "call", "Popen", "check_call", "check_output"}
SECRET_PATTERNS = (
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b"),
    re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
    re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
)


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


def _literal_false(node: ast.expr | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


def _dynamic_sql_query(node: ast.expr) -> bool:
    """Recognize dynamic string construction with an obvious SQL statement prefix."""
    prefix: str | None = None
    dynamic = False
    if isinstance(node, ast.JoinedStr):
        prefix = next(
            (
                item.value for item in node.values
                if isinstance(item, ast.Constant) and isinstance(item.value, str)
            ),
            None,
        )
        dynamic = any(isinstance(item, ast.FormattedValue) for item in node.values)
    elif (
        isinstance(node, ast.BinOp)
        and isinstance(node.op, (ast.Add, ast.Mod))
        and isinstance(node.left, ast.Constant)
        and isinstance(node.left.value, str)
    ):
        prefix = node.left.value
        dynamic = True
    elif (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
        and isinstance(node.func.value, ast.Constant)
        and isinstance(node.func.value.value, str)
    ):
        prefix = node.func.value.value
        dynamic = bool(node.args or node.keywords)

    return bool(
        dynamic
        and prefix
        and re.match(
            r"^\s*(SELECT|INSERT|UPDATE|DELETE|REPLACE|MERGE|WITH)\b",
            prefix,
            flags=re.IGNORECASE,
        )
    )


def _collect_import_aliases(
    tree: ast.Module,
) -> tuple[dict[str, str], dict[str, tuple[str, str]]]:
    """Resolve simple import aliases only when their local names are not rebound."""
    module_aliases: dict[str, str] = {}
    function_aliases: dict[str, tuple[str, str]] = {}
    ambiguous_names: set[str] = set()
    rebound_names: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                bound_name = item.asname or item.name.split(".")[0]
                previous = module_aliases.get(bound_name)
                if previous is not None and previous != item.name:
                    ambiguous_names.add(bound_name)
                module_aliases[bound_name] = item.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for item in node.names:
                if item.name == "*":
                    continue
                bound_name = item.asname or item.name
                previous = function_aliases.get(bound_name)
                resolved = (node.module, item.name)
                if previous is not None and previous != resolved:
                    ambiguous_names.add(bound_name)
                function_aliases[bound_name] = resolved
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            rebound_names.add(node.id)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            rebound_names.add(node.name)
        elif isinstance(node, ast.arg):
            rebound_names.add(node.arg)

    for name in ambiguous_names | rebound_names:
        module_aliases.pop(name, None)
        function_aliases.pop(name, None)
    return module_aliases, function_aliases


def _resolved_attribute(
    node: ast.expr,
    owner: str,
    attribute: str,
    module_aliases: dict[str, str],
) -> bool:
    if not isinstance(node, ast.Attribute) or node.attr != attribute:
        return False
    if _is_name(node.value, owner):
        return True
    return (
        isinstance(node.value, ast.Name)
        and module_aliases.get(node.value.id) == owner
    )


def _resolved_function(
    node: ast.expr,
    owner: str,
    function: str,
    function_aliases: dict[str, tuple[str, str]],
) -> bool:
    return (
        isinstance(node, ast.Name)
        and function_aliases.get(node.id) == (owner, function)
    )


def _safe_yaml_loader(
    node: ast.expr | None,
    module_aliases: dict[str, str],
    function_aliases: dict[str, tuple[str, str]],
) -> bool:
    if isinstance(node, ast.Attribute) and node.attr in {"SafeLoader", "CSafeLoader"}:
        if _is_name(node.value, "yaml"):
            return True
        if (
            isinstance(node.value, ast.Name)
            and module_aliases.get(node.value.id) == "yaml"
        ):
            return True
    return (
        _is_name(node, "SafeLoader")
        or _is_name(node, "CSafeLoader")
        or (
            isinstance(node, ast.Name)
            and function_aliases.get(node.id) in {
                ("yaml", "SafeLoader"), ("yaml", "CSafeLoader")
            }
        )
    )


class _SecurityVisitor(ast.NodeVisitor):
    def __init__(
        self,
        path: str,
        module_aliases: dict[str, str],
        function_aliases: dict[str, tuple[str, str]],
    ) -> None:
        self.path = path
        self.module_aliases = module_aliases
        self.function_aliases = function_aliases
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

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str) and any(
            pattern.search(node.value) for pattern in SECRET_PATTERNS
        ):
            self._add(
                code="PYTHON_HARDCODED_CREDENTIAL",
                severity="high",
                confidence="HIGH_CONFIDENCE",
                node=node,
                message=(
                    "A string literal matches a known credential or private-key "
                    "format; the literal value is intentionally not included."
                ),
                recommendation=(
                    "Remove the credential from source, load it from a secret manager "
                    "or protected environment, and rotate it if it was real."
                ),
            )
        self.generic_visit(node)

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
        elif (
            _resolved_attribute(function, "os", "system", self.module_aliases)
            or _resolved_attribute(function, "os", "popen", self.module_aliases)
            or _resolved_function(function, "os", "system", self.function_aliases)
            or _resolved_function(function, "os", "popen", self.function_aliases)
        ):
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
            and function.attr in SUBPROCESS_FUNCTIONS
            and (
                _is_name(function.value, "subprocess")
                or (
                    isinstance(function.value, ast.Name)
                    and self.module_aliases.get(function.value.id) == "subprocess"
                )
            )
            and _literal_true(_keyword(node, "shell"))
        ) or (
            isinstance(function, ast.Name)
            and function.id in self.function_aliases
            and self.function_aliases[function.id][0] == "subprocess"
            and self.function_aliases[function.id][1] in SUBPROCESS_FUNCTIONS
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
        elif (
            _resolved_attribute(function, "yaml", "unsafe_load", self.module_aliases)
            or _resolved_function(function, "yaml", "unsafe_load", self.function_aliases)
        ):
            self._add(
                code="PYTHON_UNSAFE_YAML_LOAD",
                severity="high",
                confidence="HIGH_CONFIDENCE",
                node=node,
                message="yaml.unsafe_load can construct arbitrary Python objects from YAML.",
                recommendation="Use yaml.safe_load for untrusted or externally supplied YAML.",
            )
        elif (
            (
                _resolved_attribute(function, "yaml", "load", self.module_aliases)
                or _resolved_function(function, "yaml", "load", self.function_aliases)
            )
            and not _safe_yaml_loader(
                _keyword(node, "Loader"),
                self.module_aliases,
                self.function_aliases,
            )
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
            (
                isinstance(function, ast.Attribute)
                and isinstance(function.value, ast.Name)
                and (
                    function.value.id in {"requests", "httpx"}
                    or self.module_aliases.get(function.value.id) in {"requests", "httpx"}
                )
            )
            or (
                isinstance(function, ast.Name)
                and function.id in self.function_aliases
                and self.function_aliases[function.id][0] in {"requests", "httpx"}
            )
        ) and _literal_false(_keyword(node, "verify"))
        ):
            self._add(
                code="PYTHON_TLS_CERTIFICATE_VERIFICATION_DISABLED",
                severity="high",
                confidence="HIGH_CONFIDENCE",
                node=node,
                message=(
                    f"{function.value.id}.{function.attr} is called with verify=False, "
                    "disabling TLS certificate verification."
                ),
                recommendation=(
                    "Keep certificate verification enabled; configure a trusted CA "
                    "bundle instead of disabling TLS verification."
                ),
            )
        elif (
            _resolved_attribute(
                function, "ssl", "_create_unverified_context", self.module_aliases
            )
            or _resolved_function(
                function, "ssl", "_create_unverified_context", self.function_aliases
            )
        ):
            self._add(
                code="PYTHON_TLS_UNVERIFIED_SSL_CONTEXT",
                severity="high",
                confidence="HIGH_CONFIDENCE",
                node=node,
                message="ssl._create_unverified_context disables TLS certificate verification.",
                recommendation=(
                    "Use ssl.create_default_context with certificate verification "
                    "enabled and a trusted CA configuration."
                ),
            )
        elif (
            isinstance(function, ast.Attribute)
            and function.attr in {"execute", "executemany"}
            and node.args
            and _dynamic_sql_query(node.args[0])
        ):
            self._add(
                code="PYTHON_DYNAMIC_SQL_QUERY",
                severity="high",
                confidence="HEURISTIC",
                node=node,
                message=(
                    "A SQL statement is dynamically assembled before being passed "
                    "to execute/executemany; interpolated values may alter the query."
                ),
                recommendation=(
                    "Use parameterized queries and pass values separately; do not "
                    "interpolate data into SQL statement strings."
                ),
            )
        elif (
            (
                isinstance(function, ast.Attribute)
                and function.attr in {"load", "loads"}
                and (
                    _is_name(function.value, "pickle")
                    or (
                        isinstance(function.value, ast.Name)
                        and self.module_aliases.get(function.value.id) == "pickle"
                    )
                )
            )
            or (
                isinstance(function, ast.Name)
                and function.id in self.function_aliases
                and self.function_aliases[function.id][0] == "pickle"
                and self.function_aliases[function.id][1] in {"load", "loads"}
            )
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
            "Checks cover selected Python AST patterns only: dynamic code execution, shell command APIs, unsafe YAML loading, pickle deserialization, explicit TLS certificate-verification disabling, obvious dynamic SQL string construction, and selected known credential formats in string literals.",
            "The analyzer does not perform taint analysis, data-flow analysis, import alias resolution, or prove that SQL interpolation values are attacker-controlled.",
            "pickle findings are heuristic because exploitability depends on the trust boundary of the input.",
            "Credential checks recognize selected token/key formats only; they do not detect arbitrary passwords, perform entropy analysis, or validate whether a credential is active. The analyzer does not inspect non-Python code, dependencies, runtime configuration, or deployed environments.",
            "No project code is imported or executed and no files are modified.",
        ],
    }
