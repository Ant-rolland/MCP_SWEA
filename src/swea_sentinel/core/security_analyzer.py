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
CONTEXTUAL_SECRET_PATTERNS = (
    re.compile(
        r"""(?im)\b(?:aws_secret_access_key|aws_secret_key)\b["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?"""
    ),
    re.compile(
        r"""(?im)\b(?:api[_-]?key|access[_-]?token|client[_-]?secret|secret[_-]?key)\b["']?\s*[:=]\s*["']?(?=[A-Za-z0-9_./+=-]{24,}["']?)(?=[A-Za-z0-9_./+=-]*[A-Z])(?=[A-Za-z0-9_./+=-]*[a-z])(?=[A-Za-z0-9_./+=-]*[0-9])[A-Za-z0-9_./+=-]{24,}["']?"""
    ),
)

SECRET_PATTERNS = (
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\bdop_v1_[a-f0-9]{64}\b"),
    re.compile(r"\bxapp-1-[0-9A-Z-]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b"),
    re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
    re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"),
    re.compile(r"\bpypi-[A-Za-z0-9_-]{50,}\b"),
    re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b"),
    re.compile(r"\bsk-proj-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bsk-ant-api\d{2}-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bhf_[A-Za-z0-9]{30,}\b"),
    re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"
    ),
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


def _call_label(node: ast.expr) -> str:
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return "call"


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


def _collect_scope_import_aliases(
    scope: ast.AST,
    inherited: tuple[dict[str, str], dict[str, tuple[str, str]]],
) -> tuple[dict[str, str], dict[str, tuple[str, str]]]:
    """Resolve imports in one lexical scope without leaking local bindings outward."""
    module_aliases = dict(inherited[0])
    function_aliases = dict(inherited[1])
    ambiguous_names: set[str] = set()
    rebound_names: set[str] = set()
    scope_types = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)

    def visit_current_scope(node: ast.AST) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, scope_types):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    rebound_names.add(child.name)
                continue
            if isinstance(child, ast.Import):
                for item in child.names:
                    bound_name = item.asname or item.name.split(".")[0]
                    resolved_module = (
                        item.name if item.asname else item.name.split(".")[0]
                    )
                    previous_module = module_aliases.get(bound_name)
                    if previous_module is not None and previous_module != resolved_module:
                        ambiguous_names.add(bound_name)
                    module_aliases[bound_name] = resolved_module
            elif isinstance(child, ast.ImportFrom) and child.module:
                for item in child.names:
                    if item.name == "*":
                        continue
                    bound_name = item.asname or item.name
                    resolved = (child.module, item.name)
                    previous_function = function_aliases.get(bound_name)
                    if previous_function is not None and previous_function != resolved:
                        ambiguous_names.add(bound_name)
                    function_aliases[bound_name] = resolved
            elif isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store):
                rebound_names.add(child.id)
            elif isinstance(child, ast.arg):
                rebound_names.add(child.arg)
            elif isinstance(child, (ast.Global, ast.Nonlocal)):
                rebound_names.update(child.names)
            visit_current_scope(child)

    visit_current_scope(scope)
    for name in ambiguous_names | rebound_names:
        module_aliases.pop(name, None)
        function_aliases.pop(name, None)
    return module_aliases, function_aliases


def _collect_import_aliases(
    tree: ast.Module,
) -> dict[int, tuple[dict[str, str], dict[str, tuple[str, str]]]]:
    """Build conservative import aliases per lexical scope, including nested functions."""
    scopes: dict[int, tuple[dict[str, str], dict[str, tuple[str, str]]]] = {}
    scope_types = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)

    def build_scope(
        scope: ast.AST,
        inherited: tuple[dict[str, str], dict[str, tuple[str, str]]],
    ) -> None:
        current = _collect_scope_import_aliases(scope, inherited)
        scopes[id(scope)] = current
        # Python class namespaces are not lexical parents of methods. A method
        # resolves names through the enclosing lexical scope, not class locals.
        child_parent = inherited if isinstance(scope, ast.ClassDef) else current

        def find_nested(node: ast.AST) -> None:
            for child in ast.iter_child_nodes(node):
                if isinstance(child, scope_types):
                    build_scope(child, child_parent)
                else:
                    find_nested(child)

        find_nested(scope)

    build_scope(tree, ({}, {}))
    return scopes


def _resolved_attribute(
    node: ast.expr,
    owner: str,
    attribute: str,
    module_aliases: dict[str, str],
) -> bool:
    if not isinstance(node, ast.Attribute) or node.attr != attribute:
        return False
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
    if (
        isinstance(node, ast.Attribute)
        and node.attr in {"SafeLoader", "CSafeLoader"}
        and isinstance(node.value, ast.Name)
        and module_aliases.get(node.value.id) == "yaml"
    ):
        return True
    return (
        isinstance(node, ast.Name)
        and function_aliases.get(node.id) in {
            ("yaml", "SafeLoader"), ("yaml", "CSafeLoader")
        }
    )


class _SecurityVisitor(ast.NodeVisitor):
    def __init__(
        self,
        path: str,
        scope_aliases: dict[
            int, tuple[dict[str, str], dict[str, tuple[str, str]]]
        ],
        root_scope: ast.Module,
    ) -> None:
        self.path = path
        self.scope_aliases = scope_aliases
        self.module_aliases, self.function_aliases = scope_aliases[id(root_scope)]
        self.findings: list[dict[str, Any]] = []

    def _visit_scope_body(self, scope: ast.AST, body: list[ast.stmt]) -> None:
        previous = (self.module_aliases, self.function_aliases)
        self.module_aliases, self.function_aliases = self.scope_aliases.get(
            id(scope), previous
        )
        for statement in body:
            self.visit(statement)
        self.module_aliases, self.function_aliases = previous

    def _visit_function_scope(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> None:
        for decorator in node.decorator_list:
            self.visit(decorator)
        for default in [*node.args.defaults, *node.args.kw_defaults]:
            if default is not None:
                self.visit(default)
        for argument in [
            *node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs
        ]:
            if argument.annotation is not None:
                self.visit(argument.annotation)
        if node.args.vararg and node.args.vararg.annotation is not None:
            self.visit(node.args.vararg.annotation)
        if node.args.kwarg and node.args.kwarg.annotation is not None:
            self.visit(node.args.kwarg.annotation)
        if node.returns is not None:
            self.visit(node.returns)
        self._visit_scope_body(node, node.body)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function_scope(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function_scope(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for decorator in node.decorator_list:
            self.visit(decorator)
        for base in node.bases:
            self.visit(base)
        for keyword in node.keywords:
            self.visit(keyword.value)
        self._visit_scope_body(node, node.body)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        for default in [*node.args.defaults, *node.args.kw_defaults]:
            if default is not None:
                self.visit(default)
        previous = (self.module_aliases, self.function_aliases)
        self.module_aliases, self.function_aliases = self.scope_aliases.get(
            id(node), previous
        )
        self.visit(node.body)
        self.module_aliases, self.function_aliases = previous

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

    @staticmethod
    def _assignment_names(target: ast.expr) -> set[str]:
        if isinstance(target, ast.Name):
            return {target.id.casefold()}
        if isinstance(target, ast.Attribute):
            return {target.attr.casefold()}
        if isinstance(target, (ast.Tuple, ast.List)):
            return {
                name
                for element in target.elts
                for name in _SecurityVisitor._assignment_names(element)
            }
        return set()

    def _check_contextual_aws_secret(
        self, node: ast.AST, targets: list[ast.expr], value: ast.expr
    ) -> None:
        names = {
            name
            for target in targets
            for name in self._assignment_names(target)
        }
        if not names.intersection({"aws_secret_access_key", "aws_secret_key"}):
            return
        if not (
            isinstance(value, ast.Constant)
            and isinstance(value.value, str)
            and re.fullmatch(r"[A-Za-z0-9/+=]{40}", value.value)
        ):
            return
        self._add(
            code="PYTHON_HARDCODED_CREDENTIAL",
            severity="high",
            confidence="HIGH_CONFIDENCE",
            node=node,
            message=(
                "A 40-character AWS secret access key is assigned to a "
                "credential-named variable; the value is intentionally redacted."
            ),
            recommendation=(
                "Remove the key from source, load it from a secret manager or "
                "protected environment, and rotate it if it was real."
            ),
        )

    def _check_contextual_secret(
        self, node: ast.AST, targets: list[ast.expr], value: ast.expr
    ) -> None:
        names = {
            name
            for target in targets
            for name in self._assignment_names(target)
        }
        credential_names = {
            "api_key", "apikey", "access_token", "accesstoken",
            "client_secret", "clientsecret", "secret_key", "secretkey",
        }
        if not any(
            name in credential_names
            or name.endswith((
                "_api_key", "_apikey", "_access_token", "_accesstoken",
                "_client_secret", "_secret_key",
            ))
            for name in names
        ):
            return
        if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
            return
        candidate = value.value
        if len(candidate) < 24 or any(
            pattern.search(candidate) for pattern in SECRET_PATTERNS
        ):
            return
        character_classes = sum((
            any(char.islower() for char in candidate),
            any(char.isupper() for char in candidate),
            any(char.isdigit() for char in candidate),
            any(char in "_./+=-" for char in candidate),
        ))
        if character_classes < 3:
            return
        self._add(
            code="PYTHON_HARDCODED_CREDENTIAL",
            severity="high",
            confidence="MEDIUM_CONFIDENCE",
            node=node,
            message=(
                "A long mixed-character value is assigned to a credential-named "
                "variable; the value is intentionally redacted."
            ),
            recommendation=(
                "Verify whether the value is a live credential; if so, remove it "
                "from source, rotate it, and use a secret manager or protected environment."
            ),
        )

    def visit_Assign(self, node: ast.Assign) -> None:
        self._check_contextual_aws_secret(node, node.targets, node.value)
        self._check_contextual_secret(node, node.targets, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self._check_contextual_aws_secret(node, [node.target], node.value)
            self._check_contextual_secret(node, [node.target], node.value)
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
                isinstance(function.value, ast.Name)
                and self.module_aliases.get(function.value.id) == "subprocess"
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
                message=f"subprocess.{_call_label(function)} is called with shell=True.",
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
                    self.module_aliases.get(function.value.id) in {"requests", "httpx"}
                )
            )
            or (
                isinstance(function, ast.Name)
                and function.id in self.function_aliases
                and self.function_aliases[function.id][0] in {"requests", "httpx"}
            )
        ) and _literal_false(_keyword(node, "verify")):
            self._add(
                code="PYTHON_TLS_CERTIFICATE_VERIFICATION_DISABLED",
                severity="high",
                confidence="HIGH_CONFIDENCE",
                node=node,
                message=(
                    f"{_call_label(function)} is called with verify=False, "
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
                    isinstance(function.value, ast.Name)
                    and self.module_aliases.get(function.value.id) == "pickle"
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
                    f"pickle.{_call_label(function)} deserializes Python objects; untrusted "
                    "pickle data can execute code."
                ),
                recommendation=(
                    "Never deserialize untrusted pickle data; prefer a data-only format "
                    "such as JSON when possible."
                ),
            )
        self.generic_visit(node)


SECRET_SCAN_SUFFIXES = {
    ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf",
    ".properties", ".tf", ".tfvars", ".sh", ".ps1", ".bat", ".cmd",
    ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".go", ".rs",
    ".java", ".cs", ".php", ".xml", ".gradle", ".config", ".txt",
    ".md", ".pem", ".key",
}


def _scan_project_secret_formats(
    root: Path,
    settings: ProjectIndexSettings,
    started: float,
) -> dict[str, Any]:
    """Scan bounded text/config files for exact known token formats without returning values."""
    excluded = IGNORED_DIRS | set(settings.excluded_directories)
    findings: list[dict[str, Any]] = []
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
            is_env_file = filename == ".env" or filename.startswith(".env.")
            if (
                path.is_symlink()
                or path.suffix.lower() == ".py"
                or not (is_env_file or path.suffix.lower() in SECRET_SCAN_SUFFIXES)
            ):
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
                text = raw.decode("utf-8-sig")
            except (OSError, UnicodeError, ValueError):
                continue

            files_scanned += 1
            bytes_scanned += len(raw)
            relative = path.relative_to(root).as_posix()
            matched = False
            seen_lines: set[int] = set()
            for pattern in (*SECRET_PATTERNS, *CONTEXTUAL_SECRET_PATTERNS):
                for match in pattern.finditer(text):
                    line_number = text.count("\n", 0, match.start()) + 1
                    marker = line_number
                    if marker in seen_lines:
                        continue
                    seen_lines.add(marker)
                    matched = True
                    findings.append({
                        "code": "HARDCODED_CREDENTIAL_FORMAT",
                        "severity": "high",
                        "confidence": "HIGH_CONFIDENCE",
                        "path": relative,
                        "line": line_number,
                        "message": "A known credential/token format was detected; the matched value is redacted.",
                        "recommendation": "Move the credential to a secret manager or protected environment variable, rotate it if exposed, and review access logs.",
                    })
            if matched:
                file_hashes[relative] = hashlib.sha256(raw).hexdigest()
        if truncated_reason:
            break

    findings.sort(key=lambda item: (item["path"], item["line"], item["code"]))
    return {
        "analysis_level": "bounded_text_credential_formats",
        "files_scanned": files_scanned,
        "bytes_scanned": bytes_scanned,
        "finding_count": len(findings),
        "findings": findings,
        "file_hashes": file_hashes,
        "truncated": truncated_reason is not None,
        "truncated_reason": truncated_reason,
        "limitations": [
            "Only selected known token/key formats are recognized; arbitrary passwords, custom secrets, and entropy-based candidates are not detected.",
            "Only bounded UTF-8 text/config files are scanned. Binary credential stores, dependency directories, runtime environment values, and deployed services are not inspected.",
            "Matched credential values are never returned or persisted; only path, line, pattern category, and SHA-256 evidence are retained.",
        ],
    }


def analyze_python_security(
    root: Path, settings: ProjectIndexSettings
) -> dict[str, Any]:
    """Inspect Python AST patterns and bounded text files for selected security risks."""
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

            scope_aliases = _collect_import_aliases(tree)
            visitor = _SecurityVisitor(relative, scope_aliases, tree)
            visitor.visit(tree)
            findings.extend(visitor.findings)
        if truncated_reason:
            break

    secret_scan = _scan_project_secret_formats(root, settings, started)
    findings.extend(secret_scan["findings"])
    file_hashes.update(secret_scan["file_hashes"])
    findings.sort(key=lambda item: (
        item["path"], item["line"], item["code"], item["message"]
    ))
    combined_truncated_reason = truncated_reason or secret_scan["truncated_reason"]
    return {
        "analysis_level": "static_project_security_patterns",
        "files_scanned": files_scanned,
        "bytes_scanned": bytes_scanned,
        "finding_count": len(findings),
        "findings": findings,
        "parse_errors": parse_errors,
        "secret_scan": secret_scan,
        "truncated": combined_truncated_reason is not None,
        "truncated_reason": combined_truncated_reason,
        "duration_ms": max(0, int((time.monotonic() - started) * 1000)),
        "file_hashes": file_hashes,
        "limitations": [
            "Python AST checks cover selected dynamic code execution, shell command APIs, unsafe YAML loading, pickle deserialization, explicit TLS certificate-verification disabling, and obvious dynamic SQL construction patterns.",
            "Imported API aliases are resolved conservatively within lexical scopes; aliases rebound or shadowed in a scope are excluded. The analyzer does not perform taint/data-flow analysis or prove that SQL interpolation values are attacker-controlled.",
            "Known credential formats are also scanned in bounded UTF-8 text/config files; binary files, arbitrary passwords, custom secrets, runtime environment values, dependency packages, and deployed services are not inspected.",
            "Credential matches are never returned or persisted; evidence contains only source paths, line numbers, and SHA-256 hashes.",
            "pickle findings are heuristic because exploitability depends on the trust boundary of the input.",
            "No project code is imported or executed and no files are modified.",
        ],
    }
