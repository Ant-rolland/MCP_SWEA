"""Bounded, read-only discovery of dependency manifests across common ecosystems."""
from __future__ import annotations

import hashlib
import os
import json
import re
import time
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from swea_sentinel.config import ProjectIndexSettings

IGNORED_DIRS = {
    ".git", ".venv", "venv", "node_modules", "__pycache__", ".mypy_cache",
    ".pytest_cache", ".next", ".turbo", "dist", "build", "coverage", "target",
    "vendor", "bin", "obj",
}
MAX_MANIFESTS = 500
MAX_MANIFEST_BYTES = 1_000_000
MAX_TOTAL_BYTES = 10_000_000
MAX_SCAN_SECONDS = 5.0
PACKAGE_NAME = re.compile(r"^([A-Za-z0-9_.-]+)")


def _dependency_names(path: Path, ecosystem: str, content: bytes) -> list[str]:
    """Extract declared direct dependency names where a safe parser is available."""
    text = content.decode("utf-8-sig")
    names: set[str] = set()

    if path.name == "package.json":
        data = json.loads(text)
        if isinstance(data, dict):
            for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
                values = data.get(section, {})
                if isinstance(values, dict):
                    names.update(str(name) for name in values)
    elif path.name == "pyproject.toml":
        data = tomllib.loads(text)
        project = data.get("project", {})
        if isinstance(project, dict):
            for item in project.get("dependencies", []):
                match = PACKAGE_NAME.match(str(item))
                if match:
                    names.add(match.group(1))
            optional = project.get("optional-dependencies", {})
            if isinstance(optional, dict):
                for items in optional.values():
                    if isinstance(items, list):
                        for item in items:
                            match = PACKAGE_NAME.match(str(item))
                            if match:
                                names.add(match.group(1))
        poetry = data.get("tool", {}).get("poetry", {}) if isinstance(data.get("tool"), dict) else {}
        poetry_deps = poetry.get("dependencies", {}) if isinstance(poetry, dict) else {}
        if isinstance(poetry_deps, dict):
            names.update(str(name) for name in poetry_deps if name.lower() != "python")
    elif path.name == "Cargo.toml":
        data = tomllib.loads(text)
        for section in ("dependencies", "dev-dependencies", "build-dependencies"):
            values = data.get(section, {})
            if isinstance(values, dict):
                names.update(str(name) for name in values)
        for section in ("workspace",):
            workspace = data.get(section, {})
            shared = workspace.get("dependencies", {}) if isinstance(workspace, dict) else {}
            if isinstance(shared, dict):
                names.update(str(name) for name in shared)
    elif path.name.startswith("requirements") and path.suffix == ".txt":
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith(("#", "-", "git+", "http:", "https:")):
                continue
            match = PACKAGE_NAME.match(line)
            if match:
                names.add(match.group(1))
    elif path.name == "go.mod":
        in_require = False
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("require ("):
                in_require = True
                continue
            if in_require and stripped == ")":
                in_require = False
                continue
            if stripped.startswith("require "):
                parts = stripped.split()
                if len(parts) >= 2:
                    names.add(parts[1])
            elif in_require and stripped and not stripped.startswith("//"):
                names.add(stripped.split()[0])
    elif path.name.endswith((".csproj", ".fsproj", ".vbproj")):
        root = ET.fromstring(text)
        for element in root.iter():
            if element.tag.rsplit("}", 1)[-1] == "PackageReference":
                name = element.attrib.get("Include") or element.attrib.get("Update")
                if name:
                    names.add(name)

    return sorted(names)


def _classify(name: str) -> tuple[str, str] | None:
    if name == "package.json":
        return "node", "manifest"
    if name in {"package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock"}:
        return "node", "lockfile"
    if name == "pyproject.toml":
        return "python", "manifest"
    if name.startswith("requirements") and name.endswith(".txt"):
        return "python", "manifest"
    if name in {"Pipfile", "Pipfile.lock", "poetry.lock"}:
        return "python", "lockfile" if name.endswith(".lock") else "manifest"
    if name in {"Cargo.toml", "Cargo.lock"}:
        return "rust", "lockfile" if name.endswith(".lock") else "manifest"
    if name in {"go.mod", "go.sum"}:
        return "go", "lockfile" if name.endswith(".sum") else "manifest"
    if name == "pom.xml":
        return "java_maven", "manifest"
    if name in {"build.gradle", "build.gradle.kts"}:
        return "java_gradle", "manifest"
    if name == "libs.versions.toml":
        return "java_gradle", "catalog"
    if name.endswith((".csproj", ".fsproj", ".vbproj")):
        return "dotnet", "manifest"
    if name in {"packages.config", "Directory.Packages.props"}:
        return "dotnet", "manifest"
    return None


def analyze_dependency_manifests(
    root: Path, settings: ProjectIndexSettings | None = None
) -> dict[str, Any]:
    """Discover manifests with strict file, byte and duration limits; never execute tools."""
    limits = settings or ProjectIndexSettings()
    started = time.monotonic()
    manifests: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    total_bytes = 0
    truncated_reason: str | None = None
    excluded = IGNORED_DIRS | set(limits.excluded_directories)

    for current, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(
            name for name in dirs
            if name not in excluded and not (Path(current) / name).is_symlink()
        )
        for filename in sorted(files):
            classified = _classify(filename)
            if classified is None:
                continue
            if len(manifests) + len(errors) >= min(limits.max_files, MAX_MANIFESTS):
                truncated_reason = "maximum_manifest_count"
                break
            if time.monotonic() - started > min(limits.max_scan_seconds, MAX_SCAN_SECONDS):
                truncated_reason = "maximum_scan_duration"
                break
            path = Path(current) / filename
            if path.is_symlink():
                continue
            try:
                relative = path.relative_to(root).as_posix()
                stat = path.stat()
                if not path.is_file():
                    continue
                if stat.st_size > min(limits.max_file_bytes, MAX_MANIFEST_BYTES):
                    errors.append({"path": relative, "error": "manifest_too_large"})
                    continue
                if total_bytes + stat.st_size > min(limits.max_total_bytes, MAX_TOTAL_BYTES):
                    truncated_reason = "maximum_total_bytes"
                    break
                per_file_limit = min(limits.max_file_bytes, MAX_MANIFEST_BYTES)
                with path.open("rb") as handle:
                    content = handle.read(per_file_limit + 1)
                if len(content) > per_file_limit:
                    errors.append({"path": relative, "error": "manifest_too_large"})
                    continue
                aggregate_limit = min(limits.max_total_bytes, MAX_TOTAL_BYTES)
                if total_bytes + len(content) > aggregate_limit:
                    truncated_reason = "maximum_total_bytes"
                    break
                total_bytes += len(content)
                ecosystem, kind = classified
                digest = hashlib.sha256(content).hexdigest()
                dependencies: list[str] = []
                parse_error: str | None = None
                if kind == "manifest":
                    try:
                        dependencies = _dependency_names(path, ecosystem, content)
                    except (UnicodeDecodeError, ValueError, TypeError, ET.ParseError):
                        parse_error = "invalid_manifest"
                manifests.append({
                    "path": relative,
                    "ecosystem": ecosystem,
                    "kind": kind,
                    "sha256": digest,
                    "declared_dependency_names": dependencies,
                    "declared_dependency_count": len(dependencies),
                    "parse_error": parse_error,
                })
            except OSError:
                continue
        if truncated_reason:
            break

    return {
        "analysis_level": "static_dependency_manifest_discovery",
        "manifests": sorted(manifests, key=lambda item: item["path"]),
        "manifest_count": len(manifests),
        "declared_dependency_count": sum(item["declared_dependency_count"] for item in manifests),
        "parse_errors": errors + [
            {"path": item["path"], "error": item["parse_error"]}
            for item in manifests if item["parse_error"]
        ],
        "indexed_bytes": total_bytes,
        "truncated": truncated_reason is not None,
        "truncated_reason": truncated_reason,
        "duration_ms": max(0, int((time.monotonic() - started) * 1000)),
        "limitations": [
            "Discovery is static and does not install packages, invoke package managers, or execute project code.",
            "Lockfiles are identified and hashed but are not expanded into resolved dependency graphs.",
            "Gradle and Maven manifests are identified but dependency declarations are not yet parsed.",
            "Declared dependency names do not establish versions, reachability, vulnerability status, or runtime usage.",
            "Only the listed manifest formats are recognized; custom build systems may be missed.",
        ],
    }
