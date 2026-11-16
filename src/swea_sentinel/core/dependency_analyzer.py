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
MAX_LOCKED_PACKAGES = 10_000
MAX_LOCKED_EDGES = 20_000
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


def _npm_package_name(install_path: str, metadata: dict[str, Any]) -> str | None:
    declared = metadata.get("name")
    if isinstance(declared, str) and declared:
        return declared
    parts = install_path.split("/")
    for index in range(len(parts) - 1, -1, -1):
        if parts[index] == "node_modules" and index + 1 < len(parts):
            if parts[index + 1].startswith("@") and index + 2 < len(parts):
                return parts[index + 1] + "/" + parts[index + 2]
            return parts[index + 1]
    return None


def _parse_npm_lockfile(content: bytes) -> dict[str, Any]:
    """Read npm lockfile v1-v3 package/version metadata and direct lockfile edges."""
    data = json.loads(content.decode("utf-8-sig"))
    if not isinstance(data, dict):
        raise ValueError("npm lockfile root must be an object")
    lock_version = data.get("lockfileVersion", 1)
    if not isinstance(lock_version, int) or lock_version not in {1, 2, 3}:
        raise ValueError("unsupported npm lockfile version")
    packages: list[dict[str, str]] = []
    edges: list[dict[str, str]] = []
    if lock_version >= 2 and isinstance(data.get("packages"), dict):
        package_map = data["packages"]
        names_by_path: dict[str, str] = {}
        for install_path, metadata in sorted(package_map.items()):
            if not install_path or not isinstance(metadata, dict):
                continue
            name = _npm_package_name(str(install_path), metadata)
            version = metadata.get("version")
            if not name or not isinstance(version, str):
                continue
            names_by_path[str(install_path)] = name
            packages.append({"name": name, "version": version, "install_path": str(install_path)})
        for install_path, metadata in sorted(package_map.items()):
            if not install_path or not isinstance(metadata, dict):
                continue
            dependencies = metadata.get("dependencies", {})
            if not isinstance(dependencies, dict):
                continue
            source_name = names_by_path.get(str(install_path))
            if not source_name:
                continue
            for target_name in sorted(dependencies):
                edges.append({"source": source_name, "target": str(target_name),
                              "source_install_path": str(install_path)})
    else:
        def visit_legacy(dependencies: Any, parent_path: str = "") -> None:
            if not isinstance(dependencies, dict):
                return
            for name, metadata in sorted(dependencies.items()):
                if not isinstance(metadata, dict):
                    continue
                version = metadata.get("version")
                install_path = (parent_path + "/node_modules/" + str(name)) if parent_path else ("node_modules/" + str(name))
                if isinstance(version, str):
                    packages.append({"name": str(name), "version": version, "install_path": install_path})
                child_dependencies = metadata.get("dependencies", {})
                if isinstance(child_dependencies, dict):
                    for child_name in sorted(child_dependencies):
                        edges.append({"source": str(name), "target": str(child_name),
                                      "source_install_path": install_path})
                visit_legacy(child_dependencies, install_path)
        visit_legacy(data.get("dependencies", {}))
    return {"lockfile_version": lock_version, "locked_packages": packages,
            "locked_package_count": len(packages), "locked_dependency_edges": edges,
            "locked_dependency_edge_count": len(edges)}

def _pnpm_package_name_version(package_key: str) -> tuple[str, str] | None:
    """Split pnpm package snapshot keys, including scoped names and peer suffixes."""
    key = package_key.lstrip("/")
    if key.startswith("@"):
        slash = key.find("/")
        separator = key.find("@", slash + 1) if slash >= 0 else -1
        if separator < 0 and slash >= 0:
            legacy_parts = key.split("/")
            if len(legacy_parts) == 3 and legacy_parts[2]:
                return key.split("/")[0] + "/" + legacy_parts[1], legacy_parts[2]
    else:
        separator = key.find("@")
        if separator < 0 and key.count("/") == 1:
            legacy_parts = key.split("/")
            if len(legacy_parts) == 2 and legacy_parts[1]:
                return legacy_parts[0], legacy_parts[1]
    if separator <= 0:
        return None
    name = key[:separator]
    version = key[separator + 1:].split("(", 1)[0]
    return (name, version) if name and version else None


def _parse_pnpm_lockfile(content: bytes) -> dict[str, Any]:
    """Parse pnpm v5-v9 package/snapshot records without resolving external references."""
    import yaml
    data = yaml.safe_load(content.decode("utf-8-sig"))
    if not isinstance(data, dict):
        raise ValueError("pnpm lockfile root must be a mapping")
    lock_version = str(data.get("lockfileVersion", ""))
    if not re.match(r"^[0-9]+(?:\.[0-9]+)?$", lock_version):
        raise ValueError("unsupported pnpm lockfile version")
    package_map = data.get("packages", {})
    snapshots = data.get("snapshots", {})
    if not isinstance(package_map, dict) or not isinstance(snapshots, dict):
        raise ValueError("pnpm package and snapshot sections must be mappings")
    records: dict[str, dict[str, str]] = {}
    for key, metadata in package_map.items():
        parsed = _pnpm_package_name_version(str(key))
        if parsed is None:
            continue
        name, version = parsed
        if isinstance(metadata, dict):
            version = str(metadata.get("version") or version)
        records[str(key)] = {"name": name, "version": version}
    packages = [{"name": item["name"], "version": item["version"], "install_path": key}
                for key, item in sorted(records.items())]
    edges: list[dict[str, str]] = []
    edge_source = snapshots if snapshots else package_map
    for key, metadata in sorted(edge_source.items(), key=lambda item: str(item[0])):
        if not isinstance(metadata, dict):
            continue
        source = records.get(str(key))
        if source is None:
            parsed = _pnpm_package_name_version(str(key))
            if parsed is None:
                continue
            source = {"name": parsed[0], "version": parsed[1]}
        for section in ("dependencies", "optionalDependencies"):
            dependencies = metadata.get(section, {})
            if isinstance(dependencies, dict):
                for target_name in sorted(dependencies):
                    edges.append({"source": source["name"], "target": str(target_name),
                                  "source_install_path": str(key)})
    return {"lockfile_version": lock_version, "locked_packages": packages,
            "locked_package_count": len(packages), "locked_dependency_edges": edges,
            "locked_dependency_edge_count": len(edges)}


def _parse_yarn_classic_lockfile(text: str) -> dict[str, Any]:
    packages: list[dict[str, str]] = []
    edges: list[dict[str, str]] = []
    selectors: list[str] = []
    version: str | None = None
    dependencies: list[str] = []
    in_dependencies = False

    def flush() -> None:
        if not version:
            return
        for selector in selectors:
            value = selector.strip().strip(chr(34)).strip(chr(39))
            if value.startswith('@'):
                slash = value.find('/')
                marker = value.find('@', slash + 1) if slash >= 0 else -1
            else:
                marker = value.find('@')
            if marker <= 0:
                continue
            name = value[:marker]
            packages.append({'name': name, 'version': version, 'install_path': selector.strip()})
            for target in dependencies:
                edges.append({'source': name, 'target': target, 'source_install_path': selector.strip()})

    for line in text.splitlines():
        if line and not line[0].isspace() and line.rstrip().endswith(':'):
            flush()
            selectors = [part.strip() for part in line.rstrip()[:-1].split(',')]
            version = None
            dependencies = []
            in_dependencies = False
            continue
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        if stripped.startswith('version '):
            version = stripped.split(None, 1)[1].strip(chr(34)).strip(chr(39))
            in_dependencies = False
        elif stripped in {'dependencies:', 'optionalDependencies:'}:
            in_dependencies = True
        elif in_dependencies and line.startswith('    '):
            target = stripped.split(None, 1)[0].rstrip(':').strip(chr(34)).strip(chr(39))
            if target and target not in dependencies:
                dependencies.append(target)
        elif line.startswith('  ') and not line.startswith('    '):
            in_dependencies = False
    flush()
    return {'lockfile_version': 'classic', 'locked_packages': packages, 'locked_package_count': len(packages), 'locked_dependency_edges': edges, 'locked_dependency_edge_count': len(edges)}


def _parse_yarn_lockfile(content: bytes) -> dict[str, Any]:
    import yaml
    text = content.decode('utf-8-sig')
    if '__metadata:' not in text:
        return _parse_yarn_classic_lockfile(text)
    data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise ValueError('Yarn lockfile root must be a mapping')
    metadata = data.get('__metadata', {})
    version = str(metadata.get('version', 'classic')) if isinstance(metadata, dict) else 'classic'
    packages: list[dict[str, str]] = []
    edges: list[dict[str, str]] = []
    for descriptor, record in sorted(data.items()):
        if descriptor == '__metadata' or not isinstance(record, dict):
            continue
        value = str(descriptor).strip(chr(34)).strip(chr(39))
        if value.startswith('@'):
            slash = value.find('/')
            marker = value.find('@', slash + 1) if slash >= 0 else -1
        else:
            marker = value.find('@')
        name = value[:marker] if marker > 0 else None
        locked_version = record.get('version')
        if not name or not isinstance(locked_version, str):
            continue
        packages.append({'name': name, 'version': locked_version, 'install_path': str(descriptor)})
        for section in ('dependencies', 'optionalDependencies'):
            deps = record.get(section, {})
            if isinstance(deps, dict):
                for target in sorted(deps):
                    edges.append({'source': name, 'target': str(target), 'source_install_path': str(descriptor)})
    return {'lockfile_version': version, 'locked_packages': packages, 'locked_package_count': len(packages), 'locked_dependency_edges': edges, 'locked_dependency_edge_count': len(edges)}


def _parse_python_lockfile(path: Path, content: bytes) -> dict[str, Any]:
    packages: list[dict[str, str]] = []
    edges: list[dict[str, str]] = []
    if path.name == 'poetry.lock':
        data = tomllib.loads(content.decode('utf-8-sig'))
        records = data.get('package', [])
        if not isinstance(records, list):
            raise ValueError('Poetry package section must be an array')
        for record in records:
            if not isinstance(record, dict):
                continue
            name, version = record.get('name'), record.get('version')
            if not isinstance(name, str) or not isinstance(version, str):
                continue
            install_path = name + '@' + version
            packages.append({'name': name, 'version': version, 'install_path': install_path})
            deps = record.get('dependencies', {})
            if isinstance(deps, dict):
                for target in sorted(deps):
                    edges.append({'source': name, 'target': str(target), 'source_install_path': install_path})
    else:
        data = json.loads(content.decode('utf-8-sig'))
        if not isinstance(data, dict):
            raise ValueError('Pipfile.lock root must be an object')
        for section in ('default', 'develop'):
            records = data.get(section, {})
            if not isinstance(records, dict):
                continue
            for name, record in sorted(records.items()):
                if not isinstance(record, dict):
                    continue
                version = record.get('version', 'unknown')
                version = str(version).lstrip('=')
                install_path = str(name) + '@' + version
                packages.append({'name': str(name), 'version': version, 'install_path': install_path})
                deps = record.get('dependencies', {})
                if isinstance(deps, dict):
                    for target in sorted(deps):
                        edges.append({'source': str(name), 'target': str(target), 'source_install_path': install_path})
    return {'lockfile_version': 'poetry' if path.name == 'poetry.lock' else 'pipfile',
            'locked_packages': packages, 'locked_package_count': len(packages),
            'locked_dependency_edges': edges, 'locked_dependency_edge_count': len(edges)}


def _parse_cargo_lockfile(content: bytes) -> dict[str, Any]:
    data = tomllib.loads(content.decode('utf-8-sig'))
    records = data.get('package', [])
    if not isinstance(records, list):
        raise ValueError('Cargo package section must be an array')
    packages: list[dict[str, str]] = []
    edges: list[dict[str, str]] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        name, version = record.get('name'), record.get('version')
        if not isinstance(name, str) or not isinstance(version, str):
            continue
        install_path = name + '@' + version
        packages.append({'name': name, 'version': version, 'install_path': install_path})
        deps = record.get('dependencies', [])
        if isinstance(deps, list):
            for dependency in deps:
                parts = str(dependency).split()
                if parts:
                    edges.append({'source': name, 'target': parts[0], 'source_install_path': install_path})
    return {'lockfile_version': str(data.get('version', 'unknown')), 'locked_packages': packages,
            'locked_package_count': len(packages), 'locked_dependency_edges': edges,
            'locked_dependency_edge_count': len(edges)}


def _parse_go_mod(content: bytes) -> dict[str, Any]:
    """Parse Go module requirements as declarations, not as a resolved lock graph."""
    module_path: str | None = None
    requirements: list[dict[str, str | bool]] = []
    in_require = False
    for raw_line in content.decode("utf-8-sig").splitlines():
        indirect_marker = "// indirect" in raw_line
        line = raw_line.split("//", 1)[0].strip()
        if not line:
            continue
        if line.startswith("module "):
            parts = line.split()
            if len(parts) >= 2:
                module_path = parts[1]
            continue
        if line == "require (":
            in_require = True
            continue
        if in_require and line == ")":
            in_require = False
            continue
        if line.startswith("require "):
            parts = line.split()
            if len(parts) >= 3:
                requirements.append({
                    "module": parts[1], "version": parts[2],
                    "indirect": indirect_marker,
                })
        elif in_require:
            parts = line.split()
            if len(parts) >= 2:
                requirements.append({
                    "module": parts[0], "version": parts[1],
                    "indirect": indirect_marker,
                })
    edges = [
        {
            "source": module_path or "go.mod",
            "target": str(item["module"]),
            "requested_version": str(item["version"]),
            "indirect": bool(item["indirect"]),
            "source_manifest": "go.mod",
        }
        for item in requirements
    ]
    return {
        "module_path": module_path,
        "declared_dependency_edges": edges,
        "declared_dependency_edge_count": len(edges),
    }


def _parse_go_sum(content: bytes) -> dict[str, Any]:
    """Read checksum presence by module/version without treating go.sum as a lock graph."""
    packages: dict[tuple[str, str], dict[str, str]] = {}
    checksum_kinds: dict[tuple[str, str], set[str]] = {}
    for line in content.decode("utf-8-sig").splitlines():
        parts = line.split()
        if len(parts) < 3 or parts[0].startswith("//"):
            continue
        module, version_token = parts[0], parts[1]
        checksum_kind = "go_mod" if version_token.endswith("/go.mod") else "module"
        version = version_token[:-7] if checksum_kind == "go_mod" else version_token
        key = (module, version)
        packages[key] = {
            "name": module, "version": version, "install_path": module + "@" + version
        }
        checksum_kinds.setdefault(key, set()).add(checksum_kind)
    records = [packages[key] for key in sorted(packages)]
    checksum_records = [
        {
            "module": module,
            "version": version,
            "module_checksum": "module" in checksum_kinds[(module, version)],
            "go_mod_checksum": "go_mod" in checksum_kinds[(module, version)],
        }
        for module, version in sorted(checksum_kinds)
    ]
    return {
        "lockfile_version": "go.sum",
        "locked_packages": records,
        "locked_package_count": len(records),
        "locked_dependency_edges": [],
        "locked_dependency_edge_count": 0,
        "checksum_records": checksum_records,
        "checksum_record_count": len(checksum_records),
    }


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
                lockfile_details: dict[str, Any] = {}
                parse_error: str | None = None
                try:
                    if kind == "manifest":
                        dependencies = _dependency_names(path, ecosystem, content)
                        if ecosystem == "go" and path.name == "go.mod":
                            lockfile_details = _parse_go_mod(content)
                    elif ecosystem == "node" and path.name in {"package-lock.json", "npm-shrinkwrap.json"}:
                        lockfile_details = _parse_npm_lockfile(content)
                    elif ecosystem == "node" and path.name == "pnpm-lock.yaml":
                        lockfile_details = _parse_pnpm_lockfile(content)
                    elif ecosystem == "node" and path.name == "yarn.lock":
                        lockfile_details = _parse_yarn_lockfile(content)
                    elif ecosystem == "python" and path.name in {"poetry.lock", "Pipfile.lock"}:
                        lockfile_details = _parse_python_lockfile(path, content)
                    elif ecosystem == "rust" and path.name == "Cargo.lock":
                        lockfile_details = _parse_cargo_lockfile(content)
                    elif ecosystem == "go" and path.name == "go.sum":
                        lockfile_details = _parse_go_sum(content)
                    if lockfile_details:
                        packages = lockfile_details.get("locked_packages", [])
                        edges = lockfile_details.get("locked_dependency_edges", [])
                        declared_edges = lockfile_details.get("declared_dependency_edges", [])
                        lockfile_truncated = (
                            len(packages) > MAX_LOCKED_PACKAGES
                            or len(edges) > MAX_LOCKED_EDGES
                            or len(declared_edges) > MAX_LOCKED_EDGES
                        )
                        lockfile_details["locked_packages"] = packages[:MAX_LOCKED_PACKAGES]
                        lockfile_details["locked_dependency_edges"] = edges[:MAX_LOCKED_EDGES]
                        lockfile_details["declared_dependency_edges"] = declared_edges[:MAX_LOCKED_EDGES]
                        lockfile_details["locked_package_count"] = len(lockfile_details["locked_packages"])
                        lockfile_details["locked_dependency_edge_count"] = len(lockfile_details["locked_dependency_edges"])
                        lockfile_details["declared_dependency_edge_count"] = len(lockfile_details["declared_dependency_edges"])
                        lockfile_details["lockfile_truncated"] = lockfile_truncated
                except (UnicodeDecodeError, ValueError, TypeError, ET.ParseError, RecursionError):
                    parse_error = "invalid_manifest" if kind == "manifest" else "invalid_lockfile"
                manifests.append({
                    "path": relative,
                    "ecosystem": ecosystem,
                    "kind": kind,
                    "sha256": digest,
                    "declared_dependency_names": dependencies,
                    "declared_dependency_count": len(dependencies),
                    **lockfile_details,
                    "parse_error": parse_error,
                })
            except OSError:
                continue
        if truncated_reason:
            break

    # Correlate go.mod requirements with sibling go.sum checksum records.
    # A checksum is evidence of a recorded module/version, not proof that Go
    # selected that version in the final module graph.
    go_sum_by_directory = {
        Path(item["path"]).parent.as_posix(): item
        for item in manifests
        if item["ecosystem"] == "go"
        and Path(item["path"]).name == "go.sum"
        and not item.get("parse_error")
    }
    for item in manifests:
        if item["ecosystem"] != "go" or Path(item["path"]).name != "go.mod":
            continue
        directory = Path(item["path"]).parent.as_posix()
        go_sum = go_sum_by_directory.get(directory)
        if go_sum is None:
            item["go_sum_path"] = None
            item["go_sum_correlations"] = []
            item["go_sum_correlation_status"] = "sibling_go_sum_not_found"
            continue
        checksum_index = {
            (record["module"], record["version"]): record
            for record in go_sum.get("checksum_records", [])
        }
        versions_by_module: dict[str, list[str]] = {}
        for module, version in checksum_index:
            versions_by_module.setdefault(module, []).append(version)
        correlations = []
        for edge in item.get("declared_dependency_edges", []):
            module = edge["target"]
            requested_version = edge["requested_version"]
            checksum = checksum_index.get((module, requested_version))
            if checksum is None:
                checksum_status = "no_exact_checksum_record"
            elif checksum["module_checksum"] and checksum["go_mod_checksum"]:
                checksum_status = "module_and_go_mod_checksums_present"
            elif checksum["module_checksum"]:
                checksum_status = "module_checksum_only"
            else:
                checksum_status = "go_mod_checksum_only"
            correlations.append({
                "module": module,
                "requested_version": requested_version,
                "indirect": edge["indirect"],
                "checksum_status": checksum_status,
                "other_checksum_versions": sorted(
                    version for version in versions_by_module.get(module, [])
                    if version != requested_version
                ),
                "selected_version_determined": False,
            })
        item["go_sum_path"] = go_sum["path"]
        item["go_sum_correlations"] = correlations
        item["go_sum_correlation_count"] = len(correlations)
        item["go_sum_correlation_status"] = "checksum_presence_only"

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
            "npm package-lock v1-v3, pnpm, and Yarn Berry lockfiles expose bounded locked package versions and dependency edges; other lockfiles are identified and hashed but not expanded.",
            "Gradle and Maven manifests are identified but dependency declarations are not yet parsed.",
            "Declared dependency names do not establish reachability, vulnerability status, or runtime usage.",
            "Go go.sum correlations show exact checksum-record presence only; they do not determine the version selected by Go's module graph.",
            "Only the listed manifest formats are recognized; custom build systems may be missed.",
        ],
    }
