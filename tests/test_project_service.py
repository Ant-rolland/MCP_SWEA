import json

from swea_sentinel.config import ProjectIndexSettings
from swea_sentinel.core.project_service import ProjectService
from swea_sentinel.persistence.database import Database


def test_register_refresh_status_and_context(tmp_path):
    project = tmp_path / "sample"
    project.mkdir()
    (project / "main.py").write_text("print('hello')\n", encoding="utf-8")
    (project / "README.md").write_text("# sample\n", encoding="utf-8")
    (project / ".env").write_text("SHOULD_NOT_BE_READ_AS_SECRET\n", encoding="utf-8")
    (project / ".git").mkdir()
    (project / ".git" / "config").write_text("ignored", encoding="utf-8")

    service = ProjectService(Database(tmp_path / "db.sqlite"))
    registered = service.initialize(str(project))
    project_id = registered.project_id
    refreshed = service.refresh(project_id)
    assert refreshed.result["indexed_files"] == 3
    status = service.status(project_id)
    assert status.indexed_files == 3
    context = service.context(project_id)
    assert context["latest_snapshot"]["file_count"] == 3


def test_inventory_respects_file_count_bound(tmp_path):
    project = tmp_path / "bounded"
    project.mkdir()
    for index in range(3):
        (project / f"file-{index}.txt").write_text(f"content-{index}", encoding="utf-8")
    service = ProjectService(
        Database(tmp_path / "db.sqlite"),
        ProjectIndexSettings(max_files=2),
    )
    registered = service.initialize(str(project))
    result = service.refresh(registered.project_id)
    assert result.result["indexed_files"] == 2
    assert result.result["truncated"] is True
    assert result.result["truncated_reason"] == "maximum_file_count"


def test_inventory_stores_hashes_not_source_contents(tmp_path):
    project = tmp_path / "private"
    project.mkdir()
    (project / "main.py").write_text("private-marker-do-not-persist", encoding="utf-8")
    db = Database(tmp_path / "db.sqlite")
    service = ProjectService(db)
    registered = service.initialize(str(project))
    service.refresh(registered.project_id)
    with db.connect() as conn:
        manifest = conn.execute(
            "SELECT manifest_json FROM project_snapshots WHERE project_id = ?",
            (registered.project_id,),
        ).fetchone()[0]
    assert "private-marker-do-not-persist" not in manifest
    assert "sha256" in manifest


def test_initialize_rejects_non_directory(tmp_path):
    file_path = tmp_path / "file.txt"
    file_path.write_text("x")
    service = ProjectService(Database(tmp_path / "db.sqlite"))
    try:
        service.initialize(str(file_path))
    except ValueError as exc:
        assert "existing directory" in str(exc)
    else:
        raise AssertionError("Expected ValueError")


def test_unknown_project_is_rejected(tmp_path):
    service = ProjectService(Database(tmp_path / "db.sqlite"))
    try:
        service.status("not-a-project")
    except ValueError as exc:
        assert "Unknown project_id" in str(exc)
    else:
        raise AssertionError("Expected ValueError")



def test_dependency_analysis_persists_manifest_edges_and_evidence(tmp_path):
    project = tmp_path / "multi-ecosystem"
    project.mkdir()
    (project / "package.json").write_text(
        '{"dependencies":{"react":"^19"}}', encoding="utf-8"
    )
    (project / "pyproject.toml").write_text(
        '[project]\ndependencies = ["httpx>=0.27"]\n', encoding="utf-8"
    )
    db = Database(tmp_path / "db.sqlite")
    service = ProjectService(db)
    registered = service.initialize(str(project))

    result = service.analyze_dependencies(registered.project_id)

    assert result.status.value == "completed"
    assert result.result["manifest_count"] == 2
    with db.connect() as conn:
        edges = conn.execute(
            "SELECT source_path, target_name, dependency_type FROM dependencies "
            "WHERE project_id = ? ORDER BY dependency_type",
            (registered.project_id,),
        ).fetchall()
        evidence = conn.execute(
            "SELECT COUNT(*) FROM evidence WHERE project_id = ? AND kind = 'dependency_manifest'",
            (registered.project_id,),
        ).fetchone()[0]
    assert {(row["source_path"], row["target_name"], row["dependency_type"]) for row in edges} == {
        ("package.json", "react", "manifest:node"),
        ("pyproject.toml", "httpx", "manifest:python"),
    }
    assert evidence == 2



def test_dependency_analysis_persists_npm_locked_packages_and_edges(tmp_path):
    project = tmp_path / "npm-project"
    project.mkdir()
    (project / "package.json").write_text(
        '{"dependencies":{"react":"^19"}}', encoding="utf-8"
    )
    (project / "package-lock.json").write_text(
        '{"name":"npm-project","lockfileVersion":3,"packages":'
        '{"":{"dependencies":{"react":"^19"}},'
        '"node_modules/react":{"version":"19.0.0"},'
        '"node_modules/react-dom":{"version":"19.0.0","dependencies":{"react":"^19"}}}}',
        encoding="utf-8",
    )
    db = Database(tmp_path / "db.sqlite")
    service = ProjectService(db)
    registered = service.initialize(str(project))

    result = service.analyze_dependencies(registered.project_id)

    assert result.result["manifest_count"] == 2
    with db.connect() as conn:
        rows = conn.execute(
            "SELECT source_path, target_name, dependency_type FROM dependencies "
            "WHERE project_id = ? ORDER BY dependency_type, source_path, target_name",
            (registered.project_id,),
        ).fetchall()
    assert {(row["source_path"], row["target_name"], row["dependency_type"]) for row in rows} == {
        ("package.json", "react", "manifest:node"),
        ("package-lock.json#package:react@19.0.0", "package-lock.json#package:react@19.0.0", "lockfile:npm:package"),
        ("package-lock.json#package:react-dom@19.0.0", "package-lock.json#package:react-dom@19.0.0", "lockfile:npm:package"),
        ("package-lock.json#package:react-dom@19.0.0", "package-lock.json#package:react@19.0.0", "node_package_graph"),
    }



def test_dependency_analysis_persists_go_declarations_and_non_node_lockfiles(tmp_path):
    project = tmp_path / "go-project"
    project.mkdir()
    (project / "go.mod").write_text(
        "module example.com/service\n\ngo 1.23\n\n"
        "require (\n example.com/lib v1.2.3\n example.com/helper v0.8.0 // indirect\n)\n",
        encoding="utf-8",
    )
    (project / "go.sum").write_text(
        "example.com/lib v1.2.3 h1:abc=\n"
        "example.com/helper v0.8.0/go.mod h1:def=\n",
        encoding="utf-8",
    )
    db = Database(tmp_path / "db.sqlite")
    service = ProjectService(db)
    registered = service.initialize(str(project))

    result = service.analyze_dependencies(registered.project_id)

    assert result.result["manifest_count"] == 2
    with db.connect() as conn:
        rows = conn.execute(
            "SELECT source_path, target_name, dependency_type FROM dependencies "
            "WHERE project_id = ? ORDER BY dependency_type, source_path, target_name",
            (registered.project_id,),
        ).fetchall()
    stored = {(row["source_path"], row["target_name"], row["dependency_type"]) for row in rows}
    assert ("go.mod#example.com/service", "example.com/lib@v1.2.3", "manifest:go:edge") in stored
    assert ("go.mod#example.com/service", "example.com/helper@v0.8.0", "manifest:go:edge") in stored
    assert ("go.sum#package:example.com/lib@v1.2.3", "go.sum#package:example.com/lib@v1.2.3", "lockfile:go:package") in stored
    assert ("go.sum#package:example.com/helper@v0.8.0", "go.sum#package:example.com/helper@v0.8.0", "lockfile:go:package") in stored
    go_mod_report = next(
        item for item in result.result["manifests"] if item["path"] == "go.mod"
    )
    checksum_statuses = {
        (item["module"], item["requested_version"]): item["checksum_status"]
        for item in go_mod_report["go_sum_correlations"]
    }
    assert checksum_statuses[("example.com/lib", "v1.2.3")] == "module_checksum_only"
    assert checksum_statuses[("example.com/helper", "v0.8.0")] == "go_mod_checksum_only"
    assert all(
        item["selected_version_determined"] is False
        for item in go_mod_report["go_sum_correlations"]
    )


def test_dependency_analysis_persists_python_and_cargo_lockfiles(tmp_path):
    project = tmp_path / "multi-ecosystem"
    project.mkdir()
    (project / "poetry.lock").write_text(
        '[[package]]\nname = "httpx"\nversion = "0.27.2"\n', encoding="utf-8"
    )
    (project / "Cargo.lock").write_text(
        'version = 3\n\n[[package]]\nname = "serde"\nversion = "1.0.210"\n',
        encoding="utf-8",
    )
    db = Database(tmp_path / "db.sqlite")
    service = ProjectService(db)
    registered = service.initialize(str(project))

    service.analyze_dependencies(registered.project_id)

    with db.connect() as conn:
        rows = conn.execute(
            "SELECT source_path, target_name, dependency_type FROM dependencies "
            "WHERE project_id = ?",
            (registered.project_id,),
        ).fetchall()
    stored = {(row["source_path"], row["target_name"], row["dependency_type"]) for row in rows}
    assert ("poetry.lock#package:httpx@0.27.2", "poetry.lock#package:httpx@0.27.2", "lockfile:python:package") in stored
    assert ("Cargo.lock#package:serde@1.0.210", "Cargo.lock#package:serde@1.0.210", "lockfile:cargo:package") in stored



def test_blast_radius_reports_package_impacts_per_relation_without_crossing_graphs(tmp_path):
    project = tmp_path / "blast-project"
    project.mkdir()
    db = Database(tmp_path / "db.sqlite")
    service = ProjectService(db)
    registered = service.initialize(str(project))

    with db.connect() as conn:
        conn.executemany(
            "INSERT INTO dependencies(dependency_id,project_id,source_path,target_name,dependency_type) "
            "VALUES(?,?,?,?,?)",
            [
                ("dep-1", registered.project_id, "package-lock.json#node_modules/app", "shared-lib@1.0.0", "lockfile:npm:edge"),
                ("dep-2", registered.project_id, "package-lock.json#node_modules/plugin", "app@2.0.0", "lockfile:npm:edge"),
                # Same identifier in another graph layer must not create a cross-layer path.
                ("dep-3", registered.project_id, "Cargo.lock#other", "app@2.0.0", "lockfile:cargo:edge"),
            ],
        )

    result = service.check_blast_radius(registered.project_id, "shared-lib@1.0.0")

    assert result.result["analysis_level"] == "static_dependency_blast_radius"
    npm = result.result["impact_by_relation"]["lockfile:npm:edge"]
    assert npm["direct_dependents"] == ["package-lock.json#node_modules/app"]
    assert npm["impact_count"] == 1
    assert npm["transitive_dependents"] == [
        {"identifier": "package-lock.json#node_modules/app", "distance": 1},
    ]
    assert "lockfile:cargo:edge" not in result.result["impact_by_relation"]


def test_blast_radius_traverses_normalized_lockfile_package_nodes(tmp_path):
    project = tmp_path / "npm-graph"
    project.mkdir()
    (project / "package-lock.json").write_text(
        json.dumps({
            "lockfileVersion": 3,
            "packages": {
                "node_modules/app": {
                    "name": "app", "version": "1.0.0",
                    "dependencies": {"react-dom": "19.0.0"},
                },
                "node_modules/react-dom": {
                    "name": "react-dom", "version": "19.0.0",
                    "dependencies": {"react": "19.0.0"},
                },
                "node_modules/react": {"name": "react", "version": "19.0.0"},
            },
        }),
        encoding="utf-8",
    )
    db = Database(tmp_path / "db.sqlite")
    service = ProjectService(db)
    registered = service.initialize(str(project))
    service.analyze_dependencies(registered.project_id)

    result = service.check_blast_radius(
        registered.project_id,
        "package-lock.json#package:react@19.0.0",
    )
    impact = result.result["impact_by_relation"]["node_package_graph"]

    assert impact["direct_dependents"] == [
        "package-lock.json#package:react-dom@19.0.0"
    ]
    assert impact["transitive_dependents"] == [
        {"identifier": "package-lock.json#package:react-dom@19.0.0", "distance": 1},
        {"identifier": "package-lock.json#package:app@1.0.0", "distance": 2},
    ]
    assert impact["impact_count"] == 2


def test_lockfile_edges_with_ambiguous_target_versions_are_not_linked(tmp_path):
    project = tmp_path / "ambiguous-npm-graph"
    project.mkdir()
    (project / "package-lock.json").write_text(
        json.dumps({
            "lockfileVersion": 3,
            "packages": {
                "node_modules/parent": {
                    "name": "parent", "version": "1.0.0",
                    "dependencies": {"shared": "^1"},
                },
                "node_modules/shared": {"name": "shared", "version": "1.0.0"},
                "node_modules/parent/node_modules/shared": {
                    "name": "shared", "version": "2.0.0"
                },
            },
        }),
        encoding="utf-8",
    )
    db = Database(tmp_path / "db.sqlite")
    service = ProjectService(db)
    registered = service.initialize(str(project))
    service.analyze_dependencies(registered.project_id)

    with db.connect() as conn:
        edges = conn.execute(
            "SELECT COUNT(*) FROM dependencies WHERE project_id = ? "
            "AND dependency_type = 'lockfile:npm:edge'",
            (registered.project_id,),
        ).fetchone()[0]
    assert edges == 0


def test_python_imports_link_only_to_unique_normalized_locked_package(tmp_path):
    project = tmp_path / "python-package-graph"
    project.mkdir()
    (project / "main.py").write_text("import requests\n", encoding="utf-8")
    (project / "pyproject.toml").write_text(
        '[project]\nname = "sample"\nversion = "1.0.0"\ndependencies = ["Requests>=2"]\n',
        encoding="utf-8",
    )
    (project / "poetry.lock").write_text(
        """[[package]]
name = "requests"
version = "2.32.3"
[package.dependencies]
urllib3 = ">=1.21.1"

[[package]]
name = "urllib3"
version = "2.2.3"
""",
        encoding="utf-8",
    )
    database = Database(tmp_path / "python-package-graph.sqlite")
    service = ProjectService(database)
    registered = service.initialize(str(project))

    result = service.analyze_dependencies(registered.project_id)

    assert result.status.value == "completed"
    with database.connect() as conn:
        edges = conn.execute(
            "SELECT source_path, target_name, dependency_type FROM dependencies "
            "WHERE project_id = ? AND dependency_type = 'python_package_graph'",
            (registered.project_id,),
        ).fetchall()
    stored = {(row["source_path"], row["target_name"], row["dependency_type"]) for row in edges}
    assert ("main.py", "poetry.lock#package:requests@2.32.3", "python_package_graph") in stored
    assert (
        "poetry.lock#package:requests@2.32.3",
        "poetry.lock#package:urllib3@2.2.3",
        "python_package_graph",
    ) in stored

    impact = service.check_blast_radius(
        registered.project_id, "poetry.lock#package:urllib3@2.2.3"
    )
    graph = impact.result["impact_by_relation"]["python_package_graph"]
    assert "poetry.lock#package:requests@2.32.3" in graph["direct_dependents"]
    assert {
        "identifier": "main.py",
        "distance": 2,
    } in graph["transitive_dependents"]


def test_python_import_package_mapping_skips_ambiguous_locked_versions(tmp_path):
    project = tmp_path / "ambiguous-python-package-graph"
    project.mkdir()
    (project / "main.py").write_text("import requests\n", encoding="utf-8")
    (project / "poetry.lock").write_text(
        """[[package]]
name = "requests"
version = "2.31.0"

[[package]]
name = "requests"
version = "2.32.3"
""",
        encoding="utf-8",
    )
    database = Database(tmp_path / "ambiguous-python-package-graph.sqlite")
    service = ProjectService(database)
    registered = service.initialize(str(project))
    service.analyze_dependencies(registered.project_id)

    with database.connect() as conn:
        source_edges = conn.execute(
            "SELECT COUNT(*) FROM dependencies WHERE project_id = ? "
            "AND dependency_type = 'python_package_graph' AND source_path = 'main.py'",
            (registered.project_id,),
        ).fetchone()[0]
    assert source_edges == 0


def test_node_source_imports_link_to_unique_locked_packages_and_blast_radius(tmp_path):
    project = tmp_path / "node-source-graph"
    project.mkdir()
    (project / "package.json").write_text(
        '{"dependencies":{"react":"^18","@scope/pkg":"^1","lodash":"^4"}}',
        encoding="utf-8",
    )
    (project / "package-lock.json").write_text(
        json.dumps({
            "name": "node-source-graph",
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "name": "node-source-graph",
                    "version": "1.0.0",
                    "dependencies": {
                        "react": "^18",
                        "@scope/pkg": "^1",
                        "lodash": "^4",
                    },
                },
                "node_modules/react": {"version": "18.3.1"},
                "node_modules/@scope/pkg": {
                    "version": "1.2.3",
                    "dependencies": {"react": "^18"},
                },
                "node_modules/lodash": {"version": "4.17.21"},
            },
        }),
        encoding="utf-8",
    )
    (project / "app.ts").write_text(
        "import React from 'react';\n"
        "const lodash = require('lodash');\n",
        encoding="utf-8",
    )
    (project / "service.ts").write_text(
        "import { helper } from '@scope/pkg/subpath';\n",
        encoding="utf-8",
    )
    db = Database(tmp_path / "db.sqlite")
    service = ProjectService(db)
    registered = service.initialize(str(project))

    result = service.analyze_dependencies(registered.project_id)

    assert result.result["node_source_imports"]["edge_count"] == 3
    with db.connect() as conn:
        rows = conn.execute(
            "SELECT source_path, target_name, dependency_type FROM dependencies "
            "WHERE project_id = ? AND dependency_type = 'node_package_graph'",
            (registered.project_id,),
        ).fetchall()
    stored = {
        (row["source_path"], row["target_name"], row["dependency_type"])
        for row in rows
    }
    assert stored == {
        ("app.ts", "package-lock.json#package:react@18.3.1", "node_package_graph"),
        ("service.ts", "package-lock.json#package:@scope/pkg@1.2.3", "node_package_graph"),
        ("app.ts", "package-lock.json#package:lodash@4.17.21", "node_package_graph"),
        (
            "package-lock.json#package:@scope/pkg@1.2.3",
            "package-lock.json#package:react@18.3.1",
            "node_package_graph",
        ),
    }

    impact = service.check_blast_radius(
        registered.project_id, "package-lock.json#package:react@18.3.1"
    )
    node_impact = impact.result["impact_by_relation"]["node_package_graph"]
    assert set(node_impact["direct_dependents"]) == {
        "app.ts",
        "package-lock.json#package:@scope/pkg@1.2.3",
    }
    assert "service.ts" in {
        item["identifier"] for item in node_impact["transitive_dependents"]
    }

    service.analyze_dependencies(registered.project_id)
    with db.connect() as conn:
        repeated_count = conn.execute(
            "SELECT COUNT(*) FROM dependencies WHERE project_id = ? "
            "AND dependency_type = 'node_package_graph'",
            (registered.project_id,),
        ).fetchone()[0]
    assert repeated_count == 4


def test_node_source_import_attribution_skips_ambiguous_locked_versions(tmp_path):
    project = tmp_path / "node-ambiguous"
    project.mkdir()
    (project / "package-lock.json").write_text(
        json.dumps({
            "name": "node-ambiguous",
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "node-ambiguous", "version": "1.0.0"},
                "node_modules/react": {"version": "18.3.1"},
                "node_modules/parent/node_modules/react": {"version": "17.0.2"},
            },
        }),
        encoding="utf-8",
    )
    (project / "app.js").write_text(
        "import React from 'react';\n", encoding="utf-8"
    )
    service = ProjectService(Database(tmp_path / "db.sqlite"))
    registered = service.initialize(str(project))

    service.analyze_dependencies(registered.project_id)

    with service.db.connect() as conn:
        source_links = conn.execute(
            "SELECT COUNT(*) FROM dependencies WHERE project_id = ? "
            "AND dependency_type = 'node_package_graph' AND source_path = 'app.js'",
            (registered.project_id,),
        ).fetchone()[0]
    assert source_links == 0


def test_go_source_imports_link_to_longest_unique_go_sum_module_prefix(tmp_path):
    project = tmp_path / "go-source-graph"
    project.mkdir()
    (project / "go.sum").write_text(
        "example.com/lib v1.2.3 h1:abc=\n"
        "example.com/lib v1.2.3/go.mod h1:def=\n"
        "example.com/lib/v2 v2.1.0 h1:ghi=\n",
        encoding="utf-8",
    )
    (project / "service.go").write_text(
        "package service\n"
        "import (\n"
        '    base "example.com/lib/pkg"\n'
        '    v2 "example.com/lib/v2/pkg"\n'
        '    "fmt"\n'
        ")\n",
        encoding="utf-8",
    )
    db = Database(tmp_path / "db.sqlite")
    service = ProjectService(db)
    registered = service.initialize(str(project))

    result = service.analyze_dependencies(registered.project_id)

    assert result.result["go_source_imports"]["edge_count"] == 3
    with db.connect() as conn:
        rows = conn.execute(
            "SELECT source_path, target_name, dependency_type FROM dependencies "
            "WHERE project_id = ? AND dependency_type = 'go_package_graph'",
            (registered.project_id,),
        ).fetchall()
    assert {
        (row["source_path"], row["target_name"], row["dependency_type"])
        for row in rows
    } == {
        ("service.go", "go.sum#package:example.com/lib@v1.2.3", "go_package_graph"),
        ("service.go", "go.sum#package:example.com/lib/v2@v2.1.0", "go_package_graph"),
    }

    impact = service.check_blast_radius(
        registered.project_id, "go.sum#package:example.com/lib/v2@v2.1.0"
    )
    assert impact.result["impact_by_relation"]["go_package_graph"]["direct_dependents"] == [
        "service.go"
    ]

    service.analyze_dependencies(registered.project_id)
    with db.connect() as conn:
        count = conn.execute(
            "SELECT COUNT(*) FROM dependencies WHERE project_id = ? "
            "AND dependency_type = 'go_package_graph'",
            (registered.project_id,),
        ).fetchone()[0]
    assert count == 2


def test_go_source_import_attribution_skips_ambiguous_module_versions(tmp_path):
    project = tmp_path / "go-ambiguous"
    project.mkdir()
    (project / "go.sum").write_text(
        "example.com/lib v1.2.3 h1:abc=\n"
        "example.com/lib v1.3.0 h1:def=\n",
        encoding="utf-8",
    )
    (project / "main.go").write_text(
        'package main\nimport "example.com/lib/pkg"\n',
        encoding="utf-8",
    )
    service = ProjectService(Database(tmp_path / "db.sqlite"))
    registered = service.initialize(str(project))

    service.analyze_dependencies(registered.project_id)

    with service.db.connect() as conn:
        count = conn.execute(
            "SELECT COUNT(*) FROM dependencies WHERE project_id = ? "
            "AND dependency_type = 'go_package_graph' AND source_path = 'main.go'",
            (registered.project_id,),
        ).fetchone()[0]
    assert count == 0


def test_rust_source_imports_link_to_normalized_cargo_crates_and_blast_radius(tmp_path):
    project = tmp_path / "rust-source-graph"
    project.mkdir()
    (project / "Cargo.lock").write_text(
        'version = 3\n\n'
        '[[package]]\nname = "app"\nversion = "0.1.0"\n'
        'dependencies = ["serde 1.0.210"]\n\n'
        '[[package]]\nname = "serde"\nversion = "1.0.210"\n'
        'dependencies = ["serde-derive 1.0.210"]\n\n'
        '[[package]]\nname = "serde-derive"\nversion = "1.0.210"\n',
        encoding="utf-8",
    )
    (project / "main.rs").write_text(
        "use serde::Serialize;\n"
        "use std::fmt;\n"
        "use crate::local::Thing;\n",
        encoding="utf-8",
    )
    db = Database(tmp_path / "db.sqlite")
    service = ProjectService(db)
    registered = service.initialize(str(project))

    result = service.analyze_dependencies(registered.project_id)

    assert result.result["rust_source_imports"]["edge_count"] == 1
    with db.connect() as conn:
        rows = conn.execute(
            "SELECT source_path, target_name, dependency_type FROM dependencies "
            "WHERE project_id = ? AND dependency_type = 'rust_package_graph'",
            (registered.project_id,),
        ).fetchall()
    assert {
        (row["source_path"], row["target_name"], row["dependency_type"])
        for row in rows
    } == {
        ("main.rs", "Cargo.lock#package:serde@1.0.210", "rust_package_graph"),
        (
            "Cargo.lock#package:app@0.1.0",
            "Cargo.lock#package:serde@1.0.210",
            "rust_package_graph",
        ),
        (
            "Cargo.lock#package:serde@1.0.210",
            "Cargo.lock#package:serde-derive@1.0.210",
            "rust_package_graph",
        ),
    }

    impact = service.check_blast_radius(
        registered.project_id, "Cargo.lock#package:serde-derive@1.0.210"
    )
    rust_impact = impact.result["impact_by_relation"]["rust_package_graph"]
    assert rust_impact["direct_dependents"] == [
        "Cargo.lock#package:serde@1.0.210"
    ]
    assert {
        item["identifier"] for item in rust_impact["transitive_dependents"]
    } == {
        "Cargo.lock#package:app@0.1.0",
        "Cargo.lock#package:serde@1.0.210",
        "main.rs",
    }

    service.analyze_dependencies(registered.project_id)
    with db.connect() as conn:
        count = conn.execute(
            "SELECT COUNT(*) FROM dependencies WHERE project_id = ? "
            "AND dependency_type = 'rust_package_graph'",
            (registered.project_id,),
        ).fetchone()[0]
    assert count == 3


def test_rust_source_import_attribution_skips_ambiguous_crate_versions(tmp_path):
    project = tmp_path / "rust-ambiguous"
    project.mkdir()
    (project / "Cargo.lock").write_text(
        'version = 3\n\n'
        '[[package]]\nname = "serde"\nversion = "1.0.0"\n\n'
        '[[package]]\nname = "serde"\nversion = "2.0.0"\n',
        encoding="utf-8",
    )
    (project / "main.rs").write_text(
        "use serde::Serialize;\n", encoding="utf-8"
    )
    service = ProjectService(Database(tmp_path / "db.sqlite"))
    registered = service.initialize(str(project))

    service.analyze_dependencies(registered.project_id)

    with service.db.connect() as conn:
        count = conn.execute(
            "SELECT COUNT(*) FROM dependencies WHERE project_id = ? "
            "AND dependency_type = 'rust_package_graph' AND source_path = 'main.rs'",
            (registered.project_id,),
        ).fetchone()[0]
    assert count == 0


def test_php_source_imports_link_to_unique_composer_psr4_package(tmp_path):
    project = tmp_path / "php-source-graph"
    project.mkdir()
    (project / "composer.json").write_text(
        json.dumps({"require": {"vendor/library": "^2"}}),
        encoding="utf-8",
    )
    (project / "composer.lock").write_text(json.dumps({
        "packages": [{
            "name": "vendor/library",
            "version": "2.1.0",
            "require": {"psr/log": "^3"},
            "autoload": {"psr-4": {"Vendor\\Library\\": "src/"}},
        }, {
            "name": "psr/log",
            "version": "3.0.0",
            "autoload": {"psr-4": {"Psr\\Log\\": "src/"}},
        }],
        "packages-dev": [],
    }), encoding="utf-8")
    (project / "app.php").write_text(
        "<?php\nuse Vendor\\Library\\Client;\n",
        encoding="utf-8",
    )
    db = Database(tmp_path / "db.sqlite")
    service = ProjectService(db)
    registered = service.initialize(str(project))

    result = service.analyze_dependencies(registered.project_id)

    assert result.result["php_source_imports"]["edge_count"] == 1
    with db.connect() as conn:
        rows = conn.execute(
            "SELECT source_path, target_name, dependency_type FROM dependencies "
            "WHERE project_id = ? AND dependency_type = 'php_package_graph'",
            (registered.project_id,),
        ).fetchall()
    assert {
        (row["source_path"], row["target_name"])
        for row in rows
    } == {
        ("app.php", "composer.lock#package:vendor/library@2.1.0"),
        (
            "composer.lock#package:vendor/library@2.1.0",
            "composer.lock#package:psr/log@3.0.0",
        ),
    }

    impact = service.check_blast_radius(
        registered.project_id, "composer.lock#package:psr/log@3.0.0"
    )
    php_impact = impact.result["impact_by_relation"]["php_package_graph"]
    assert php_impact["direct_dependents"] == [
        "composer.lock#package:vendor/library@2.1.0"
    ]
    assert {
        item["identifier"] for item in php_impact["transitive_dependents"]
    } == {
        "composer.lock#package:vendor/library@2.1.0",
        "app.php",
    }
    assert any(
        item.kind == "php_source_imports" and item.source_path == "app.php"
        for item in impact.evidence
    )


def test_php_source_import_attribution_skips_ambiguous_psr4_prefixes(tmp_path):
    project = tmp_path / "php-ambiguous-graph"
    project.mkdir()
    (project / "composer.lock").write_text(json.dumps({
        "packages": [
            {
                "name": "vendor/library-a",
                "version": "1.0.0",
                "autoload": {"psr-4": {"Vendor\\Library\\": "src/"}},
            },
            {
                "name": "vendor/library-b",
                "version": "2.0.0",
                "autoload": {"psr-4": {"Vendor\\Library\\": "src/"}},
            },
        ],
        "packages-dev": [],
    }), encoding="utf-8")
    (project / "app.php").write_text(
        "<?php\nuse Vendor\\Library\\Client;\n",
        encoding="utf-8",
    )
    db = Database(tmp_path / "db.sqlite")
    service = ProjectService(db)
    registered = service.initialize(str(project))

    result = service.analyze_dependencies(registered.project_id)

    assert result.result["php_source_imports"]["edge_count"] == 1
    with db.connect() as conn:
        count = conn.execute(
            "SELECT COUNT(*) FROM dependencies WHERE project_id = ? "
            "AND dependency_type = 'php_package_graph' AND source_path = 'app.php'",
            (registered.project_id,),
        ).fetchone()[0]
    assert count == 0


def test_assess_project_runs_current_analyses_and_returns_consolidated_summary(tmp_path):
    project = tmp_path / "assessment-sample"
    project.mkdir()
    (project / "app.py").write_text(
        "def greet(name):\n    return f'hello {name}'\n", encoding="utf-8"
    )
    service = ProjectService(Database(tmp_path / "swea.sqlite"))
    registered = service.initialize(str(project))

    result = service.assess_project(registered.project_id)

    assert result.status.value == "partial"
    assert result.result["analysis_level"] == "orchestrated_project_assessment"
    assert set(result.result["analyses"]) == {
        "architecture", "dependencies", "contracts", "code_quality", "security",
    }
    assert result.result["risk_summary"]["domains_assessed"] == 4
    assert result.result["coverage_complete"] is False
    assert len(result.result["domains_not_assessed"]) == 8
    assert result.result["total_findings"] == len(result.findings)
    assert result.result["total_evidence"] == len(result.evidence)


def test_assess_project_can_refresh_before_running_analyses(tmp_path):
    project = tmp_path / "assessment-refresh"
    project.mkdir()
    (project / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    service = ProjectService(Database(tmp_path / "swea.sqlite"))
    registered = service.initialize(str(project))

    result = service.assess_project(registered.project_id, refresh_index=True)

    assert result.result["refresh"]["status"] == "completed"
    assert result.status.value == "partial"
