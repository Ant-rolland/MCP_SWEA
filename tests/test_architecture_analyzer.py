from swea_sentinel.config import ProjectIndexSettings
from swea_sentinel.core.architecture_analyzer import analyze_python_imports


def test_static_import_graph_resolves_local_python_modules_and_externals(tmp_path):
    root = tmp_path / "project"
    (root / "app").mkdir(parents=True)
    (root / "app" / "main.py").write_text(
        "import app.helper\nimport json\nimport requests\n", encoding="utf-8"
    )
    (root / "app" / "helper.py").write_text("VALUE = 42\n", encoding="utf-8")

    report = analyze_python_imports(root, ProjectIndexSettings())

    assert report["files_scanned"] == 2
    assert any(
        edge["source"] == "app/main.py" and edge["target"] == "app/helper.py"
        for edge in report["local_dependency_edges"]
    )
    assert "requests" in report["external_import_roots"]
    assert "json" not in report["external_import_roots"]
    assert {
        (edge["source"], edge["import_root"])
        for edge in report["external_import_edges"]
    } == {("app/main.py", "requests")}
    assert report["parse_errors"] == []


def test_static_import_graph_reports_syntax_errors_without_execution(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "broken.py").write_text("def broken(:\n    pass\n", encoding="utf-8")

    report = analyze_python_imports(root, ProjectIndexSettings())

    assert report["files_scanned"] == 1
    assert report["parse_errors"] == [
        {"path": "broken.py", "error": "SyntaxError", "line": "1"}
    ]


def test_static_import_graph_detects_candidate_cycles_and_namespace_packages(tmp_path):
    root = tmp_path / "project"
    (root / "app").mkdir(parents=True)
    (root / "app" / "alpha.py").write_text(
        "import app.beta\nfrom app import beta\n", encoding="utf-8"
    )
    (root / "app" / "beta.py").write_text("import app.alpha\n", encoding="utf-8")

    report = analyze_python_imports(root, ProjectIndexSettings())

    assert report["candidate_import_cycles"] == [["app/alpha.py", "app/beta.py"]]
    assert "app" not in report["external_import_roots"]
