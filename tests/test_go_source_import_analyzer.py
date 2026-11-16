from swea_sentinel.config import ProjectIndexSettings
from swea_sentinel.core.go_source_import_analyzer import analyze_go_source_imports


def test_discovers_single_and_grouped_go_import_paths(tmp_path):
    (tmp_path / "main.go").write_text(
        'package main\n'
        'import "fmt"\n'
        'import (\n'
        '    alias "example.com/lib/v2/pkg"\n'
        '    _ "example.com/plugin"\n'
        '    "example.com/other"\n'
        ')\n',
        encoding="utf-8",
    )

    report = analyze_go_source_imports(tmp_path, ProjectIndexSettings())

    assert {item["import_path"] for item in report["edges"]} == {
        "fmt",
        "example.com/lib/v2/pkg",
        "example.com/plugin",
        "example.com/other",
    }
    assert report["edge_count"] == 4
    assert len(report["file_hashes"]["main.go"]) == 64


def test_go_source_import_scan_is_bounded_and_excludes_vendor(tmp_path):
    (tmp_path / "a.go").write_text(
        'package a\nimport "example.com/a"\n', encoding="utf-8"
    )
    (tmp_path / "b.go").write_text(
        'package b\nimport "example.com/b"\n', encoding="utf-8"
    )
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "ignored.go").write_text(
        'package ignored\nimport "example.com/ignored"\n', encoding="utf-8"
    )

    report = analyze_go_source_imports(
        tmp_path, ProjectIndexSettings(max_files=1)
    )

    assert report["files_scanned"] == 1
    assert report["edge_count"] == 1
    assert report["truncated"] is True
    assert report["truncated_reason"] == "maximum_file_count"
