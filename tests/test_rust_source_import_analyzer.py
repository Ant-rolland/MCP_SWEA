from swea_sentinel.config import ProjectIndexSettings
from swea_sentinel.core.rust_source_import_analyzer import analyze_rust_source_imports


def test_discovers_literal_rust_crate_imports_and_excludes_local_roots(tmp_path):
    (tmp_path / "main.rs").write_text(
        "use serde::{Serialize, Deserialize};\n"
        "pub use tokio::task::spawn;\n"
        "extern crate regex;\n"
        "use std::fmt;\n"
        "use crate::local::Thing;\n"
        "use super::parent::Thing;\n"
        "// use fake_crate::Fake;\n",
        encoding="utf-8",
    )

    report = analyze_rust_source_imports(tmp_path, ProjectIndexSettings())

    assert {item["import_root"] for item in report["edges"]} == {
        "serde", "tokio", "regex",
    }
    assert report["edge_count"] == 3
    assert len(report["file_hashes"]["main.rs"]) == 64


def test_rust_source_import_scan_is_bounded_and_excludes_vendor_and_target(tmp_path):
    (tmp_path / "a.rs").write_text("use alpha::A;\n", encoding="utf-8")
    (tmp_path / "b.rs").write_text("use beta::B;\n", encoding="utf-8")
    for folder in ("vendor", "target"):
        (tmp_path / folder).mkdir()
        (tmp_path / folder / "ignored.rs").write_text(
            "use ignored::Thing;\n", encoding="utf-8"
        )

    report = analyze_rust_source_imports(
        tmp_path, ProjectIndexSettings(max_files=1)
    )

    assert report["files_scanned"] == 1
    assert report["edge_count"] == 1
    assert report["truncated"] is True
    assert report["truncated_reason"] == "maximum_file_count"
