from swea_sentinel.config import ProjectIndexSettings
from swea_sentinel.core.php_source_import_analyzer import analyze_php_source_imports


def test_discovers_literal_php_class_and_grouped_imports(tmp_path):
    (tmp_path / "app.php").write_text(
        "<?php\n"
        "use Vendor\\Library\\Client;\n"
        "use Vendor\\Library\\{Factory, Helpers\\Thing as ThingAlias};\n"
        "use function Vendor\\Library\\helper;\n"
        "use const Vendor\\Library\\VERSION;\n"
        "// use Fake\\Package\\Client;\n",
        encoding="utf-8",
    )

    report = analyze_php_source_imports(tmp_path, ProjectIndexSettings())

    assert {item["import_name"] for item in report["edges"]} == {
        "Vendor\\Library\\Client",
        "Vendor\\Library\\Factory",
        "Vendor\\Library\\Helpers\\Thing",
    }
    assert report["edge_count"] == 3
    assert len(report["file_hashes"]["app.php"]) == 64


def test_php_source_scan_is_bounded_and_excludes_vendor(tmp_path):
    (tmp_path / "a.php").write_text("<?php use A\\Client;\n", encoding="utf-8")
    (tmp_path / "b.php").write_text("<?php use B\\Client;\n", encoding="utf-8")
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "ignored.php").write_text(
        "<?php use Ignored\\Client;\n", encoding="utf-8"
    )

    report = analyze_php_source_imports(
        tmp_path, ProjectIndexSettings(max_files=1)
    )

    assert report["files_scanned"] == 1
    assert report["edge_count"] == 1
    assert report["truncated"] is True
    assert report["truncated_reason"] == "maximum_file_count"
