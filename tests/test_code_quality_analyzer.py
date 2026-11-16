from swea_sentinel.config import ProjectIndexSettings
from swea_sentinel.core.code_quality_analyzer import analyze_python_code_quality


def test_detects_mutable_defaults_and_broad_exception_handlers(tmp_path):
    (tmp_path / "sample.py").write_text(
        "def bad(items=[]): pass\n"
        "def also_bad(*, options=dict()): pass\n"
        "def good(items=None): pass\n"
        "try:\n    work()\nexcept:\n    recover()\n"
        "try:\n    work()\nexcept (ValueError, Exception):\n    recover()\n",
        encoding="utf-8",
    )

    report = analyze_python_code_quality(tmp_path, ProjectIndexSettings())

    codes = [item["code"] for item in report["findings"]]
    assert codes.count("PYTHON_MUTABLE_DEFAULT_ARGUMENT") == 2
    assert codes.count("PYTHON_BARE_EXCEPT") == 1
    assert codes.count("PYTHON_BROAD_EXCEPTION_CATCH") == 1
    assert all(item["confidence"] == "HIGH_CONFIDENCE" for item in report["findings"])
    assert len(report["file_hashes"]["sample.py"]) == 64


def test_quality_scan_is_bounded_and_reports_parse_errors(tmp_path):
    (tmp_path / "a.py").write_text("def ok(): pass\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("def broken(:\n", encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "ignored.py").write_text(
        "def bad(value=[]): pass\n", encoding="utf-8"
    )

    report = analyze_python_code_quality(
        tmp_path, ProjectIndexSettings(max_files=1)
    )

    assert report["files_scanned"] == 1
    assert report["truncated"] is True
    assert report["truncated_reason"] == "maximum_file_count"
    assert report["finding_count"] == 0
