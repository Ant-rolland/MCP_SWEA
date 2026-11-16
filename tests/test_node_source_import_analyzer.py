from swea_sentinel.config import ProjectIndexSettings
from swea_sentinel.core.node_source_import_analyzer import analyze_node_source_imports


def test_discovers_literal_external_node_imports_and_excludes_builtins(tmp_path):
    (tmp_path / "app.ts").write_text(
        "import React from 'react';\n"
        "import { helper } from '@scope/pkg/subpath';\n"
        "export { parse } from 'date-fns';\n"
        "const lodash = require('lodash');\n"
        "const zod = import('zod');\n"
        "import fs from 'node:fs';\n"
        "import path from 'path';\n"
        "import local from './local';\n"
        "// import fake from 'not-a-real-package'\n",
        encoding="utf-8",
    )

    report = analyze_node_source_imports(tmp_path, ProjectIndexSettings())

    assert {
        (item["import_root"], item["import"])
        for item in report["edges"]
    } == {
        ("react", "react"),
        ("@scope/pkg", "@scope/pkg/subpath"),
        ("date-fns", "date-fns"),
        ("lodash", "lodash"),
        ("zod", "zod"),
    }
    assert report["edge_count"] == 5
    assert len(report["file_hashes"]["app.ts"]) == 64
    assert report["truncated"] is False


def test_node_source_import_scan_is_bounded_and_excludes_vendor_directories(tmp_path):
    (tmp_path / "a.js").write_text("import x from 'alpha';\n", encoding="utf-8")
    (tmp_path / "b.ts").write_text("import y from 'beta';\n", encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "ignored.js").write_text(
        "import z from 'ignored';\n", encoding="utf-8"
    )

    report = analyze_node_source_imports(
        tmp_path, ProjectIndexSettings(max_files=1)
    )

    assert report["files_scanned"] == 1
    assert report["edge_count"] == 1
    assert report["truncated"] is True
    assert report["truncated_reason"] == "maximum_file_count"
