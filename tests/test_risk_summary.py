from swea_sentinel.config import ProjectIndexSettings
from swea_sentinel.core.project_service import ProjectService
from swea_sentinel.persistence.database import Database


def test_risk_summary_uses_only_latest_assessment_per_domain(tmp_path):
    project = tmp_path / "sample"
    project.mkdir()
    source = project / "app.py"
    source.write_text("def bad(items=[]): pass\n", encoding="utf-8")
    service = ProjectService(Database(tmp_path / "swea.sqlite"))
    registered = service.initialize(str(project))

    first = service.analyze_code_quality(registered.project_id)
    assert len(first.findings) == 1
    source.write_text("def good(items=None): pass\n", encoding="utf-8")
    service.analyze_code_quality(registered.project_id)

    summary = service.get_risk_summary(registered.project_id)

    assert summary.status.value == "completed"
    assert summary.result["domains_assessed"] == 1
    assert len(summary.result["domains_not_assessed"]) == 11
    assert summary.result["overall"]["open_finding_count"] == 0
    assert summary.result["domains"][0]["domain"] == "code_quality"
    assert summary.result["domains"][0]["scan_complete"] is True
    assert summary.findings == []
    assert summary.evidence == []


def test_risk_summary_marks_truncated_domain_as_incomplete(tmp_path):
    project = tmp_path / "sample"
    project.mkdir()
    (project / "a.py").write_text("def a(): pass\n", encoding="utf-8")
    (project / "b.py").write_text("def b(): pass\n", encoding="utf-8")
    service = ProjectService(
        Database(tmp_path / "swea.sqlite"),
        ProjectIndexSettings(max_files=1),
    )
    registered = service.initialize(str(project))
    service.analyze_code_quality(registered.project_id)

    summary = service.get_risk_summary(registered.project_id)

    assert summary.status.value == "partial"
    assert summary.result["domains_incomplete"] == ["code_quality"]
    assert summary.result["domains"][0]["scan_complete"] is False


def test_risk_summary_without_assessments_is_explicitly_partial(tmp_path):
    project = tmp_path / "sample"
    project.mkdir()
    service = ProjectService(Database(tmp_path / "swea.sqlite"))
    registered = service.initialize(str(project))

    summary = service.get_risk_summary(registered.project_id)

    assert summary.status.value == "partial"
    assert summary.result["domains_assessed"] == 0
    assert len(summary.result["domains_not_assessed"]) == 12
    assert summary.result["overall"]["open_finding_count"] == 0


def test_risk_summary_returns_current_findings_and_their_evidence(tmp_path):
    project = tmp_path / "sample"
    project.mkdir()
    (project / "app.py").write_text(
        "import subprocess\nsubprocess.run(command, shell=True)\n",
        encoding="utf-8",
    )
    service = ProjectService(Database(tmp_path / "swea.sqlite"))
    registered = service.initialize(str(project))
    service.analyze_security(registered.project_id)

    summary = service.get_risk_summary(registered.project_id)

    assert summary.status.value == "completed"
    assert summary.result["overall"]["open_finding_count"] == 1
    assert summary.result["overall"]["severity_counts"]["high"] == 1
    assert summary.findings[0].code == "PYTHON_SUBPROCESS_SHELL_TRUE"
    assert summary.evidence[0].kind == "python_security_source"


def test_risk_summary_marks_truncated_node_source_scan_as_incomplete(tmp_path):
    project = tmp_path / "node-sample"
    project.mkdir()
    (project / "package.json").write_text(
        '{"dependencies":{"react":"^18"}}', encoding="utf-8"
    )
    (project / "a.js").write_text(
        "import React from 'react';\n", encoding="utf-8"
    )
    (project / "b.js").write_text(
        "import zod from 'zod';\n", encoding="utf-8"
    )
    service = ProjectService(
        Database(tmp_path / "swea.sqlite"),
        ProjectIndexSettings(max_files=1),
    )
    registered = service.initialize(str(project))
    dependency_result = service.analyze_dependencies(registered.project_id)
    assert dependency_result.result["node_source_imports"]["truncated"] is True

    summary = service.get_risk_summary(registered.project_id)

    assert summary.status.value == "partial"
    assert summary.result["domains_incomplete"] == ["architecture"]
    architecture = summary.result["domains"][0]
    assert architecture["domain"] == "architecture"
    assert architecture["scan_complete"] is False


def test_risk_summary_keeps_latest_assessment_per_analysis_type(tmp_path):
    project = tmp_path / "multi-analysis"
    project.mkdir()
    (project / "package.json").write_text(
        '{"dependencies":{"react":"^18"}}', encoding="utf-8"
    )
    (project / "main.py").write_text("import os\n", encoding="utf-8")
    service = ProjectService(Database(tmp_path / "swea.sqlite"))
    registered = service.initialize(str(project))

    service.analyze_architecture(registered.project_id)
    service.analyze_dependencies(registered.project_id)
    service.analyze_architecture(registered.project_id)

    summary = service.get_risk_summary(registered.project_id)

    assert summary.result["domains_assessed"] == 1
    assert summary.result["analyses_assessed"] == 2
    architecture = summary.result["domains"][0]
    assert architecture["domain"] == "architecture"
    assert architecture["analysis_count"] == 2
    assert set(architecture["analysis_levels"]) == {
        "python_static_import_graph",
        "static_dependency_manifest_discovery",
    }
    assert {
        item["analysis_level"] for item in summary.result["analyses"]
    } == set(architecture["analysis_levels"])


def test_risk_summary_marks_truncated_php_source_scan_incomplete(tmp_path):
    project = tmp_path / "php-sample"
    project.mkdir()
    (project / "composer.lock").write_text(
        '{"packages": [], "packages-dev": []}', encoding="utf-8"
    )
    (project / "a.php").write_text("<?php use Vendor\\A;\n", encoding="utf-8")
    (project / "b.php").write_text("<?php use Vendor\\B;\n", encoding="utf-8")
    service = ProjectService(
        Database(tmp_path / "swea.sqlite"),
        ProjectIndexSettings(max_files=1),
    )
    registered = service.initialize(str(project))

    service.analyze_dependencies(registered.project_id)
    summary = service.get_risk_summary(registered.project_id)

    assert summary.status.value == "partial"
    assert "architecture" in summary.result["domains_incomplete"]
    dependency_analysis = next(
        item for item in summary.result["analyses"]
        if item["analysis_level"] == "dependency_manifests_and_lockfiles"
    )
    assert dependency_analysis["scan_complete"] is False
