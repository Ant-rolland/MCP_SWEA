from swea_sentinel.core.project_service import ProjectService
from swea_sentinel.persistence.database import Database


def test_security_assessment_persists_findings_and_source_evidence(tmp_path):
    project = tmp_path / "sample"
    project.mkdir()
    (project / "app.py").write_text(
        "import subprocess\n"
        "subprocess.run('echo unsafe', shell=True)\n"
        "eval(user_input)\n",
        encoding="utf-8",
    )
    database = Database(tmp_path / "swea.sqlite")
    service = ProjectService(database)
    registered = service.initialize(str(project))

    result = service.analyze_security(registered.project_id)

    assert result.status.value == "partial"
    assert result.result["analysis_level"] == "static_project_security_patterns"
    assert len(result.findings) == 2
    assert len(result.evidence) == 1
    assert all(item.evidence_ids == [result.evidence[0].evidence_id] for item in result.findings)
    with database.connect() as conn:
        assessment = conn.execute(
            "SELECT domain FROM assessments WHERE project_id = ?",
            (registered.project_id,),
        ).fetchone()
        findings = conn.execute(
            "SELECT COUNT(*) FROM findings WHERE project_id = ?",
            (registered.project_id,),
        ).fetchone()[0]
        evidence = conn.execute(
            "SELECT COUNT(*) FROM evidence WHERE project_id = ?",
            (registered.project_id,),
        ).fetchone()[0]
    assert assessment["domain"] == "security"
    assert findings == 2
    assert evidence == 1


def test_security_assessment_scans_env_and_config_files_without_echoing_tokens(tmp_path):
    project = tmp_path / "sample"
    project.mkdir()
    token = "glpat-" + "A" * 24
    (project / ".env.local").write_text(
        f"GITLAB_TOKEN={token}\n", encoding="utf-8"
    )
    (project / "settings.yaml").write_text(
        "api_key: npm_" + "B" * 36 + "\n", encoding="utf-8"
    )
    database = Database(tmp_path / "swea.sqlite")
    service = ProjectService(database)
    registered = service.initialize(str(project))

    result = service.analyze_security(registered.project_id)

    assert result.status.value == "partial"
    assert result.result["secret_scan"]["files_scanned"] == 2
    assert len(result.findings) == 2
    assert {item.location for item in result.findings} == {
        ".env.local:1", "settings.yaml:1",
    }
    assert all(token not in item.title for item in result.findings)
    assert all(
        "npm_" not in item.title and "glpat-" not in item.title
        for item in result.findings
    )
    assert {item.source_path for item in result.evidence} == {
        ".env.local", "settings.yaml",
    }
