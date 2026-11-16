"""Exercise tool registration and audit persistence with a FastMCP test double."""
import sqlite3
import sys
import types

from swea_sentinel.mcp.server import build_server


class FakeServer:
    def __init__(self, name):
        self.name = name
        self.tools = {}
        self.settings = types.SimpleNamespace(host="127.0.0.1", port=8000)

    def tool(self):
        def decorator(fn):
            self.tools[fn.__name__] = fn
            return fn
        return decorator


def install_fake_mcp(monkeypatch):
    fake_module = types.ModuleType("mcp.server.fastmcp")
    fake_module.FastMCP = FakeServer
    package = types.ModuleType("mcp")
    server_package = types.ModuleType("mcp.server")
    monkeypatch.setitem(sys.modules, "mcp", package)
    monkeypatch.setitem(sys.modules, "mcp.server", server_package)
    monkeypatch.setitem(sys.modules, "mcp.server.fastmcp", fake_module)


def test_mcp_server_registers_p1_and_p2_tools(monkeypatch, tmp_path):
    install_fake_mcp(monkeypatch)
    server = build_server(str(tmp_path / "swea.db"))
    assert set(server.tools) == {
        "swea_initialize_project", "swea_analyze_project", "swea_assess_project", "swea_analyze_architecture", "swea_analyze_code_quality", "swea_analyze_security", "swea_get_risk_summary", "swea_analyze_contracts", "swea_analyze_dependencies", "swea_check_blast_radius", "swea_get_project_context",
        "swea_get_project_status", "swea_refresh_project_index",
    }
    assert server.name == "SWEA Sentinel"


def test_successful_and_failed_tool_calls_are_audited(monkeypatch, tmp_path):
    install_fake_mcp(monkeypatch)
    database_path = tmp_path / "swea.db"
    server = build_server(str(database_path))
    project = tmp_path / "demo"
    project.mkdir()

    result = server.tools["swea_initialize_project"](path=str(project), name="demo")
    assert result["status"] == "completed"

    try:
        server.tools["swea_get_project_status"](project_id="missing-project")
    except ValueError:
        pass
    else:
        raise AssertionError("Expected unknown project to fail")

    with sqlite3.connect(database_path) as conn:
        executions = conn.execute(
            "SELECT tool_name, status FROM tool_executions ORDER BY created_at"
        ).fetchall()
        events = conn.execute(
            "SELECT action, outcome FROM audit_events ORDER BY created_at"
        ).fetchall()

    assert executions == [
        ("swea_initialize_project", "completed"),
        ("swea_get_project_status", "failed"),
    ]
    assert events == [
        ("mcp.tool.swea_initialize_project", "success"),
        ("mcp.tool.swea_get_project_status", "failure"),
    ]



def test_dependency_analysis_is_available_as_mcp_tool(monkeypatch, tmp_path):
    install_fake_mcp(monkeypatch)
    server = build_server(str(tmp_path / "swea.db"))
    project = tmp_path / "node-project"
    project.mkdir()
    (project / "package.json").write_text(
        '{"dependencies":{"react":"^19"}}', encoding="utf-8"
    )
    registered = server.tools["swea_initialize_project"](path=str(project), name="node-project")

    result = server.tools["swea_analyze_dependencies"](project_id=registered["project_id"])

    assert result["status"] == "completed"
    assert result["result"]["manifest_count"] == 1
    assert result["result"]["manifests"][0]["declared_dependency_names"] == ["react"]


def test_consolidated_assessment_tool_runs_all_current_analyses(monkeypatch, tmp_path):
    install_fake_mcp(monkeypatch)
    server = build_server(str(tmp_path / "swea.db"))
    project = tmp_path / "demo"
    project.mkdir()
    (project / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    initialized = server.tools["swea_initialize_project"](path=str(project))
    project_id = initialized["project_id"]

    result = server.tools["swea_assess_project"](project_id=project_id)

    assert result["status"] == "completed"
    assert result["result"]["analysis_level"] == "orchestrated_project_assessment"
    assert set(result["result"]["analyses"]) == {
        "architecture", "dependencies", "contracts", "code_quality", "security",
    }
