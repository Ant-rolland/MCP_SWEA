from swea_sentinel.config import ProjectIndexSettings
from swea_sentinel.core.security_analyzer import analyze_python_security


def test_detects_selected_risky_python_apis_and_respects_safe_yaml_loader(tmp_path):
    (tmp_path / "security.py").write_text(
        "import os, pickle, subprocess, yaml\n"
        "from yaml import CSafeLoader\n"
        "eval(user_input)\n"
        "exec(code)\n"
        "os.system(command)\n"
        "subprocess.run(command, shell=True)\n"
        "yaml.load(payload)\n"
        "yaml.load(payload, Loader=yaml.SafeLoader)\n"
        "yaml.load(payload, Loader=CSafeLoader)\n"
        "yaml.unsafe_load(payload)\n"
        "pickle.loads(payload)\n",
        encoding="utf-8",
    )

    report = analyze_python_security(tmp_path, ProjectIndexSettings())

    codes = [item["code"] for item in report["findings"]]
    assert codes.count("PYTHON_DYNAMIC_CODE_EXECUTION") == 2
    assert codes.count("PYTHON_OS_COMMAND_EXECUTION") == 1
    assert codes.count("PYTHON_SUBPROCESS_SHELL_TRUE") == 1
    assert codes.count("PYTHON_YAML_LOAD_WITHOUT_SAFE_LOADER") == 1
    assert codes.count("PYTHON_UNSAFE_YAML_LOAD") == 1
    assert codes.count("PYTHON_PICKLE_DESERIALIZATION") == 1
    assert len(report["file_hashes"]["security.py"]) == 64
    pickle_finding = next(
        item for item in report["findings"]
        if item["code"] == "PYTHON_PICKLE_DESERIALIZATION"
    )
    assert pickle_finding["confidence"] == "HEURISTIC"


def test_security_scan_reports_parse_errors_and_respects_file_limit(tmp_path):
    (tmp_path / "a.py").write_text("def broken(:\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("eval(data)\n", encoding="utf-8")

    report = analyze_python_security(
        tmp_path, ProjectIndexSettings(max_files=1)
    )

    assert report["files_scanned"] == 1
    assert report["parse_errors"][0]["path"] == "a.py"
    assert report["truncated"] is True
    assert report["truncated_reason"] == "maximum_file_count"


def test_detects_explicit_tls_certificate_verification_disabling(tmp_path):
    (tmp_path / "tls.py").write_text(
        "import ssl, requests, httpx\n"
        "requests.get(url, verify=False)\n"
        "httpx.Client(verify=False)\n"
        "ssl._create_unverified_context()\n"
        "requests.get(url, verify=True)\n"
        "httpx.get(url)\n",
        encoding="utf-8",
    )

    report = analyze_python_security(tmp_path, ProjectIndexSettings())

    findings = [
        item for item in report["findings"]
        if item["code"] in {
            "PYTHON_TLS_CERTIFICATE_VERIFICATION_DISABLED",
            "PYTHON_TLS_UNVERIFIED_SSL_CONTEXT",
        }
    ]
    assert len(findings) == 3
    assert all(item["severity"] == "high" for item in findings)
    assert all(item["confidence"] == "HIGH_CONFIDENCE" for item in findings)
    assert {item["code"] for item in findings} == {
        "PYTHON_TLS_CERTIFICATE_VERIFICATION_DISABLED",
        "PYTHON_TLS_UNVERIFIED_SSL_CONTEXT",
    }
