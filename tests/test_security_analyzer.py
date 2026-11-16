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


def test_detects_obvious_dynamic_sql_but_not_parameterized_queries(tmp_path):
    (tmp_path / "database.py").write_text(
        "cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')\n"
        "cursor.execute('UPDATE users SET name = ' + user_name)\n"
        "cursor.execute('DELETE FROM users WHERE id = {}'.format(user_id))\n"
        "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))\n"
        "cursor.execute(query)\n",
        encoding="utf-8",
    )

    report = analyze_python_security(tmp_path, ProjectIndexSettings())

    findings = [
        item for item in report["findings"]
        if item["code"] == "PYTHON_DYNAMIC_SQL_QUERY"
    ]
    assert len(findings) == 3
    assert all(item["severity"] == "high" for item in findings)
    assert all(item["confidence"] == "HEURISTIC" for item in findings)


def test_detects_known_credential_formats_without_echoing_values(tmp_path):
    github_token = "ghp_" + "A" * 36
    aws_key_id = "AKIA" + "B" * 16
    private_key_marker = "-----BEGIN RSA " + "PRIVATE KEY-----"
    (tmp_path / "credentials.py").write_text(
        f'github_token = "{github_token}"\n'
        f'aws_key_id = "{aws_key_id}"\n'
        f'private_key = "{private_key_marker}"\n'
        'example = "replace-me-with-your-token"\n',
        encoding="utf-8",
    )

    report = analyze_python_security(tmp_path, ProjectIndexSettings())

    findings = [
        item for item in report["findings"]
        if item["code"] == "PYTHON_HARDCODED_CREDENTIAL"
    ]
    assert len(findings) == 3
    assert all(item["severity"] == "high" for item in findings)
    assert all(item["confidence"] == "HIGH_CONFIDENCE" for item in findings)
    assert all(github_token not in item["message"] for item in findings)
    assert all(aws_key_id not in item["message"] for item in findings)
    assert all(private_key_marker not in item["message"] for item in findings)


def test_resolves_unshadowed_security_api_import_aliases(tmp_path):
    (tmp_path / "aliases.py").write_text(
        "import subprocess as sp\n"
        "from subprocess import run as run_cmd\n"
        "import os as operating_system\n"
        "from os import system as shell\n"
        "import yaml as y\n"
        "from yaml import unsafe_load as unsafe_yaml, load as yaml_load, SafeLoader as Safe\n"
        "import requests as req\n"
        "from requests import get as http_get\n"
        "import ssl as tls\n"
        "from ssl import _create_unverified_context as unverified\n"
        "import pickle as serializer\n"
        "from pickle import loads as deserialize\n"
        "sp.run(command, shell=True)\n"
        "run_cmd(command, shell=True)\n"
        "operating_system.system(command)\n"
        "shell(command)\n"
        "y.unsafe_load(payload)\n"
        "unsafe_yaml(payload)\n"
        "yaml_load(payload)\n"
        "yaml_load(payload, Loader=Safe)\n"
        "req.get(url, verify=False)\n"
        "http_get(url, verify=False)\n"
        "tls._create_unverified_context()\n"
        "unverified()\n"
        "serializer.loads(data)\n"
        "deserialize(data)\n",
        encoding="utf-8",
    )

    report = analyze_python_security(tmp_path, ProjectIndexSettings())
    codes = [item["code"] for item in report["findings"]]

    assert codes.count("PYTHON_SUBPROCESS_SHELL_TRUE") == 2
    assert codes.count("PYTHON_OS_COMMAND_EXECUTION") == 2
    assert codes.count("PYTHON_UNSAFE_YAML_LOAD") == 2
    assert codes.count("PYTHON_YAML_LOAD_WITHOUT_SAFE_LOADER") == 1
    assert codes.count("PYTHON_TLS_CERTIFICATE_VERIFICATION_DISABLED") == 2
    assert codes.count("PYTHON_TLS_UNVERIFIED_SSL_CONTEXT") == 2
    assert codes.count("PYTHON_PICKLE_DESERIALIZATION") == 2


def test_does_not_apply_import_alias_after_rebinding(tmp_path):
    (tmp_path / "shadowed.py").write_text(
        "import subprocess as sp\n"
        "sp = fake_module\n"
        "sp.run(command, shell=True)\n",
        encoding="utf-8",
    )

    report = analyze_python_security(tmp_path, ProjectIndexSettings())

    assert not any(
        item["code"] == "PYTHON_SUBPROCESS_SHELL_TRUE"
        for item in report["findings"]
    )


def test_security_aliases_are_resolved_per_function_scope(tmp_path):
    (tmp_path / "scopes.py").write_text(
        "import subprocess as sp\n"
        "def shadowed():\n"
        "    sp = fake_module\n"
        "    sp.run(command, shell=True)\n"
        "def uses_global_alias():\n"
        "    sp.run(command, shell=True)\n"
        "def local_import():\n"
        "    import subprocess as local_sp\n"
        "    local_sp.run(command, shell=True)\n"
        "class Example:\n"
        "    import subprocess as class_sp\n"
        "    def method(self):\n"
        "        class_sp.run(command, shell=True)\n",
        encoding="utf-8",
    )

    report = analyze_python_security(tmp_path, ProjectIndexSettings())

    findings = [
        item for item in report["findings"]
        if item["code"] == "PYTHON_SUBPROCESS_SHELL_TRUE"
    ]
    assert len(findings) == 2
    assert [item["line"] for item in findings] == [6, 9]
