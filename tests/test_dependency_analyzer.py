import json

from swea_sentinel.config import ProjectIndexSettings
from swea_sentinel.core.dependency_analyzer import analyze_dependency_manifests


def test_discovers_common_manifests_and_declared_dependencies(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({
        "dependencies": {"react": "^19"},
        "devDependencies": {"vitest": "^3"},
    }), encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        '[project]\ndependencies = ["httpx>=0.27", "pydantic>=2"]\n', encoding="utf-8"
    )
    (tmp_path / "Cargo.toml").write_text(
        '[dependencies]\nserde = "1"\n', encoding="utf-8"
    )
    (tmp_path / "go.mod").write_text(
        "module example.com/app\n\nrequire (\n example.com/lib v1.2.0\n)\n", encoding="utf-8"
    )
    (tmp_path / "Demo.csproj").write_text(
        '<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13" /></ItemGroup></Project>',
        encoding="utf-8",
    )
    (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")

    report = analyze_dependency_manifests(tmp_path)
    by_path = {item["path"]: item for item in report["manifests"]}

    assert by_path["package.json"]["declared_dependency_names"] == ["react", "vitest"]
    assert by_path["pyproject.toml"]["declared_dependency_names"] == ["httpx", "pydantic"]
    assert by_path["Cargo.toml"]["declared_dependency_names"] == ["serde"]
    assert by_path["go.mod"]["declared_dependency_names"] == ["example.com/lib"]
    assert by_path["Demo.csproj"]["declared_dependency_names"] == ["Newtonsoft.Json"]
    assert by_path["package-lock.json"]["kind"] == "lockfile"
    assert report["truncated"] is False


def test_invalid_manifest_is_reported_without_aborting_scan(tmp_path):
    (tmp_path / "package.json").write_text("{ invalid", encoding="utf-8")
    (tmp_path / "good" ).mkdir()
    (tmp_path / "good" / "package.json").write_text('{"dependencies":{"zod":"1"}}', encoding="utf-8")

    report = analyze_dependency_manifests(tmp_path)

    assert any(item["path"] == "package.json" and item["error"] == "invalid_manifest"
               for item in report["parse_errors"])
    assert any(item["path"] == "good/package.json" for item in report["manifests"])


def test_manifest_discovery_excludes_vendor_and_symlinks(tmp_path):
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "package.json").write_text('{"dependencies":{"bad":"1"}}')
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()
    (outside / "package.json").write_text('{"dependencies":{"outside":"1"}}')
    (tmp_path / "linked").symlink_to(outside, target_is_directory=True)
    (tmp_path / "package.json").write_text('{"dependencies":{"good":"1"}}')

    report = analyze_dependency_manifests(tmp_path)

    assert [item["path"] for item in report["manifests"]] == ["package.json"]


def test_manifest_size_limit_is_respected(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies":{"a":"1"}}', encoding="utf-8")
    settings = ProjectIndexSettings(max_file_bytes=1024, max_total_bytes=1_024_000)
    (tmp_path / "package.json").write_bytes(b" " * 1025)

    report = analyze_dependency_manifests(tmp_path, settings)

    assert report["manifests"] == []
    assert report["parse_errors"] == [{"path": "package.json", "error": "manifest_too_large"}]



def test_parses_npm_lockfile_v3_versions_and_dependency_edges(tmp_path):
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "name": "demo",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "demo", "dependencies": {"left-pad": "^1"}},
            "node_modules/left-pad": {"version": "1.3.0"},
            "node_modules/@scope/tool": {
                "version": "2.4.1",
                "dependencies": {"left-pad": "^1"},
            },
            "node_modules/parent/node_modules/child": {"version": "0.9.0"},
        },
    }), encoding="utf-8")

    report = analyze_dependency_manifests(tmp_path)
    lock = report["manifests"][0]

    assert lock["lockfile_version"] == 3
    assert lock["locked_package_count"] == 3
    assert {(item["name"], item["version"]) for item in lock["locked_packages"]} == {
        ("left-pad", "1.3.0"),
        ("@scope/tool", "2.4.1"),
        ("child", "0.9.0"),
    }
    assert lock["locked_dependency_edges"] == [
        {
            "source": "@scope/tool",
            "target": "left-pad",
            "source_install_path": "node_modules/@scope/tool",
        }
    ]


def test_parses_legacy_npm_lockfile_v1_nested_dependencies(tmp_path):
    (tmp_path / "npm-shrinkwrap.json").write_text(json.dumps({
        "name": "demo",
        "dependencies": {
            "parent": {
                "version": "1.0.0",
                "dependencies": {"child": {"version": "2.0.0"}},
            }
        },
    }), encoding="utf-8")

    report = analyze_dependency_manifests(tmp_path)
    lock = report["manifests"][0]

    assert lock["lockfile_version"] == 1
    assert [(item["name"], item["version"]) for item in lock["locked_packages"]] == [
        ("parent", "1.0.0"),
        ("child", "2.0.0"),
    ]
    assert lock["locked_dependency_edges"][0]["target"] == "child"


def test_invalid_npm_lockfile_is_reported(tmp_path):
    (tmp_path / "package-lock.json").write_text(
        '{"lockfileVersion":99,"packages":{}}', encoding="utf-8"
    )

    report = analyze_dependency_manifests(tmp_path)

    assert report["manifests"][0]["parse_error"] == "invalid_lockfile"
    assert report["parse_errors"] == [
        {"path": "package-lock.json", "error": "invalid_lockfile"}
    ]



def test_parses_pnpm_lockfile_versions_and_dependency_edges(tmp_path):
    (tmp_path / "pnpm-lock.yaml").write_text(
        """lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      alpha:
        specifier: ^1.0.0
        version: 1.2.0
packages:
  alpha@1.2.0:
    resolution: {integrity: sha512-example}
  '@scope/tool@2.4.1':
    resolution: {integrity: sha512-example}
snapshots:
  alpha@1.2.0:
    dependencies:
      '@scope/tool': 2.4.1
  '@scope/tool@2.4.1': {}
""",
        encoding="utf-8",
    )

    report = analyze_dependency_manifests(tmp_path)
    lock = report["manifests"][0]

    assert lock["lockfile_version"] == "9.0"
    assert {(item["name"], item["version"]) for item in lock["locked_packages"]} == {
        ("alpha", "1.2.0"),
        ("@scope/tool", "2.4.1"),
    }
    assert lock["locked_dependency_edges"] == [{
        "source": "alpha",
        "target": "@scope/tool",
        "source_install_path": "alpha@1.2.0",
    }]


def test_parses_pnpm_legacy_scoped_lockfile_keys(tmp_path):
    (tmp_path / "pnpm-lock.yaml").write_text(
        """lockfileVersion: '5.4'
packages:
  /left-pad/1.3.0: {}
  /@scope/tool/2.4.1:
    dependencies:
      left-pad: 1.3.0
""",
        encoding="utf-8",
    )

    lock = analyze_dependency_manifests(tmp_path)["manifests"][0]

    assert {(item["name"], item["version"]) for item in lock["locked_packages"]} == {
        ("left-pad", "1.3.0"),
        ("@scope/tool", "2.4.1"),
    }
    assert lock["locked_dependency_edges"][0]["target"] == "left-pad"



def test_parses_yarn_berry_lockfile_packages_and_edges(tmp_path):
    (tmp_path / 'yarn.lock').write_text('''__metadata:\n  version: 8\n  cacheKey: 10c0\n\n"left-pad@npm:^1.0.0":\n  version: 1.3.0\n  resolution: "left-pad@npm:1.3.0"\n  dependencies:\n    right-pad: "npm:^2.0.0"\n\n"@scope/tool@npm:^2.0.0":\n  version: 2.4.1\n  resolution: "@scope/tool@npm:2.4.1"\n''', encoding='utf-8')
    report = analyze_dependency_manifests(tmp_path)
    lock = report['manifests'][0]
    assert lock['lockfile_version'] == '8'
    assert {(item['name'], item['version']) for item in lock['locked_packages']} == {
        ('left-pad', '1.3.0'), ('@scope/tool', '2.4.1')}
    assert lock['locked_dependency_edges'] == [{
        'source': 'left-pad', 'target': 'right-pad',
        'source_install_path': 'left-pad@npm:^1.0.0'}]



def test_parses_yarn_classic_lockfile_dependencies(tmp_path):
    (tmp_path / 'yarn.lock').write_text('''left-pad@^1.0.0:\n  version "1.3.0"\n  resolved "https://example.invalid/left-pad.tgz"\n  dependencies:\n    right-pad "^2.0.0"\n\nright-pad@^2.0.0:\n  version "2.1.0"\n''', encoding='utf-8')
    report = analyze_dependency_manifests(tmp_path)
    lock = report['manifests'][0]
    assert lock['lockfile_version'] == 'classic'
    assert {(item['name'], item['version']) for item in lock['locked_packages']} == {
        ('left-pad', '1.3.0'), ('right-pad', '2.1.0')}
    assert lock['locked_dependency_edges'] == [{
        'source': 'left-pad', 'target': 'right-pad', 'source_install_path': 'left-pad@^1.0.0'}]



def test_parses_poetry_lockfile_packages_and_edges(tmp_path):
    (tmp_path / 'poetry.lock').write_text('''[[package]]\nname = "httpx"\nversion = "0.27.2"\n[package.dependencies]\ncertifi = "*"\n\n[[package]]\nname = "certifi"\nversion = "2024.8.30"\n''', encoding='utf-8')
    lock = analyze_dependency_manifests(tmp_path)['manifests'][0]
    assert lock['lockfile_version'] == 'poetry'
    assert {(item['name'], item['version']) for item in lock['locked_packages']} == {
        ('httpx', '0.27.2'), ('certifi', '2024.8.30')}
    assert lock['locked_dependency_edges'] == [{
        'source': 'httpx', 'target': 'certifi', 'source_install_path': 'httpx@0.27.2'}]


def test_parses_pipfile_lock_packages_and_edges(tmp_path):
    (tmp_path / 'Pipfile.lock').write_text(json.dumps({
        '_meta': {'requires': {'python_version': '3.12'}},
        'default': {'requests': {'version': '==2.32.3', 'dependencies': {'urllib3': '>=1.0'}},
                    'urllib3': {'version': '==2.2.3'}},
        'develop': {'pytest': {'version': '==8.3.3'}},
    }), encoding='utf-8')
    lock = analyze_dependency_manifests(tmp_path)['manifests'][0]
    assert lock['lockfile_version'] == 'pipfile'
    assert {(item['name'], item['version']) for item in lock['locked_packages']} == {
        ('requests', '2.32.3'), ('urllib3', '2.2.3'), ('pytest', '8.3.3')}
    assert lock['locked_dependency_edges'] == [{
        'source': 'requests', 'target': 'urllib3', 'source_install_path': 'requests@2.32.3'}]



def test_parses_cargo_lockfile_packages_and_edges(tmp_path):
    (tmp_path / 'Cargo.lock').write_text('''version = 3\n\n[[package]]\nname = "app"\nversion = "0.1.0"\ndependencies = ["serde 1.0.210", "tokio 1.40.0"]\n\n[[package]]\nname = "serde"\nversion = "1.0.210"\n\n[[package]]\nname = "tokio"\nversion = "1.40.0"\n''', encoding='utf-8')
    lock = analyze_dependency_manifests(tmp_path)['manifests'][0]
    assert lock['lockfile_version'] == '3'
    assert {(item['name'], item['version']) for item in lock['locked_packages']} == {
        ('app', '0.1.0'), ('serde', '1.0.210'), ('tokio', '1.40.0')}
    assert {item['target'] for item in lock['locked_dependency_edges']} == {'serde', 'tokio'}


def test_parses_go_sum_versions_without_inventing_edges(tmp_path):
    (tmp_path / 'go.sum').write_text('''example.com/lib v1.2.3 h1:abc=\nexample.com/lib v1.2.3/go.mod h1:def=\nexample.com/other v2.0.0/go.mod h1:ghi=\n''', encoding='utf-8')
    lock = analyze_dependency_manifests(tmp_path)['manifests'][0]
    assert {(item['name'], item['version']) for item in lock['locked_packages']} == {
        ('example.com/lib', 'v1.2.3'), ('example.com/other', 'v2.0.0')}
    assert lock['locked_dependency_edges'] == []
