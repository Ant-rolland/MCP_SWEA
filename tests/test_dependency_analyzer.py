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
    outside = tmp_path / "outside"
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
