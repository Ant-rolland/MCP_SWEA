from pydantic import ValidationError

from swea_sentinel.config import load_settings


def test_loads_versioned_yaml_configuration(tmp_path):
    config = tmp_path / "settings.yaml"
    config.write_text(
        'version: "1.0"\nproject_index:\n  max_files: 123\nserver:\n  transports:\n    streamable_http:\n      port: 9000\n',
        encoding="utf-8",
    )
    settings = load_settings(config)
    assert settings.project_index.max_files == 123
    assert settings.server.transports.streamable_http.port == 9000


def test_environment_overrides_yaml(tmp_path, monkeypatch):
    config = tmp_path / "settings.yaml"
    config.write_text('version: "1.0"\nstorage:\n  path: ./old.db\n', encoding="utf-8")
    monkeypatch.setenv("SWEA_DB_PATH", "./override.db")
    settings = load_settings(config)
    assert settings.storage.path == "./override.db"


def test_configuration_rejects_remote_http_binding(tmp_path):
    config = tmp_path / "settings.yaml"
    config.write_text(
        'version: "1.0"\nserver:\n  transports:\n    streamable_http:\n      host: "0.0.0.0"\n',
        encoding="utf-8",
    )
    try:
        load_settings(config)
    except ValidationError:
        return
    raise AssertionError("Remote binding must remain disabled in P1")
