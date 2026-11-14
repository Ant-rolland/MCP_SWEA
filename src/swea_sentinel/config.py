"""Strict, versioned YAML configuration for the SWEA Sentinel runtime."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field


class StrictSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, validate_assignment=True)


class StdioTransportSettings(StrictSettings):
    enabled: bool = True


class StreamableHTTPSettings(StrictSettings):
    enabled: bool = True
    host: Literal["127.0.0.1", "localhost", "::1"] = "127.0.0.1"
    port: int = Field(default=8765, ge=1, le=65535)
    remote_binding_allowed: Literal[False] = False


class TransportSettings(StrictSettings):
    stdio: StdioTransportSettings = Field(default_factory=StdioTransportSettings)
    streamable_http: StreamableHTTPSettings = Field(default_factory=StreamableHTTPSettings)


class ServerSettings(StrictSettings):
    name: str = "SWEA Sentinel"
    transports: TransportSettings = Field(default_factory=TransportSettings)


class StorageSettings(StrictSettings):
    backend: Literal["sqlite"] = "sqlite"
    path: str = "~/.swea-sentinel/sentinel.db"
    journal_mode: Literal["WAL"] = "WAL"
    schema_version: int = Field(default=1, ge=1)


class ProjectIndexSettings(StrictSettings):
    max_files: int = Field(default=20_000, ge=1, le=200_000)
    max_file_bytes: int = Field(default=2_000_000, ge=1_024, le=20_000_000)
    max_total_bytes: int = Field(default=250_000_000, ge=1_024_000, le=2_000_000_000)
    max_scan_seconds: int = Field(default=30, ge=1, le=600)
    excluded_directories: list[str] = Field(
        default_factory=lambda: [".git", ".venv", "venv", "node_modules", "__pycache__"]
    )
    follow_symlinks: Literal[False] = False


class GovernanceSettings(StrictSettings):
    profile: Literal["observe", "govern", "enforce"] = "govern"
    evidence_required: bool = True
    heuristic_is_not_proof: bool = True
    controlled_execution_enabled: Literal[False] = False


class Settings(StrictSettings):
    version: Literal["1.0"] = "1.0"
    server: ServerSettings = Field(default_factory=ServerSettings)
    storage: StorageSettings = Field(default_factory=StorageSettings)
    project_index: ProjectIndexSettings = Field(default_factory=ProjectIndexSettings)
    governance: GovernanceSettings = Field(default_factory=GovernanceSettings)


def load_settings(path: str | Path | None = None) -> Settings:
    config_path = Path(path or os.getenv("SWEA_CONFIG_PATH", "config/default.yaml")).expanduser()
    raw: dict[str, object] = {}
    if config_path.is_file():
        loaded = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        if not isinstance(loaded, dict):
            raise ValueError("Configuration root must be a YAML mapping")
        raw = loaded
    settings = Settings.model_validate(raw)
    if value := os.getenv("SWEA_DB_PATH"):
        settings.storage.path = value
    if value := os.getenv("SWEA_HTTP_HOST"):
        settings.server.transports.streamable_http.host = value
    if value := os.getenv("SWEA_HTTP_PORT"):
        settings.server.transports.streamable_http.port = int(value)
    return settings
