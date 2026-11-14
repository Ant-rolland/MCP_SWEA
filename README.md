# SWEA Sentinel

SWEA Sentinel is an independent MCP service that adds an evidence-aware engineering governance layer around AI coding agents. It is designed to preserve rapid exploratory coding while making uncertainty, project context, and verification boundaries explicit.

## P0/P1 baseline

- Strict, versioned Pydantic contracts: lifecycle states, 12 SWEA domains, severity, confidence, data origin, and qualification status.
- Unknown evidence is never silently treated as verified; evidence defaults to UNKNOWN / REQUIRES_REVIEW.
- SQLite persistence with WAL, foreign keys, ordered schema migrations, and governance-oriented tables.
- Per-tool execution records and audit events, including successful and failed tool invocations.
- Project registration and bounded filesystem inventory (metadata and SHA-256 only; source contents are not stored or sent to external services).
- Five MCP tools for project initialization, inventory analysis, context, status, and index refresh.
- Real MCP client handshake tests for STDIO and Streamable HTTP.
- GitHub Actions matrix for Python 3.12 and 3.13.

## Engineering behavior contract

The agent-facing SWEA engineering reflexes are documented in [skills/SWEA-REFLEX.md](skills/SWEA-REFLEX.md). The skill distinguishes currently implemented tools from planned capabilities and explicitly preserves exploratory coding while requiring evidence qualification and honest verification reports.

## Requirements and installation

- Python 3.12+
- Install: `python -m pip install -e ".[dev]"`

## Run

- STDIO: `swea-sentinel --transport stdio`
- Local Streamable HTTP: `swea-sentinel --transport http --host 127.0.0.1 --port 8765`

Default database: `~/.swea-sentinel/sentinel.db`. Override with `SWEA_DB_PATH` or `--db`.

## Initial MCP tools

- `swea_initialize_project`
- `swea_analyze_project`
- `swea_get_project_context`
- `swea_get_project_status`
- `swea_refresh_project_index`

## Verification

```bash
pytest
python -m compileall -q src tests
swea-sentinel --help
```

## Security and scope boundaries

P1 performs filesystem inventory only. It does not claim semantic architecture, security, compliance, performance, or test analysis. It does not execute project commands or modify project files. HTTP remote binding, authentication, multi-tenant authorization, and controlled execution are intentionally out of scope until independently designed and tested.
