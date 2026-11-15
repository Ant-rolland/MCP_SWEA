# SWEA Sentinel

SWEA Sentinel is an independent MCP service that adds an evidence-aware engineering governance layer around AI coding agents. It is designed to preserve rapid exploratory coding while making uncertainty, project context, and verification boundaries explicit.

## P0/P1 baseline and initial P2 slice

- Strict, versioned Pydantic contracts: lifecycle states, 12 SWEA domains, severity, confidence, data origin, and qualification status.
- Unknown evidence is never silently treated as verified; evidence defaults to UNKNOWN / REQUIRES_REVIEW.
- SQLite persistence with WAL, foreign keys, ordered schema migrations, and governance-oriented tables.
- Per-tool execution records and audit events, including successful and failed tool invocations.
- Project registration and bounded filesystem inventory (metadata and SHA-256 only; source contents are not stored or sent to external services).
- Seven MCP tools for project initialization, inventory analysis, architecture analysis, blast-radius checks, context, status, and index refresh.
- Initial P2 architecture analyzer: bounded, read-only Python AST import graph; local dependency edges, external import roots, candidate import-cycle detection, syntax-error reporting, and qualified source-hash evidence persisted with assessment records.
- Initial blast-radius query: direct and transitive Python dependents of a project-relative file, with path-traversal rejection and source evidence.\n- Initial P2 contract analyzer: bounded discovery of OpenAPI (JSON/YAML) and JSON Schema documents, duplicate OpenAPI operationId checks, local JSON Pointer reference checks, assessment/finding/evidence persistence, and an MCP tool.
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
- `swea_analyze_architecture`
- `swea_check_blast_radius`\n- `swea_analyze_contracts`
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

P1 performs filesystem inventory only. The initial P2 architecture slice statically inspects Python imports and computes a bounded reverse-dependency impact graph; it does not execute project code or resolve dynamic imports, runtime dependency injection, generated modules, non-Python dependencies, or prove runtime use. Candidate cycles are structural observations, not proof of runtime failure. It is not yet a complete architecture, security, compliance, performance, or test audit. It does not execute project commands or modify project files. HTTP remote binding, authentication, multi-tenant authorization, and controlled execution are intentionally out of scope until independently designed and tested.
