# SWEA Sentinel

SWEA Sentinel is an independent MCP service that adds an evidence-aware engineering governance layer around AI coding agents. It is designed to preserve rapid exploratory coding while making uncertainty, project context, and verification boundaries explicit.

## P0/P1 baseline and initial P2 slice

- Strict, versioned Pydantic contracts: lifecycle states, 12 SWEA domains, severity, confidence, data origin, and qualification status.
- Unknown evidence is never silently treated as verified; evidence defaults to UNKNOWN / REQUIRES_REVIEW.
- SQLite persistence with WAL, foreign keys, ordered schema migrations, and governance-oriented tables; newly created database directories use owner-only permissions and database files are restricted to owner read/write on POSIX, and database symlink paths are rejected.
- Per-tool execution records and audit events, including successful and failed tool invocations.
- Project registration and bounded filesystem inventory (metadata and SHA-256 only; source contents are not stored or sent to external services).
- MCP tools for project initialization, inventory analysis, architecture analysis, code-quality and security analysis, risk summaries, blast-radius checks, dependency-manifest discovery, contract analysis, context, status, and index refresh.
- Initial P2 architecture analyzer: bounded, read-only Python AST import graph; local dependency edges, external import roots, candidate import-cycle detection, syntax-error reporting, and qualified source-hash evidence persisted with assessment records.
- Initial blast-radius query: direct and transitive dependents from independently traversed persisted dependency-relation layers (Python imports, Python and Node source-to-package links, manifest declarations, lockfile edges, and exact API-contract-to-route links); accepts a project-relative file or exact dependency identifier and rejects traversal paths. Python source evidence is attached where available. Lockfile package edges use canonical package/version node identifiers; name-only edges are connected only when the target package name resolves to exactly one locked version. Ambiguous targets are deliberately left unlinked to avoid false impact paths.
- JavaScript/TypeScript source-to-package attribution: bounded literal ES import/export, `require`, and dynamic-import specifier discovery; exact npm package names are connected to a single uniquely locked package node, with source SHA-256 evidence. Source-to-package edges and npm lockfile edges share a dedicated Node graph layer, enabling package-to-source blast-radius traversal. Relative paths, builtins, aliases, ambiguous versions, multiline imports, and computed specifiers are not guessed.
- Initial P2 dependency discovery: bounded, read-only detection of Node.js, Python, Rust, Go, Java/Gradle, and .NET manifests; direct declaration extraction for package.json, pyproject.toml, requirements files, Cargo.toml, go.mod, and .NET project files; SHA-256 evidence and SQLite persistence. npm (v1-v3), pnpm, Yarn Classic/Berry, Poetry, Pipenv, and Cargo lockfile package/version records and dependency edges are persisted separately from manifest declarations. Go `go.mod` requirements are stored as declared dependency edges (including `// indirect` markers). Sibling `go.sum` records are correlated by exact module/version and distinguish module checksums from `go.mod` checksums; this is checksum-presence evidence only and does not claim to determine the version selected by Go or create dependency edges.
- Initial P2 contract analyzer: bounded discovery of OpenAPI (JSON/YAML) and JSON Schema documents, duplicate OpenAPI operationId checks, local JSON Pointer reference checks, assessment/finding/evidence persistence, and an MCP tool.
- Exact static API-to-source mapping: OpenAPI operations are matched to literal Python HTTP route decorators and explicit `add_api_route`, `add_url_rule`, and `add_route` registrations only when both method and path match exactly. Literal FastAPI `APIRouter(prefix=...)` and same-file `include_router(..., prefix=...)` prefixes are composed; dynamic and cross-module mounts remain unresolved. Unique matches include source path, function, line, and SHA-256 evidence; duplicate declarations are marked ambiguous and unmatched operations remain explicitly unmapped.
- Initial Python code-quality analyzer: bounded AST checks for mutable default arguments, bare `except`, broad `Exception`/`BaseException` catches, and handlers that silently discard exceptions with `pass` or `...`. Findings carry severity, confidence, source location, recommendation, and SHA-256 evidence; syntax errors and truncated scans are explicit.
- Initial Python security analyzer: bounded AST checks for `eval`/`exec`, `os.system`/`os.popen`, `subprocess.*(shell=True)`, unsafe YAML loading, pickle deserialization, explicit TLS certificate-verification disabling through `requests`/`httpx` `verify=False` or `ssl._create_unverified_context()`, obvious dynamic SQL statement construction passed to `execute`/`executemany`, and selected known credential/private-key formats in Python string literals. Dynamic SQL findings remain heuristic because no taint analysis is performed; credential scanning uses narrow format patterns and does not claim generic secret coverage. Findings are evidence-backed and distinguish high-confidence API patterns from heuristic pickle risk; no data-flow or taint claims are made.
- Domain risk summary: `swea_get_risk_summary` reports latest open findings, severity/confidence counts, linked evidence, incomplete scans, and domains not yet assessed; it does not invent a composite risk score.
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
- `swea_check_blast_radius`
- `swea_analyze_dependencies`
- `swea_analyze_contracts`
- `swea_analyze_code_quality`
- `swea_analyze_security`
- `swea_get_risk_summary`
- `swea_get_project_context`
- `swea_get_project_status`
- `swea_refresh_project_index`

## Verification

```bash
ruff check src tests
mypy src
pytest
python -m compileall -q src tests
python -m pip wheel . --no-deps --wheel-dir dist
swea-sentinel --help
```

## Security and scope boundaries

P1 performs filesystem inventory only. The initial P2 architecture slice statically inspects Python imports and computes a bounded reverse-dependency impact graph. Python source imports are connected to Python lockfile package nodes only when the normalized import root exactly matches one uniquely locked distribution name; ambiguous versions and import aliases are deliberately not guessed. These source-to-package links and Python lockfile edges share one Python-only relation layer so impact can traverse from a package to importing source files. Other ecosystems remain separate. Exact API contract mappings are stored in a separate blast-radius relation, allowing an OpenAPI operation identifier to identify its uniquely matched Python route source. Router prefix composition, dynamic route expressions, registration calls, and non-Python implementations remain unmapped. The analyzers do not execute project code or resolve dynamic imports, runtime dependency injection, generated modules, non-Python source references, or prove runtime use. Candidate cycles are structural observations, not proof of runtime failure. It is not yet a complete architecture, security, compliance, performance, or test audit. The initial code-quality checks cover only three explicit Python AST patterns and are not a replacement for Ruff, mypy, or a full review. The initial security checks cover selected Python API patterns only; they do not perform taint analysis, resolve import aliases, or prove attacker control of inputs. It does not execute project commands or modify project files. HTTP remote binding, authentication, multi-tenant authorization, and controlled execution are intentionally out of scope until independently designed and tested.
