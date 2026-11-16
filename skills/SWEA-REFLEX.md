# SWEA Sentinel — Agent Engineering Reflexes

## Purpose

SWEA Sentinel is an evidence-aware engineering governance MCP service. It helps an AI coding agent understand a project, inspect selected engineering risks, trace static dependencies, and explain uncertainty. It is an analysis and governance layer, not an autonomous code executor.

## Operating principles

1. **Discover before judging.** Register the project and inspect its current inventory before drawing conclusions.
2. **Use the narrowest relevant analysis.** Run architecture, dependency, contract, code-quality, and security analyses when they answer a concrete question.
3. **Separate evidence from interpretation.** Every finding should retain its source location, evidence reference, severity, and confidence.
4. **Never turn absence of evidence into proof of absence.** Truncated scans, syntax errors, unsupported languages, ambiguous mappings, and unresolved references must remain visible.
5. **Do not claim runtime verification from static inspection.** AST and manifest relationships are structural observations, not proof of runtime behavior.
6. **Do not execute or modify the inspected project through these tools.** Current P1/P2 analyzers are read-only and do not run project commands.
7. **Do not overstate security conclusions.** A detected risky API is not automatically an exploitable vulnerability; exploitability may depend on data flow, trust boundaries, configuration, and runtime context.

## Available MCP tools

| Tool | Purpose |
|---|---|
| `swea_initialize_project` | Register an existing local project directory. |
| `swea_analyze_project` | Produce or return the bounded filesystem inventory. |
| `swea_get_project_context` | Retrieve the latest inventory context and file-type summary. |
| `swea_get_project_status` | Check registration and indexing status. |
| `swea_refresh_project_index` | Refresh the filesystem inventory and component hashes. |
| `swea_analyze_architecture` | Inspect Python imports, local dependency edges, and candidate import cycles. |
| `swea_analyze_dependencies` | Discover supported ecosystem manifests and lockfile package relationships. |
| `swea_analyze_contracts` | Inspect OpenAPI and JSON Schema documents, references, and exact Python route mappings. |
| `swea_analyze_code_quality` | Check selected Python AST code-quality patterns. |
| `swea_analyze_security` | Check selected Python AST security-sensitive API patterns. |
| `swea_get_risk_summary` | Summarize open findings from the latest assessment in each domain. |
| `swea_check_blast_radius` | Trace direct and transitive dependents within one persisted relation layer. |

## Recommended analysis sequence

1. Call `swea_initialize_project` with the exact local project directory supplied by the user.
2. Call `swea_analyze_project` and `swea_get_project_context` to understand the indexed scope.
3. Run the relevant specialist analyses:
   - `swea_analyze_architecture` for Python import relationships.
   - `swea_analyze_dependencies` for manifests and lockfiles.
   - `swea_analyze_contracts` for API/data contracts and recognized Python route declarations.
   - `swea_analyze_code_quality` for the currently implemented code-quality rules.
   - `swea_analyze_security` for the currently implemented security-sensitive API rules.
4. Call `swea_get_risk_summary` to review the latest findings and scan completeness by domain. This summarizes only the latest assessment per domain, and explicitly lists domains without an assessment; it is not a calibrated risk score.
5. Use `swea_check_blast_radius` only with an identifier present in a persisted graph. The result reports impact separately by relation type; do not join unrelated ecosystems.
6. If files changed or a fresh snapshot is needed, call `swea_refresh_project_index` before relying on the inventory.

## Evidence and confidence

- **PROVEN**: use only when the tool has direct, sufficient evidence for the exact claim. Current static findings generally should not be promoted to PROVEN runtime claims.
- **HIGH_CONFIDENCE**: a source pattern or structural relationship was directly observed, but its runtime significance may remain unknown.
- **HEURISTIC**: a pattern suggests a possible risk, but important context is missing.
- **UNKNOWN**: evidence is insufficient, ambiguous, unsupported, or incomplete.

Severity describes potential impact; confidence describes how strongly the available evidence supports the finding. Do not conflate them.

Evidence records include a source path and SHA-256 hash where available. Source contents are not persisted by these analysis workflows.

## Local data protection

The SQLite database is created with owner-only read/write permissions on POSIX systems; a newly created database directory is owner-only, and symlink database paths are rejected. Do not copy database contents, findings, project paths, or audit metadata into public logs or tickets. This is local filesystem permission hardening, not database encryption or multi-user authorization.

## Current analysis boundaries

### Architecture and dependencies

- Python imports are inspected statically; dynamic imports, runtime dependency injection, plugin loading, and generated modules are not resolved.
- Manifest and lockfile relationships describe declarations or lockfile edges, not proof of runtime use. Node source imports are regex-based structural observations, not a full JavaScript/TypeScript parse.
- Python source-to-package attribution requires an exact normalized import-root/distribution-name match and one unique locked package. Import aliases are not guessed.
- JavaScript/TypeScript source-to-package attribution recognizes only single-line literal import/export, require, and dynamic-import specifiers. The package root must exactly match one uniquely locked npm package across discovered Node lockfiles; scoped package roots are supported. Relative imports, Node builtins, aliases, multiline declarations, computed specifiers, and ambiguous locked versions remain unlinked.
- Blast-radius relation layers are independent. Do not infer cross-ecosystem impact from matching names alone.

### API/data contracts

- Contract discovery is bounded to JSON/YAML documents resembling OpenAPI or JSON Schema.
- External references are not fetched. Structural discovery is not full specification validation.
- Python source mapping recognizes literal HTTP method/path decorators and explicit `add_api_route`, `add_url_rule`, and `add_route` registration calls only when both method and path are known. Literal FastAPI `APIRouter(prefix=...)` and same-file `include_router(..., prefix=...)` prefixes are composed.
- Duplicate route matches are ambiguous; dynamic paths or methods, dynamic prefixes, cross-module router mounts, other registration calls, and non-Python implementations are not inferred.
- If route scanning is truncated or Python syntax errors occur, unmatched mappings are incomplete, not proof that no implementation exists.
- Exact unique contract-to-route matches are persisted as a separate blast-radius relation.

The Python code-quality checks also flag exception handlers whose only statement is `pass` or `...`, because they silently discard failures. This is a source-pattern finding, not proof that the exception is unexpected in the application's context.

### Security

The analyzer also detects a narrow set of known credential formats and private-key markers in Python string literals. It deliberately does not echo matched values in findings. This is not generic secret scanning: arbitrary passwords, unknown token formats, environment files, non-Python files, and credential validity are outside its scope. Treat matches as sensitive and rotate a real credential rather than copying it into logs or tickets.

The current Python security checks also flag obvious dynamically assembled SQL strings passed to `execute` or `executemany` when the literal prefix resembles a SQL statement. These findings are heuristic: the analyzer does not trace whether interpolated values are attacker-controlled. Prefer parameterized queries and inspect the call site and trust boundary before treating a finding as exploitable.

### Code quality

The current Python security checks include explicit TLS verification bypass patterns: `requests`/`httpx` calls with literal `verify=False` and `ssl._create_unverified_context()`. These are high-confidence source-pattern observations, not proof that a network connection is reachable or exploitable. Import aliases and indirect wrappers are not resolved.

The current Python checks cover only:
- Mutable default arguments.
- Bare `except` handlers.
- Broad `Exception` or `BaseException` catches.

These checks are not a replacement for Ruff, mypy, a full review, or runtime testing.

### Security

The current Python checks cover only:
- Built-in `eval` and `exec`.
- `os.system` and `os.popen`.
- `subprocess` calls with literal `shell=True`.
- `yaml.load` without an explicit SafeLoader and `yaml.unsafe_load`.
- `pickle.load` and `pickle.loads`.

The analyzer does not perform taint analysis, data-flow analysis, import-alias resolution, dependency vulnerability matching, secret scanning, or exploitability validation. Pickle findings are heuristic because risk depends on whether input is trusted.

## Safety and deployment

- P1/P2 analyses do not execute project code or modify project files.
- Symlink traversal is disabled; generated and dependency directories are excluded; file count, file size, aggregate bytes, and scan duration are bounded.
- The Streamable HTTP transport is restricted to loopback. Do not expose it remotely until authentication, authorization, project isolation, and transport security are independently implemented and tested.
- Controlled execution is not currently implemented. Database approval tables do not constitute a secure execution sandbox.
- Python subprocess APIs alone are not a sandbox. Any future execution capability requires independently tested OS/container isolation, filesystem and network controls, timeouts, output limits, and explicit approval policies.

## Reporting requirements

When presenting results to a user:
- State which tools actually ran and whether each scan completed or was partial.
- Include the relevant finding code, severity, confidence, location, and recommendation.
- Explain important limitations and any truncated or unsupported areas.
- Distinguish static observations from tests, runtime verification, and confirmed exploitability.
- Never claim that CI, tests, deployment, or remediation succeeded unless the corresponding result was actually observed.
