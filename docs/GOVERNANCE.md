# Governance and project isolation

## Current security boundary

SWEA Sentinel is currently a single-user, local-first service. The Streamable HTTP
transport is restricted to loopback addresses. Loopback binding is a network
exposure reduction, **not authentication** and not a multi-user authorization
boundary. Do not bind the HTTP transport to a LAN, public interface, reverse
proxy, or container network until the controls below are implemented and tested.

The current database already scopes project-owned snapshots, components,
dependencies, tasks, assessments, findings, evidence, usage records, and
approvals with project_id foreign keys. Tool executions and audit events are
recorded, including failed invocations. These records do not yet establish an
authenticated actor or tenant boundary.

## Required authorization model

Introduce an authenticated principal supplied by the transport/session layer;
never accept an actor or tenant identity from ordinary tool arguments.

Initial roles:

| Role | Read project | Run analysis | Refresh inventory | Manage members/policies |
| --- | --- | --- | --- | --- |
| Owner | Yes | Yes | Yes | Yes |
| Maintainer | Yes | Yes | Yes | No |
| Analyst | Yes | Yes | No | No |
| Viewer | Yes | No | No | No |

Permissions must be checked in the service layer for every project-scoped
operation. Hiding tools in an MCP client is not an authorization control.
Project IDs are selectors, not proof of access.

## Isolation requirements

1. Add tenant/workspace and membership records through ordered schema migrations.
2. Bind each project to exactly one workspace; represent memberships with a
   unique (workspace_id, principal_id) key and an explicit role.
3. Resolve the authenticated principal to an authorized workspace before
   loading a project. Every read and write must be scoped by both workspace and
   project; do not rely solely on a post-query ownership check.
4. Reject unknown, cross-workspace, revoked, and insufficient-role access with
   a consistent authorization error. Avoid revealing whether an inaccessible
   project ID exists.
5. Keep the local STDIO mode usable without introducing a fake remote identity.
   A local owner context may be established by the trusted process boundary,
   not by a user-controlled request field.
6. Keep remote HTTP disabled for multi-user use until authentication,
   authorization, isolation, and negative cross-tenant tests are complete.

## Audit requirements

Extend audit events with an authenticated actor/principal, workspace, project,
tool/action, outcome, timestamp, and request/correlation identifier. Record
authorization denials as well as successful and failed operations. Keep
audit metadata allow-listed and sanitized: never store credentials, raw secret
matches, source contents, or arbitrary tool arguments by default.

Audit history should be append-only through the application API. Add tests for
missing audit persistence, failed tool calls, denied access, actor attribution,
and cross-workspace isolation. Define retention and export controls before
commercial multi-tenant deployment.

## Delivery sequence

- **GOV-1 — Identity context:** define principal/session contracts for STDIO and
  HTTP without trusting tool-supplied identity fields.
- **GOV-2 — Workspace schema:** add migration, workspace ownership, memberships,
  and explicit roles; migrate existing local projects into a local workspace.
- **GOV-3 — Service authorization:** centralize capability checks and enforce
  workspace/project scope at every service and persistence boundary.
- **GOV-4 — Audit attribution:** add actor/workspace/request metadata and
  privacy-safe authorization-denial events.
- **GOV-5 — Verification:** test role matrices, cross-project and cross-workspace
  denial, revoked memberships, and concurrent membership changes.
- **GOV-6 — Exposure review:** only after all prior gates pass, reassess whether
  authenticated remote HTTP can be enabled.

No multi-user or remote-security guarantee should be claimed until GOV-1
through GOV-6 are implemented and independently verified.
