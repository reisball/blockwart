# Blockwart

Blockwart is a small infrastructure knowledge and credential-reference platform for Kai, Zoe, and other agents.

The MVP goal is narrow:

- structured systems, services, credential references, and runbooks
- DB-backed canonical storage
- search-first human UI
- read-only REST API for humans and integrations
- read-only MCP surface for agents
- Markdown/YAML export as generated output
- no secret values in database records, fixtures, exports, logs, docs, or issues

## Current Status

This repository is scaffolded from the planning artifacts in:

- `/home/zoe/shared/infra-knowledge-platform/specs/repo-skeleton-plan.md`
- `/home/zoe/shared/infra-knowledge-platform/specs/core-object-schema.md`
- `/home/zoe/shared/infra-knowledge-platform/specs/pilot-import-mapping.md`

## Local Development

Create a virtual environment and install development dependencies:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --constraint requirements/dev.txt ".[dev]"
```

Run the app:

```bash
blockwart-db upgrade
uvicorn blockwart.main:app --reload
```

Without `BLOCKWART_ADMIN_TOKEN`, Blockwart is fail-closed and the UI is read-only. To enable
short-lived UI write sessions, inject an admin token with at least 32 characters through the
protected runtime environment and unlock the UI at `/admin`. The token is never stored in the
database or returned to the browser; the browser receives only an HMAC-signed `HttpOnly` session
cookie.

Initialize or refresh a local pilot database:

```bash
blockwart-seed --create-schema --seed seeds/pilot_objects.yaml
```

`--create-schema` is retained as a compatibility flag, but it now performs a real
`alembic upgrade head`; it never calls SQLAlchemy `create_all()` in a production path.
Container startup uses `blockwart-start`, which completes the same upgrade and verifies the
database revision before Uvicorn starts. An unversioned legacy Blockwart database is adopted only
when its schema exactly matches the known initial catalog schema.

Run checks:

```bash
pytest
ruff check --no-cache .
python -m compileall -q src tests scripts
```

The dependency update process, reviewed OpenAPI snapshot, installed-wheel smoke, container smoke,
and Gitea Actions contract are documented in `docs/ci.md`.

## Agent Read API

The first agent-facing surface is read-only and lives under /api/agent:

- GET /api/agent/search
- GET /api/agent/objects/{object_id}
- GET /api/agent/context

It returns sanitized object context, resolved parent paths, children, network/endpoint summaries,
and credential-reference IDs only. Structured read filters are available for placement, IP, port,
status, lifecycle, and health. It never resolves credential values. See docs/agent-api.md.

The canonical asset hierarchy is `host → system → service`, with direct
`host → service` placement also supported. Placement is stored only as a
parent-to-child `hosts` relationship; object IDs are globally unique. See
`docs/domain-model.md`.

All relationship types, directions, typed-reference checks, dependency storage, kind-change and
delete behavior, database constraints, and the read-only integrity diagnostic are documented in
`docs/relationship-integrity.md`.

Endpoint, technical-port, and administrative-access semantics use one backend contract. Agent API
and MCP expose its normalized view, while live-data normalization remains an explicit dry-run-first
operation. See `docs/service-interfaces.md`.

The catalog REST API is also read-only. Object changes are available only through authenticated
UI form routes. Catalog, Agent, and MCP boundaries share RFC3339 UTC timestamps, stable REST error
codes with correlation IDs, and explicit safe diagnostics for corrupt catalog rows. See
`docs/api-boundary-contract.md`.

A local MCP-compatible stdio wrapper is available as blockwart-mcp. See docs/mcp.md.

## Markdown Import

Blockwart can import the current workspace operations index from TOOLS.md with a dry-run-first CLI.
Database writes require the explicit apply flag. The importer creates system objects and
credential-reference pointers only; it does not resolve or store secret values. See
docs/markdown-import.md.

## Transaction Ownership

Application boundaries own database transactions. One authenticated UI request or one complete
seed/Markdown import runs inside `blockwart.db.session.transaction()` and commits exactly once.
Catalog and import service helpers only flush; calling them without an owning transaction does not
persist changes. Object, relationship, cleanup, and audit changes therefore commit together or
roll back together. Markdown `--replace` uses the same transaction for deletion and replacement.

## Database Schema Lifecycle

Alembic is the only application and container schema lifecycle. Useful commands:

```bash
blockwart-db upgrade
blockwart-db check
blockwart-db integrity
blockwart-db interfaces
blockwart-db placements
```

Both use an explicitly supplied `--database-url` first, then `BLOCKWART_DATABASE_URL`, then the
local development default. Schema or revision mismatches fail closed. Blockwart never performs an
automatic downgrade; restore the matching pre-upgrade database backup when rolling application
code back. `blockwart-db placements` is read-only by default and lists deliberately unassigned
systems and services; `--apply` only records the explicit unassigned marker and requires the normal
pre-change database backup. See `docs/deployment.md`.

## Deployment Readiness

Blockwart exposes process liveness at `/api/health` and `/api/health/live`. Operational readiness
at `/api/health/ready` additionally requires a readable and writable database, the exact packaged
Alembic head, and the expected SQLite runtime settings. Persistent SQLite databases use foreign-key
enforcement, a bounded lock wait, and WAL mode so readers can continue while a writer commits. The
container healthcheck uses readiness rather than liveness.

The health responses include the package version and `BLOCKWART_BUILD_REVISION`; pass the deployed
Git commit as a build argument instead of relying on the `unknown` fallback. The Dockerfile,
localhost-only compose example, endpoint contract, and backup/restore procedure are documented in
`docs/deployment.md`.

## Secret Policy

Blockwart stores credential references, never credential values.

Allowed examples:

- `vaultwarden:Brieftraeger`
- `secrets_json:n8n.apiKey`
- `env_file:/opt/n8n/.env`
- `local_file:<ssh key location not imported>`

Forbidden:

- raw passwords
- API key values
- bearer tokens
- private keys
- cookies/sessions
- exported password-store data
