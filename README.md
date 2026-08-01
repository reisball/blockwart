# Blockwart

Blockwart is a small infrastructure knowledge and credential-reference platform for Kai, Zoe, and other agents.

The MVP goal is narrow:

- structured hosts, systems, network assets, devices, services, credential
  references, and runbooks
- DB-backed canonical storage
- search-first human UI
- object-authorized REST API for humans and integrations
- object-authorized MCP surface for agents
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

Catalog reads are object-authorized. Browser routes require an authenticated
human session; `/api/objects`, `/api/agent`, and `/api/v1` require a
service-account bearer token. `discover` returns a strict placement stub,
`read` returns full detail, and objects without `discover` are concealed.
Catalog mutations use object-scoped `write`, `create_child`, or `delete`
permissions; dedicated grant management uses `manage_access` plus Owner-only
protection for Owner grants. UI, API v1, and MCP share the same policy,
revision, audit, and last-owner safeguards. Roles, bootstrap, token lifecycle,
projection, revision, and audit contracts are documented in
`docs/auth-rbac.md`.

Initialize or refresh a local pilot database:

```bash
blockwart-seed --create-schema --seed seeds/pilot_objects.yaml
```

`--create-schema` is retained as a compatibility flag, but it now performs a real
`alembic upgrade head`; it never calls SQLAlchemy `create_all()` in a production path.
Container startup uses `blockwart-start`, which completes the same upgrade and verifies the
database revision plus nonempty, active effective Owner coverage for every catalog object before
Uvicorn starts. An unversioned legacy Blockwart database is adopted only when its schema exactly
matches the known initial catalog schema.

Run checks:

```bash
pytest
ruff check --no-cache .
python -m compileall -q src tests scripts
```

The dependency update process, reviewed OpenAPI snapshot, installed-wheel smoke, container smoke,
and Gitea Actions contract are documented in `docs/ci.md`.

The backend uses one canonical English vocabulary. The UI defaults to English
and ships complete English/German catalogs with a persistent language switcher.
The database, audit, schema-override, deployment, and rollback contracts are
documented in `docs/internationalization.md`.

## Agent Read API

The first agent-facing surface is read-only and lives under /api/agent:

- GET /api/agent/search
- GET /api/agent/objects/{object_id}
- GET /api/agent/context

Every request requires `Authorization: Bearer <service-account token>` and is
filtered by that principal's current object grants.

It returns sanitized object context, resolved parent paths, children, network/endpoint summaries,
and credential-reference IDs only. Structured read filters are available for placement, IP, port,
status, lifecycle, and health. It never resolves credential values. See docs/agent-api.md.

The canonical placement hierarchy is `host → system → service`, with direct
`host → service` placement also supported. Placement is stored only as a
parent-to-child `hosts` relationship. `device` is a separate public asset kind;
its attachment graph does not extend placement or RBAC inheritance. Object IDs
are globally unique. See `docs/domain-model.md`.

All relationship types, directions, typed-reference checks, dependency storage, kind-change and
delete behavior, database constraints, and the read-only integrity diagnostic are documented in
`docs/relationship-integrity.md`.

Endpoint, technical-port, and administrative-access semantics use one backend contract. Agent API
and MCP expose its normalized view, while live-data normalization remains an explicit dry-run-first
operation. See `docs/service-interfaces.md`.

The compatibility `/api/objects` and `/api/agent` routes remain read-only.
Authorized object changes are available through authenticated UI form routes,
the `/api/v1` command routes, and MCP write tools. Catalog, Agent, and MCP
boundaries share RFC3339 UTC timestamps, stable REST error codes with
correlation IDs, and explicit safe diagnostics for corrupt catalog rows. See
`docs/api-boundary-contract.md`.

Catalog JSON routes and UI reads use the same policy-aware, FastAPI-independent
Application Query layer for object, Relationship, Audit, and canonical
topology models. Agent context remains a separate sanitized projection, but
uses the same authorization decision and safe stub contract. See
`docs/read-models.md`.

Catalog writes, seeds, Markdown imports, and stored-record integrity checks use one immutable
in-code object-schema registry for field paths and types. Unknown extension data stays compatible,
while global secret rejection cannot be disabled or overridden by a schema. See
`docs/object-validation.md`.

Every object also has a validated provenance header that distinguishes manual,
imported, discovered, and unknown sources; separates database update,
observation, verification, and staleness times; and protects explicit manual
overrides from silent import replacement. Read APIs and MCP expose the same
header and source/freshness filters. See `docs/provenance.md`.

The stable machine contract lives under `/api/v1` with object-authorized reads
and writes, opaque keyset cursors, deterministic sorting, structured domain
filters, and versioned Relationship, Audit, and Topology resources. Existing
`/api/objects` and `/api/agent` routes remain read-only compatibility surfaces.
See `docs/api-v1.md`.

A local MCP-compatible stdio wrapper is available as blockwart-mcp. It uses
the v1 service layer and can attach a service-account bearer token from a
protected file when the server requires one. See docs/mcp.md.

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
blockwart-schema-overrides
```

Both use an explicitly supplied `--database-url` first, then `BLOCKWART_DATABASE_URL`, then the
local development default. Schema or revision mismatches fail closed. Blockwart never performs an
automatic downgrade; restore the matching pre-upgrade database backup when rolling application
code back. `blockwart-db placements` is read-only by default and lists deliberately unassigned
systems and services; `--apply` only records the explicit unassigned marker and requires the normal
pre-change database backup. See `docs/deployment.md`.
`blockwart-schema-overrides` is also dry-run by default and migrates legacy UI
metadata to locale-specific version 2 only with `--apply`.

## Deployment Readiness

Blockwart exposes process liveness at `/api/health` and `/api/health/live`. Operational readiness
at `/api/health/ready` additionally requires a readable and writable database, the exact packaged
Alembic head, the expected SQLite runtime settings, and active effective Owner coverage for every
object in a nonempty catalog. Persistent SQLite databases use foreign-key
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
