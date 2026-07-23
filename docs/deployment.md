# Deployment Readiness

Blockwart is prepared for controlled deployment, but this repository does not deploy or register a
persistent service by itself.

## Approval Gate

Before a real deployment, decide and document:

- target host or container
- bind address and port
- backup location and retention
- source for `BLOCKWART_ADMIN_TOKEN`
- whether TLS is required and `BLOCKWART_ADMIN_COOKIE_SECURE` can be enabled
- whether agents reach Blockwart through REST, MCP, or both
- credential reference name for runtime configuration

Do not bind Blockwart to LAN or public networks until those decisions are made.

## Local Package Run

Install the package:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
```

Initialize a database and import the pilot seed:

```bash
BLOCKWART_DATABASE_URL=sqlite:////tmp/blockwart.sqlite3 \
  blockwart-seed --create-schema --seed seeds/pilot_objects.yaml
```

Run the app:

```bash
BLOCKWART_DATABASE_URL=sqlite:////tmp/blockwart.sqlite3 \
  blockwart-db upgrade
BLOCKWART_DATABASE_URL=sqlite:////tmp/blockwart.sqlite3 \
  uvicorn blockwart.main:app --host 127.0.0.1 --port 8000
```

This starts in fail-closed read-only mode. UI writes require an admin token of at least 32
characters supplied through the protected runtime environment:

```bash
BLOCKWART_DATABASE_URL=sqlite:////tmp/blockwart.sqlite3 \
  blockwart-db upgrade
BLOCKWART_DATABASE_URL=sqlite:////tmp/blockwart.sqlite3 \
BLOCKWART_ADMIN_TOKEN="$BLOCKWART_RUNTIME_ADMIN_TOKEN" \
  uvicorn blockwart.main:app --host 127.0.0.1 --port 8000
```

`BLOCKWART_RUNTIME_ADMIN_TOKEN` in this example must itself come from the runtime secret store. Do
not put its value into Git, compose files, documentation, issue comments, shell history, or the
Blockwart database.

## Container Example

The example compose file binds only to localhost:

```bash
BLOCKWART_BUILD_REVISION="$(git rev-parse HEAD)" \
  docker compose -f compose.example.yaml build
docker compose -f compose.example.yaml run --rm blockwart \
  blockwart-seed --create-schema --seed seeds/pilot_objects.yaml
docker compose -f compose.example.yaml up
```

This is an example only. It does not set up TLS, backups, monitoring, or service registration.
Leave `BLOCKWART_ADMIN_TOKEN` unset for read-only use, or inject it through the deployment secret
store before using the UI write paths.

The image command is `blockwart-start`. It runs the packaged Alembic upgrade against the effective
`BLOCKWART_DATABASE_URL`, verifies that the resulting revision equals the packaged head, and only
then replaces itself with Uvicorn. A migration, schema-adoption, connection, or revision error
stops startup with a redacted `startup_error=database_migration_failed`; the application is never
served against an unchecked schema.

The image healthcheck calls `/api/health/ready`. An unhealthy result therefore means the process
may still be alive but must not receive normal traffic.

## Liveness And Readiness

The health endpoints have separate operational meanings:

- `GET /api/health` and `GET /api/health/live` return `200` when the application process can
  answer HTTP. They deliberately do not touch the database.
- `GET /api/health/ready` returns `200` only when `SELECT 1` succeeds, the current Alembic revision
  exactly matches the packaged head, SQLite has the expected connection settings, and a
  `BEGIN IMMEDIATE`/`ROLLBACK` write-lock probe succeeds without changing data.

Readiness failures return `503` with a stable `error_code`, check statuses, package version, build
revision, and current schema revision where available. The public response never includes database
paths, SQL text, driver exceptions, or credentials. Expected codes are
`database_missing`, `database_unavailable`, `schema_revision_mismatch`,
`sqlite_configuration_invalid`, and `database_not_writable`.

Example:

```bash
curl -fsS http://127.0.0.1:8000/api/health/live
curl -fsS http://127.0.0.1:8000/api/health/ready
```

These endpoints provide probes, not a monitoring system. Alerting, dashboards, and external
service registration remain deployment concerns.

## SQLite Migration And Rollback

Treat application code and its database revision as one release. Before updating the live image:

1. Record the current application commit and image ID.
2. Create a SQLite online backup outside `/opt/blockwart-data`.
3. Run `PRAGMA integrity_check` against the backup and record the catalog, relationship, and audit
   counts.
4. Keep the previous image under a release-specific rollback tag.
5. Start the new image and require `blockwart-db check` plus the normal application smoke tests.

Example host-side backup:

```bash
install -d -m 0750 /opt/blockwart-backups
sqlite3 /opt/blockwart-data/blockwart.sqlite3 \
  ".backup '/opt/blockwart-backups/blockwart-before-upgrade.sqlite3'"
sqlite3 /opt/blockwart-backups/blockwart-before-upgrade.sqlite3 \
  "PRAGMA integrity_check;"
```

Also run `blockwart-db upgrade` and `/api/health/ready` against a disposable restored copy before
depending on a backup. This proves that the backup is readable, migratable, and compatible with
the current image without mutating the live database.

For rollback, stop Blockwart first, preserve the failed database for diagnosis, restore the
verified pre-upgrade backup, select the matching previous image, and start the service again. Do
not run an automatic Alembic downgrade on live data.

An existing unversioned Blockwart database is adopted only if Alembic finds no model/schema
differences. The adopter stamps the known initial revision and then applies later revisions
normally. Unknown JSON fields are data and remain untouched. Missing tables, columns or indexes,
extra schema objects, an unknown revision, and unwritable targets all abort startup instead of
being guessed or repaired.

## Runtime Configuration

Required:

- `BLOCKWART_DATABASE_URL`

Optional:

- `BLOCKWART_ENV`
- `BLOCKWART_BUILD_REVISION` (default `unknown`; inject the deployed Git commit at image build)
- `BLOCKWART_SECRET_REFERENCE`
- `BLOCKWART_ADMIN_TOKEN`
- `BLOCKWART_ADMIN_SESSION_TTL_SECONDS` (default `3600`, allowed `300..86400`)
- `BLOCKWART_ADMIN_COOKIE_SECURE` (default `false`; set `true` behind HTTPS)
- `BLOCKWART_SQLITE_BUSY_TIMEOUT_MS` (default `5000`, allowed `100..60000`)
- `BLOCKWART_SQLITE_WAL_ENABLED` (default `true`)

Every SQLite connection enables foreign-key enforcement and applies the configured busy timeout.
The five-second default absorbs short UI/import lock contention while still failing a stuck writer
within a bounded interval. Persistent database files use WAL by default so readers can proceed
during a write transaction. In-memory SQLite retains its compatible `memory` journal mode.
Disabling WAL selects SQLite's `DELETE` journal for an explicitly incompatible filesystem, but
reduces concurrency and must be documented in the deployment configuration.

`BLOCKWART_SECRET_REFERENCE` is a reference label only. It must not contain a raw token, password,
private key, cookie, or `.env` body.

`BLOCKWART_ADMIN_TOKEN` is the one runtime secret. It is not written to the database, logs, HTML,
URLs, or the session cookie. Missing or empty configuration disables every UI write. A successful
unlock at `/admin` creates a time-limited HMAC-signed cookie with `HttpOnly` and `SameSite=Strict`;
rotating the token invalidates existing sessions. Logout deletes the cookie.

The catalog and agent APIs remain read-only even while the UI is unlocked. Their OpenAPI contract
contains no catalog mutation operation.

The token and session cookie still traverse the network during browser use. On an untrusted network,
serve Blockwart through HTTPS and set `BLOCKWART_ADMIN_COOKIE_SECURE=true`.

## Agent Access

The read-only agent API lives under `/api/agent`. The local MCP wrapper uses that API through
`BLOCKWART_API_BASE_URL`. Deployment of the MCP wrapper into OpenClaw/Gateway config is a separate
approval step.
