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
  uvicorn blockwart.main:app --host 127.0.0.1 --port 8000
```

This starts in fail-closed read-only mode. UI writes require an admin token of at least 32
characters supplied through the protected runtime environment:

```bash
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
docker compose -f compose.example.yaml build
docker compose -f compose.example.yaml run --rm blockwart \
  blockwart-seed --create-schema --seed seeds/pilot_objects.yaml
docker compose -f compose.example.yaml up
```

This is an example only. It does not set up TLS, backups, monitoring, or service registration.
Leave `BLOCKWART_ADMIN_TOKEN` unset for read-only use, or inject it through the deployment secret
store before using the UI write paths.

## Runtime Configuration

Required:

- `BLOCKWART_DATABASE_URL`

Optional:

- `BLOCKWART_ENV`
- `BLOCKWART_SECRET_REFERENCE`
- `BLOCKWART_ADMIN_TOKEN`
- `BLOCKWART_ADMIN_SESSION_TTL_SECONDS` (default `3600`, allowed `300..86400`)
- `BLOCKWART_ADMIN_COOKIE_SECURE` (default `false`; set `true` behind HTTPS)

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
