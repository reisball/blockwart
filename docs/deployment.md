# Deployment Readiness

Blockwart is prepared for controlled deployment, but this repository does not deploy or register a
persistent service by itself.

## Approval Gate

Before a real deployment, decide and document:

- target host or container
- bind address and port
- backup location and retention
- authentication boundary
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

## Container Example

The example compose file binds only to localhost:

```bash
docker compose -f compose.example.yaml build
docker compose -f compose.example.yaml run --rm blockwart \
  blockwart-seed --create-schema --seed seeds/pilot_objects.yaml
docker compose -f compose.example.yaml up
```

This is an example only. It does not set up TLS, backups, authentication, monitoring, or service
registration.

## Runtime Configuration

Required:

- `BLOCKWART_DATABASE_URL`

Optional:

- `BLOCKWART_ENV`
- `BLOCKWART_SECRET_REFERENCE`

`BLOCKWART_SECRET_REFERENCE` is a reference label only. It must not contain a raw token, password,
private key, cookie, or `.env` body.

## Agent Access

The read-only agent API lives under `/api/agent`. The local MCP wrapper uses that API through
`BLOCKWART_API_BASE_URL`. Deployment of the MCP wrapper into OpenClaw/Gateway config is a separate
approval step.
