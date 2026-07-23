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
python -m pip install -e ".[dev]"
```

Run the app:

```bash
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

Run checks:

```bash
pytest
python -m compileall src
```

## Agent Read API

The first agent-facing surface is read-only and lives under /api/agent:

- GET /api/agent/search
- GET /api/agent/objects/{object_id}
- GET /api/agent/context

It returns sanitized object context, resolved parent paths, children, network/endpoint summaries,
and credential-reference IDs only. Structured read filters are available for placement, IP, port,
status, lifecycle, and health. It never resolves credential values. See docs/agent-api.md.

The catalog REST API is also read-only. Object changes are available only through authenticated
UI form routes.

A local MCP-compatible stdio wrapper is available as blockwart-mcp. See docs/mcp.md.

## Markdown Import

Blockwart can import the current workspace operations index from TOOLS.md with a dry-run-first CLI.
Database writes require the explicit apply flag. The importer creates system objects and
credential-reference pointers only; it does not resolve or store secret values. See
docs/markdown-import.md.

## Deployment Readiness

Blockwart includes a Dockerfile, a localhost-only compose example, and deployment notes. They are
for controlled rollout preparation only; no persistent service or gateway registration is created
by this repository. See docs/deployment.md.

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
