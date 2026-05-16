# Blockwart

Blockwart is a small infrastructure knowledge and credential-reference platform for Kai, Zoe, and other agents.

The MVP goal is narrow:

- structured systems, services, credential references, and runbooks
- DB-backed canonical storage
- search-first human UI
- REST API for humans and integrations
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

It returns sanitized object context, relationships, and credential-reference IDs only. It never
resolves credential values. See docs/agent-api.md.

A local MCP-compatible stdio wrapper is available as blockwart-mcp. See docs/mcp.md.

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
