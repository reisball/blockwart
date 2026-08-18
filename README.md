# Blockwart

Blockwart is an infrastructure knowledge base for humans and AI agents. It
keeps hosts, systems, services, networks, devices, relationships, runbook
links, and credential references in one searchable catalog.

Blockwart stores references to credentials, never passwords, tokens, private
keys, or other secret values.

## Current status

The current Development/Staging pilot is deployed and accepted. The GitHub
repository `reisball/blockwart` and its `main` branch are canonical; the former
Gitea repository is retained only as a read-only rollback source.

The pilot is not a production service and this repository does not deploy it
automatically.

## What Blockwart can do

- model infrastructure as typed catalog objects and validated relationships;
- describe bounded internal service components and their local dependencies;
- record canonical Decisions with explicit lifecycle, asset scope, related knowledge, and
  cycle-safe supersession links;
- keep canonical Project research, experiments, migrations, implementations, and incident
  reviews as structured reviewed knowledge with safe evidence and typed links;
- keep canonical Runbook operating and recovery contracts with inert exact commands,
  explicit verification, distinct rollback/recovery, and cycle-safe typed links;
- show placement, device, dependency, and network topology in the human UI;
- search and read authorized context through REST and MCP;
- create, update, relate, and delete catalog objects through authorized UI,
  REST, and MCP commands;
- keep an append-only, Markdown-capable operational comment timeline per
  object through UI, REST, and MCP;
- manage human and service-account identities separately from object grants;
- enforce object-scoped RBAC, optimistic concurrency, idempotency, audit, and
  last-owner safeguards;
- import reviewed infrastructure data from Markdown/YAML with a dry-run-first
  workflow;
- export generated Markdown/YAML without exporting credential values.

## Interfaces

| Interface | Use it for | Contract |
|---|---|---|
| Human UI | Search, catalog work, access management, and administration | [Authentication and RBAC](docs/auth-rbac.md) |
| REST API v1 | Stable object-authorized reads and commands | [API v1](docs/api-v1.md) |
| Agent API | Read-only compatibility access for existing clients | [Agent API](docs/agent-api.md) |
| MCP (`blockwart-mcp`) | Agent-native catalog reads and authorized commands over stdio | [MCP server](docs/mcp.md) |
| Object comments | Human and agent operational history, separate from audit | [Object comments](docs/object-comments.md) |
| Import CLI | Reviewed TOOLS.md/YAML ingestion without resolving secrets | [Markdown import](docs/markdown-import.md) |
| Knowledge plan CLI | Deterministic private-source classification with no catalog writes | [Knowledge planning](docs/knowledge-planning.md) |
| Knowledge apply CLI | Offline digest-bound reviewed apply and paired SQLite rollback | [Knowledge apply](docs/knowledge-apply.md) |

## Agent quick start

For new agent integrations, prefer `blockwart-mcp` or `/api/v1`. Both expose
the same authorization decisions and safe catalog projections.

Run the MCP server against an existing Blockwart API:

```bash
BLOCKWART_API_BASE_URL=http://127.0.0.1:8000 \
BLOCKWART_API_TOKEN_FILE=/protected/path/to/token \
blockwart-mcp
```

The service-account token must have the exact object grants required by the
requested tools. Credential references may be returned; credential values are
never resolved. See the [MCP tool list](docs/mcp.md), [REST API](docs/api-v1.md),
and [authorization model](docs/auth-rbac.md) before integrating a client.

## Local setup

Create an environment, install the development dependencies, upgrade the
database, and start the application:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --constraint requirements/dev.txt ".[dev]"
blockwart-db upgrade
uvicorn blockwart.main:app --reload
```

Database initialization, Owner bootstrap, container startup, HTTPS, readiness,
backup, and rollback are documented in [Deployment](docs/deployment.md).
Environment variables and pilot seed commands are documented in
[Configuration](docs/config.md).

## Documentation

Use the [documentation index](docs/README.md) to find the current API,
security, operations, architecture, data, and historical migration material.

For development checks and build contracts, see [CI](docs/ci.md).
Questions and tracked work belong in this repository's GitHub Issues.

## License

Blockwart is licensed under the [Apache License 2.0](LICENSE). It may be used,
modified, and distributed for private or commercial purposes under that
license's terms.
