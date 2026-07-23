# Agent API

Blockwart exposes a read-only agent namespace under /api/agent.

The namespace is intentionally separate from the catalog read API. Both API surfaces are read-only:
agents and integrations can search and retrieve context, but they cannot create, update, delete, or
resolve credential values. Catalog changes are restricted to authenticated UI form routes.

## Endpoints

### GET /api/agent/search

Returns compact object summaries.

Query parameters:

- q: optional search term
- kind: optional object kind filter
- limit: optional result limit, 1..50, default 10

### GET /api/agent/objects/{object_id}

Returns one object as agent context:

- summary fields
- sanitized data
- relationships
- extracted credential-reference IDs

### GET /api/agent/context

Returns a small context bundle for a search query.

Query parameters:

- q: optional search term
- kind: optional object kind filter
- limit: optional object limit, 1..20, default 5

## Secret Handling

Agent responses are defensive:

- credential references are returned as reference strings only
- raw credential values are never resolved
- secret-shaped keys and values are redacted in agent output as [redacted-secret-field]

This is a last-resort guard. Normal writes should still reject secret-shaped payloads before data
enters the catalog.

## MCP Direction

The first MCP server should wrap these read-only operations:

- blockwart.search
- blockwart.get_object_context
- blockwart.get_context

Writable MCP tools are out of scope until auth, review gates, and audit requirements are defined.
