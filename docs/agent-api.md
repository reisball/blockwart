# Agent API

Blockwart exposes a read-only agent namespace under /api/agent.

The namespace is intentionally separate from the catalog read API. Both API surfaces are read-only:
agents and integrations can search and retrieve context, but they cannot create, update, delete, or
resolve credential values. Catalog changes are restricted to authenticated UI form routes.

## Endpoints

### GET /api/agent/search

Returns compact object summaries with canonical parent, explicit placement state, resolved
IPs/hostnames, primary endpoint, lifecycle, and health where those values are available.

Query parameters:

- q: optional search term
- kind: optional object kind filter
- parent: optional typed ancestor reference such as `host:fabrik-01`
- ip: optional exact resolved IP address
- port: optional exact endpoint or declared port
- endpoint_type: optional exact endpoint capability such as `REST API`, `SMB`, or `HTTP`
- protocol: optional exact application protocol such as `https`, `ssh`, or `smb`
- exposure: optional exact `loopback`, `lan`, `vpn`, `internal`, `public`, or `unknown`
- status: optional catalog status
- lifecycle: optional exact `planned`, `active`, or `retired`
- health: optional exact `unknown`, `healthy`, `degraded`, `down`, or `maintenance`
- limit: optional result limit, 1..50, default 10

The parent filter matches the complete canonical parent path, not only the immediate parent.
Lifecycle and health are canonical catalog columns, not free-form object-data fields. Asset writes
that omit them keep an existing canonical pair; new legacy-style writes are mapped
deterministically from `status`. See `domain-model.md`.

### GET /api/agent/objects/{object_id}

Returns one object as agent context:

- summary fields
- sanitized data
- raw direct relationships
- canonical root-to-parent path and immediate parent
- direct placement children
- normalized endpoints with stable ID, capability, URL/host/port, application
  protocol, TCP/UDP transport, exposure and optional health URL
- source references, last update timestamp, and structured upstream/downstream dependencies
- extracted credential-reference IDs

Placement resolution uses only canonical `hosts` relationships. It supports
`host -> system -> service` as well as a service placed directly on a host. The
catalog REST API exposes the same `parent_path`; the UI and MCP use the same
placement graph. Legacy `provides` and `data.system_id` values are migrated by
Alembic and are not read fallbacks.

`placement_state` is derived as `root` for hardware, `assigned` for a system or
service with one canonical parent, `unassigned` for an explicit unassigned
marker without a parent, and `unknown` for legacy inventory that has neither a
parent nor an explicit decision. MCP returns the same field unchanged.

Dependency resolution uses only canonical `depends_on` relationships. The source object depends on
the target; Agent API `upstream` lists outgoing targets and `downstream` lists incoming sources.
Legacy `data.dependencies` is migrated and rejected on new object writes.

Endpoint resolution uses the shared service-interface contract. Legacy access
method URLs are promoted into the normalized endpoint view and exact duplicate
URLs are returned once. Generic HTTP endpoints remain `HTTP`; the read layer
does not guess whether they are Web, REST, metrics, or webhooks. See
`service-interfaces.md`.

### GET /api/agent/context

Returns a small context bundle for a search query.

Query parameters:

- q: optional search term
- kind: optional object kind filter
- parent, ip, port, endpoint_type, protocol, exposure, status, lifecycle,
  health: same structured filters as search
- limit: optional object limit, 1..20, default 5

Search and context use the same resolver and filter semantics. All Agent API routes remain GET-only.

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
