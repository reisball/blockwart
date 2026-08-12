# Agent API

Blockwart exposes a read-only compatibility agent namespace under /api/agent.

The namespace is intentionally separate from the catalog read API. Authorized
machine commands live in `/api/v1` and are documented in `api-v1.md`; agents
and integrations never resolve credential values. Every request requires a service-account bearer
token and is filtered by its current object grants. Catalog changes are
restricted to the authenticated `/api/v1`, MCP, and UI command surfaces.

The catalog model is the faithful stored-object projection: validated data, canonical asset and
placement state, timestamps, parent path, and safe integrity diagnostics. Agent context is a
different compact projection with resolved endpoint, network, dependency, child, and
credential-reference summaries plus defensive secret redaction. Both use the same canonical
placement graph; neither response shape is derived from the HTML UI. See `read-models.md`.

`/api/agent` is the compatibility namespace. New clients should use the
cursor-paginated `/api/v1/objects`, `/api/v1/context`, and object-resource
endpoints documented in `api-v1.md`. Both namespaces delegate to the same
Agent query service.

Authorization is projection-based: `read` returns the documented summary or
context, `discover` returns only a strict identity/placement/capability stub,
and no `discover` is indistinguishable from an absent object. Detail filters
never evaluate stub-only objects.

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
- decision_status: optional exact canonical Decision lifecycle value
- applies_to: optional exact authorized asset `kind:id` Decision scope
- source_type: optional exact `unknown`, `manual`, `import`, or `discovery`
- stale: optional exact computed freshness state
- limit: optional result limit, 1..50, default 10

The parent filter matches the complete canonical parent path, not only the immediate parent.
Lifecycle and health are canonical catalog columns, not free-form object-data fields. Asset writes
that omit them keep an existing canonical pair; new legacy-style writes are mapped
deterministically from `status`. See `domain-model.md`.

### GET /api/agent/objects/{object_id}

Returns one object as agent context:

- summary fields
- the monotone revision and current strong `etag` (`"rev-N"`), byte-identical
  to the HTTP `ETag` header and reusable unchanged as `If-Match`
- sanitized data
- raw direct relationships
- canonical root-to-parent path and immediate parent
- direct placement children
- normalized endpoints with stable ID, capability, URL/host/port, application
  protocol, TCP/UDP transport, exposure and optional health URL
- source references, last update timestamp, and structured upstream/downstream dependencies
- canonical provenance and computed freshness
- extracted credential-reference IDs
- the five newest authorized object comments as exact source plus format

Placement resolution uses only canonical `hosts` relationships. It supports
`host -> system -> service` as well as a service placed directly on a host. The
catalog REST API exposes the same `parent_path`; the UI and MCP use the same
placement graph. Legacy `provides` and `data.system_id` values are migrated by
Alembic and are not read fallbacks.

### GET /api/agent/objects/{object_id}/network-topology

Returns the same authorized network-topology resource as API v1. It resolves
direct host/system attachments, placement inheritance for systems and services,
all readable uplink alternatives, completion state, and deterministic bounds.
Network neighbors and edge metadata require `read` on both endpoints; a
discover-only anchor is concealed. New integrations may use the equivalent
`/api/v1/objects/{object_id}/network-topology` resource directly.

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
  health, decision_status, applies_to, source_type, stale: same structured filters as search
- limit: optional object limit, 1..20, default 5

Search and context use the same resolver and filter semantics. All Agent API
routes remain GET-only and require
`Authorization: Bearer <service-account token>`.

Every readable full context in this bundle carries the same strong `etag`
field as the single-object resource. Discover-only stubs expose neither
`revision` nor body `etag`; the single-object stub response also omits the HTTP
`ETag` header. Concealed objects remain omitted from collections and return
the same `404` as absent IDs on direct reads.

Readable contexts expose `recent_comments`; discover-only stubs do not. The
complete timeline and append command live only in REST v1 and MCP. Agent
responses return Markdown or legacy plain-text source, never rendered HTML;
see `object-comments.md`.

All Agent timestamps use RFC3339 UTC with `Z`. Every summary and context object also exposes
`record_state` plus `diagnostics`. A damaged `data_json` row remains discoverable by ID, label, or
summary, but its data is returned as an empty object with a `corrupt_record` diagnostic; raw broken
JSON is never returned. See `api-boundary-contract.md`.

`updated_at`, `observed_at`, `verified_at`, and `stale_after` have distinct
meanings. The canonical header, migration rules, manual-override behavior, and
freshness calculation are documented in `provenance.md`.

## Secret Handling

Agent responses are defensive:

- credential references are returned as reference strings only
- raw credential values are never resolved
- secret-shaped keys and values are redacted in agent output as [redacted-secret-field]

This is a last-resort guard. Normal writes should still reject secret-shaped payloads before data
enters the catalog.

## MCP Direction

The MCP server wraps these read-only operations through `/api/v1` while
preserving its established `results` and `objects` payload fields:

- blockwart.search
- blockwart.get_object_context
- blockwart.get_object_contexts
- blockwart.get_context

The MCP server also exposes authorized create, update, relationship, and delete
commands through the shared `/api/v1` command surface. See `mcp.md`.
