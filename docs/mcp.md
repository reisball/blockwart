# MCP Server

Blockwart ships a local MCP stdio server named `blockwart-mcp`. Transport and protocol lifecycle
are implemented by the official Python MCP SDK.

It wraps the object-authorized v1 API:

- blockwart.describe_schema -> local projection of the canonical domain schema (no API call)
- blockwart.search -> GET /api/v1/objects
- blockwart.get_object_context -> GET /api/v1/objects/{object_id}
- blockwart.list_comments -> GET /api/v1/objects/{object_id}/comments
- blockwart.list_audit_events -> GET /api/v1/objects/{object_id}/audit-events
- blockwart.add_comment -> POST /api/v1/objects/{object_id}/comments
- blockwart.get_context -> GET /api/v1/context
- blockwart.create_child -> POST /api/v1/objects/{parent_id}/children
- blockwart.create_root -> POST /api/v1/roots
- blockwart.update_object -> PUT /api/v1/objects/{object_id}
- blockwart.delete_object -> DELETE /api/v1/objects/{object_id}
- blockwart.create_relationship -> POST /api/v1/objects/{object_id}/relationships
- blockwart.delete_relationship -> DELETE /api/v1/objects/{object_id}/relationships
- blockwart.create_attached_device -> POST /api/v1/objects/{parent_id}/attached-devices
- blockwart.get_device_graph -> GET /api/v1/objects/{object_id}/device-graph
- blockwart.get_network_topology -> GET /api/v1/objects/{object_id}/network-topology
- blockwart.get_object_access -> GET /api/v1/objects/{object_id}/access
- blockwart.search_principals -> GET /api/v1/objects/{object_id}/access/principals
- blockwart.list_admin_principals -> GET /api/v1/admin/principals
- blockwart.get_admin_principal -> GET /api/v1/admin/principals/{principal_id}
- blockwart.preview_grant_scope -> GET /api/v1/objects/{object_id}/access/preview
- blockwart.create_grant -> POST /api/v1/objects/{object_id}/access/grants
- blockwart.update_grant -> PUT /api/v1/objects/{object_id}/access/grants/{grant_id}
- blockwart.revoke_grant -> DELETE /api/v1/objects/{object_id}/access/grants/{grant_id}

## Agent intent guide

Choose the smallest tool that directly answers the intent:

- Call `blockwart.describe_schema` before any object write. It returns the
  canonical writable kind contract (required, optional, and forbidden nested
  data paths, JSON types, enums, reference kinds, bounds, normalization,
  forbidden secret key names, lifecycle/health semantics, and one minimal
  valid example per write intent) generated from the domain schema registry
  with no catalog data or credentials, so a published contract cannot drift
  from server-side validation.
- Use `blockwart.get_object_context` when the exact object ID is already known.
- Use `blockwart.get_context` to find assets or services by name, kind, parent,
  endpoint, state, or provenance and return their full authorized details in
  the same call.
- Use `blockwart.search` when a compact candidate list is preferable to full
  detail payloads.
- Use `blockwart.get_device_graph` or `blockwart.get_network_topology` when
  relationship metadata or resolved paths are the requested detail.
- Use `blockwart.get_object_access` only for grants and effective permissions;
  access data is deliberately separate from catalog details.
- Use `blockwart.list_comments` for the complete newest-first operational
  comment timeline and `blockwart.add_comment` to append a Markdown work note.
  Use `blockwart.list_audit_events` for the separate immutable system audit
  timeline. The five newest comments are already included by
  `get_object_context`; audit events are not.

For example, `blockwart.get_context` with `q="n8n"` and `kind="service"`
returns matching service details in one MCP call. Type-specific aliases such as
`get_service_details` or `get_asset_details` would duplicate this contract and
are intentionally not added.

Every readable full detail contains `revision` and its current strong `etag`
(`"rev-N"`). Pass that `etag` byte-for-byte as `if_match` to `update_object`,
`delete_object`, relationship tools, or access-management writes. A fresh read
after a successful non-delete mutation supplies the next current value;
deletion leaves no object or successor ETag to read. Discover-only stubs
contain neither field, so they cannot be used to infer or attempt a write
precondition.

## Tool assessment

The current surface is intentionally small. `directly sufficient` means the
tool already performs one bounded intent. `response improved` means the tool
keeps its operation but now returns a complete result proof. `intent tool`
means it deliberately bundles lower-level API concerns behind one agent call.

| Tool | Primary agent intent | Assessment | Rationale |
|---|---|---|---|
| `describe_schema` | Read the writable object contract | `directly sufficient` | Projects the canonical domain schema registry locally with no catalog data, so the published contract cannot drift from server-side validation. |
| `search` | Find compact candidates | `directly sufficient` | Avoids full detail payloads when selecting an object. |
| `get_object_context` | Read one known object | `directly sufficient` | Returns full authorized catalog context and its write-ready ETag by ID. |
| `list_comments` | Read an object's operational timeline | `directly sufficient` | Preserves the dedicated newest-first, opaque-cursor resource. |
| `list_audit_events` | Read an object's system audit timeline | `directly sufficient` | Projects the existing redacted newest-first audit page without mixing in comment content. |
| `add_comment` | Append an operational work note | `directly sufficient` | Keeps Markdown source and idempotency explicit without exposing audit internals. |
| `get_context` | Find objects and read details | `directly sufficient` | Search, filters, full details, and per-object write-ready ETags already share one call. |
| `create_child` | Create a placed child | `intent tool`, `response improved` | Resolves the parent internally and proves placement, ownership, revision, and idempotency. |
| `create_root` | Create a disconnected catalog root | `intent tool`, `response improved` | Requires an already active catalog-owner principal; proves ownership, revision, idempotency, and the absence of a placement parent. Never mutates any catalog role. |
| `update_object` | Update one known object | `directly sufficient` | The explicit current ETag preserves visible optimistic concurrency. |
| `delete_object` | Delete one known object | `directly sufficient` | The destructive action and current ETag remain explicit. |
| `create_relationship` | Link existing objects | `directly sufficient` | Its response already contains the exact relationship, metadata, revision, and ETag. |
| `delete_relationship` | Unlink existing objects | `directly sufficient` | The exact edge and current ETag remain explicit. |
| `create_attached_device` | Create and attach one device | `intent tool`, `response improved` | Resolves the parent internally and proves the attachment, metadata, ownership, revision, and idempotency. |
| `get_device_graph` | Inspect device attachments | `directly sufficient` | Returns the authorized `attached_to` graph with link metadata. |
| `get_network_topology` | Inspect network paths | `directly sufficient` | Returns bounded direct or inherited paths with metadata and truncation state. |
| `get_object_access` | Inspect access | `directly sufficient` | Separates direct grants from effective permissions. |
| `search_principals` | Select a grant principal | `directly sufficient` | Keeps principal choice explicit before a security write. |
| `list_admin_principals` | List platform principals | `directly sufficient` | Provides bounded, cursor-paginated administrator discovery. |
| `get_admin_principal` | Read one platform principal | `directly sufficient` | Returns one authorized principal and its filtered assignments. |
| `preview_grant_scope` | Preview grant coverage | `directly sufficient` | Makes subtree impact visible before mutation. |
| `create_grant` | Add object access | `directly sufficient` | Principal selection and the access-resource ETag stay explicit. |
| `update_grant` | Change object access | `directly sufficient` | No hidden create/update branching or automatic CAS retry is introduced. |
| `revoke_grant` | Remove object access | `directly sufficient` | Destructive intent, grant ID, and current ETag stay explicit. |

`blockwart.search` and `blockwart.get_context` accept `host`, `system`, `network`, `device`, and
`service` as kinds. Both tools also forward v1's structured `parent`, `ip`, `port`,
`endpoint_type`, `protocol`, `exposure`, `status`, `lifecycle`, and `health`
filters plus canonical `source_type` and computed `stale`, `cursor`, `sort`,
`direction`, and optional `include_total`.
Resolved context comes from the same service implementation used by REST.
`blockwart.get_network_topology` returns the same policy-projected direct or
inherited paths, completion states, relationship metadata, and truncation signal
as API v1; it does not reconstruct topology in the MCP wrapper.
All tools require a service-account token and receive exactly that
principal's authorized detail/stub projection.

Each tool call validates an upstream correlation ID or generates one, then sends
`X-Correlation-ID` on every outgoing API request. API security events and object
audits therefore retain the same context. Production MCP errors and logs contain
only operation, stable code, channel, and correlation ID; exception text,
tracebacks, headers, cookies, tokens, and payloads are excluded.

Write tools use the same command, validation, policy, ETag, idempotency, audit,
and rollback implementation as REST and the browser UI. Update and delete
arguments carry the last full-read body `etag` unchanged as `if_match`. Child creation carries an
`idempotency_key`; credentials remain runtime configuration and are never tool
arguments. Delete tools publish MCP's destructive annotation.

`blockwart.add_comment` carries `object_id`, exact Markdown `body`, and
`idempotency_key`. It intentionally has no `if_match`: appends are independent,
advance the object revision atomically, and never overwrite timeline entries.
The result and `blockwart.list_comments` return source plus format, not rendered
HTML. Markdown safety and migration behavior are specified in
`object-comments.md`.

`blockwart.list_audit_events` carries `object_id`, `limit`, the opaque
`cursor`, and optional `include_total`. It directly projects
`GET /api/v1/objects/{object_id}/audit-events`, preserving the REST default
limit of 50, the 1..100 bounds, fixed `created_at desc` order, redacted event
shape, and page metadata. Missing, undiscoverable, and discover-only objects
all remain concealed as `404 not_found`; cursors remain bound to the principal,
effective policy, object, resource, sort, and direction. Audit events never
contain or inline operational comment bodies.

`blockwart.create_child` and `blockwart.create_attached_device` execute the
unchanged API command and resolve its authoritative typed parent inside the
same MCP call. Their additive result fields are:

- `parent_ref`: the typed parent reference;
- `relationship`: the exact `hosts` or `attached_to` edge and metadata;
- `owner_assignment`: the API command's atomic Owner/self assignment to the
  authenticated caller; and
- `revision`: the created object's explicit revision alongside the existing
  `etag`, `changed`, and `replayed` fields.

The established `catalog_object`, `etag`, `changed`, and `replayed` fields stay
unchanged for compatibility. The compact proof follows from the successful
atomic API command; neither tool loads a complete device graph or retries a
failed concurrency precondition.

`blockwart.create_root` executes the same shared `create_root` command as REST
and the browser UI. It requires an already active catalog-owner service
principal with an `mcp`-audience token and an `idempotency_key`, and it never
assigns or removes any catalog role. Its additive result fields are
`parent_ref` (always `null`, proving the disconnected root), the same
`owner_assignment` Owner/self proof, and `revision` alongside `etag`,
`changed`, and `replayed`. The catalog role itself remains read-only in MCP
through the admin principal projections.

Grant read tools expose only minimized principal identity, separated direct
grants and effective access, and safe canonical-scope previews. Grant write
tools use the same `manage_access`, Owner-only, last-owner, self-lockout,
revision, and audit rules as REST and UI. Their `if_match` argument carries the
last access-resource ETag. The service token remains runtime transport
configuration and is never accepted as a tool argument.

The two platform-admin MCP tools are read-only. They require the calling
service account to have the explicit `admin` platform role, and assignment
rows remain filtered by that same principal's object `manage_access` policy.
`blockwart.list_admin_principals` forwards `query`, `principal_type`, `active`,
`limit`, and the opaque `cursor`, returning `next_cursor` without a total count.
MCP intentionally provides no password, session-secret, or service-token-value
operation; existing object grant tools remain the only MCP assignment writes.

For compatibility, MCP output retains the established `results` and `objects`
fields. It additionally returns v1 `next_cursor`, `total`, `sort`, and
`direction` metadata.

## Local Usage

Start Blockwart separately, then run:

```bash
BLOCKWART_API_BASE_URL=http://127.0.0.1:8000 blockwart-mcp
```

The server speaks MCP over stdio. Each compact JSON-RPC message occupies exactly one UTF-8 line;
`Content-Length` headers are not used. Standard output is reserved for MCP messages. Library and
application logs go to standard error.

Protocol versions are negotiated during `initialize`. The minimum supported SDK version
(`mcp` 1.28.1) supports `2024-11-05`, `2025-03-26`, `2025-06-18`, and `2025-11-25`; its current
client and server default is `2025-11-25`. The server also handles the standard initialized
notification and ping request through the SDK protocol implementation.

## Configuration

- BLOCKWART_API_BASE_URL: base URL for the Blockwart HTTP API
- default: http://127.0.0.1:8000
- BLOCKWART_API_TOKEN_FILE: protected file containing one service-account
  bearer token; preferred for deployed runtimes and re-read on every request
- BLOCKWART_API_TOKEN: direct bearer-token environment fallback for runtimes
  without secret files

Configure at most one token source. If both are present, the wrapper fails
closed with `credential_configuration_error`. Token values are never MCP tool
arguments and never appear in tool output. File re-reading allows credential
rotation without restarting the MCP process.

Tokens used by this wrapper must be issued with the server-stored `mcp`
audience for comment writes. Revision `20260804_0014` conservatively marks all
pre-existing tokens as `api`; rotate the exact deployed MCP token with
`--audience mcp` under the normal credential/deployment approval before
enabling `blockwart.add_comment`. A caller-controlled header cannot change a
token's audience.

Bearer credentials may use plain HTTP only for loopback targets. Non-loopback
targets require HTTPS, and the MCP client rejects redirects instead of risking
credential forwarding across an origin or scheme boundary.

## Secret Handling

The MCP wrapper never resolves credential values. It only returns what the v1 API
returns: sanitized object context, relationships, and credential-reference IDs.
Canonical provenance is returned unchanged from v1; secret-shaped stored
provenance is handled by the same safe record-integrity boundary.

The bearer token authenticates every catalog tool call. Read tools are
object-filtered: no-discover objects are concealed,
discover-only objects are strict stubs, and readable objects return sanitized
detail. Write tools reject secret-shaped payloads and require the corresponding
object permission. Credential resolution and Gateway registration remain out
of scope.

## Error Contract

Local tool validation, unknown-tool, and internal failures use stable public MCP error codes and do
not include exception text. Structured Agent API errors preserve only the public REST code, message,
and validated correlation ID. Legacy or malformed upstream error bodies become
`upstream_http_error`; arbitrary upstream details are not forwarded. Catalog record-integrity
markers and RFC3339 UTC timestamps pass through unchanged. See `api-boundary-contract.md`.
