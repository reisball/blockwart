# MCP Server

Blockwart ships a local MCP stdio server named `blockwart-mcp`. Transport and protocol lifecycle
are implemented by the official Python MCP SDK.

It wraps the object-authorized v1 API:

- blockwart.search -> GET /api/v1/objects
- blockwart.get_object_context -> GET /api/v1/objects/{object_id}
- blockwart.get_context -> GET /api/v1/context
- blockwart.create_child -> POST /api/v1/objects/{parent_id}/children
- blockwart.update_object -> PUT /api/v1/objects/{object_id}
- blockwart.delete_object -> DELETE /api/v1/objects/{object_id}
- blockwart.create_relationship -> POST /api/v1/objects/{object_id}/relationships
- blockwart.delete_relationship -> DELETE /api/v1/objects/{object_id}/relationships
- blockwart.get_object_access -> GET /api/v1/objects/{object_id}/access
- blockwart.search_principals -> GET /api/v1/objects/{object_id}/access/principals
- blockwart.list_admin_principals -> GET /api/v1/admin/principals
- blockwart.get_admin_principal -> GET /api/v1/admin/principals/{principal_id}
- blockwart.preview_grant_scope -> GET /api/v1/objects/{object_id}/access/preview
- blockwart.create_grant -> POST /api/v1/objects/{object_id}/access/grants
- blockwart.update_grant -> PUT /api/v1/objects/{object_id}/access/grants/{grant_id}
- blockwart.revoke_grant -> DELETE /api/v1/objects/{object_id}/access/grants/{grant_id}

`blockwart.search` and `blockwart.get_context` accept `host`, `system`, `network`, `device`, and
`service` as kinds. Both tools also forward v1's structured `parent`, `ip`, `port`,
`endpoint_type`, `protocol`, `exposure`, `status`, `lifecycle`, and `health`
filters plus canonical `source_type` and computed `stale`, `cursor`, `sort`,
`direction`, and optional `include_total`.
Resolved context comes from the same service implementation used by REST.
All tools require a service-account token and receive exactly that
principal's authorized detail/stub projection.

Each tool call validates an upstream correlation ID or generates one, then sends
`X-Correlation-ID` on every outgoing API request. API security events and object
audits therefore retain the same context. Production MCP errors and logs contain
only operation, stable code, channel, and correlation ID; exception text,
tracebacks, headers, cookies, tokens, and payloads are excluded.

Write tools use the same command, validation, policy, ETag, idempotency, audit,
and rollback implementation as REST and the browser UI. Update and delete
arguments carry the last full-read `if_match` ETag. Child creation carries an
`idempotency_key`; credentials remain runtime configuration and are never tool
arguments. Delete tools publish MCP's destructive annotation.

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
