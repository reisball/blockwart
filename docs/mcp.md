# MCP Server

Blockwart ships a local MCP stdio server named `blockwart-mcp`. Transport and protocol lifecycle
are implemented by the official Python MCP SDK.

It wraps only the read-only v1 API:

- blockwart.search -> GET /api/v1/objects
- blockwart.get_object_context -> GET /api/v1/objects/{object_id}
- blockwart.get_context -> GET /api/v1/context

There are no writable MCP tools.

`blockwart.search` and `blockwart.get_context` accept `host`, `system`, `network`, and `service`
as kinds. Both tools also forward v1's structured `parent`, `ip`, `port`,
`endpoint_type`, `protocol`, `exposure`, `status`, `lifecycle`, and `health`
filters plus canonical `source_type` and computed `stale`, `cursor`, `sort`,
`direction`, and optional `include_total`.
Resolved context comes from the same service implementation used by REST.

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

The MCP wrapper never resolves credential values. It only returns whatever the read-only v1 API
returns: sanitized object context, relationships, and credential-reference IDs.
Canonical provenance is returned unchanged from v1; secret-shaped stored
provenance is handled by the same safe record-integrity boundary.

The optional bearer token currently authenticates only endpoints that demand
it, such as `/api/v1/auth/me`. Existing catalog tools remain read-only and are
not yet object-filtered. Writable tools, credential resolution, and Gateway
registration require their dedicated implementation and approval.

## Error Contract

Local tool validation, unknown-tool, and internal failures use stable public MCP error codes and do
not include exception text. Structured Agent API errors preserve only the public REST code, message,
and validated correlation ID. Legacy or malformed upstream error bodies become
`upstream_http_error`; arbitrary upstream details are not forwarded. Catalog record-integrity
markers and RFC3339 UTC timestamps pass through unchanged. See `api-boundary-contract.md`.
