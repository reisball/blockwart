# MCP Server

Blockwart ships a local MCP stdio server named `blockwart-mcp`. Transport and protocol lifecycle
are implemented by the official Python MCP SDK.

It wraps only the read-only v1 API:

- blockwart.search -> GET /api/v1/objects
- blockwart.get_object_context -> GET /api/v1/objects/{object_id}
- blockwart.get_context -> GET /api/v1/context

There are no writable MCP tools.

`blockwart.search` and `blockwart.get_context` accept `host`, `system`, `netzwerk`, and `service`
as kinds. Both tools also forward v1's structured `parent`, `ip`, `port`,
`endpoint_type`, `protocol`, `exposure`, `status`, `lifecycle`, and `health`
filters plus `cursor`, `sort`, `direction`, and optional `include_total`.
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

## Secret Handling

The MCP wrapper never resolves credential values. It only returns whatever the read-only v1 API
returns: sanitized object context, relationships, and credential-reference IDs.

Writable tools, credential resolution, and Gateway registration require separate design and approval.

## Error Contract

Local tool validation, unknown-tool, and internal failures use stable public MCP error codes and do
not include exception text. Structured Agent API errors preserve only the public REST code, message,
and validated correlation ID. Legacy or malformed upstream error bodies become
`upstream_http_error`; arbitrary upstream details are not forwarded. Catalog record-integrity
markers and RFC3339 UTC timestamps pass through unchanged. See `api-boundary-contract.md`.
