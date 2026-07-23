# MCP Server

Blockwart ships a local MCP stdio server named `blockwart-mcp`. Transport and protocol lifecycle
are implemented by the official Python MCP SDK.

It wraps only the read-only Agent API:

- blockwart.search -> GET /api/agent/search
- blockwart.get_object_context -> GET /api/agent/objects/{object_id}
- blockwart.get_context -> GET /api/agent/context

There are no writable MCP tools.

`blockwart.search` and `blockwart.get_context` accept `host`, `system`, `netzwerk`, and `service`
as kinds. Both tools also forward the Agent API's structured `parent`, `ip`, `port`, `status`,
`lifecycle`, and `health` filters. Resolved context comes from the same service implementation used
by REST.

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

The MCP wrapper never resolves credential values. It only returns whatever the read-only Agent API
returns: sanitized object context, relationships, and credential-reference IDs.

Writable tools, credential resolution, and Gateway registration require separate design and approval.
