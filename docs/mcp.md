# MCP Wrapper

Blockwart ships a local MCP-compatible stdio wrapper named blockwart-mcp.

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

The wrapper speaks MCP over stdio using JSON-RPC messages with Content-Length framing.

## Configuration

- BLOCKWART_API_BASE_URL: base URL for the Blockwart HTTP API
- default: http://127.0.0.1:8000

## Secret Handling

The MCP wrapper never resolves credential values. It only returns whatever the read-only Agent API
returns: sanitized object context, relationships, and credential-reference IDs.

Writable tools, credential resolution, and Gateway registration require separate design and approval.
