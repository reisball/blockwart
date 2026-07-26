# API Boundary Contract

Blockwart's catalog and Agent APIs use one external time, error, and record-integrity
contract. The HTML UI remains a separate surface.

## Timestamps

All externally returned catalog, Agent, MCP, and audit timestamps are RFC3339 UTC
strings ending in `Z`, including microseconds:

```text
2026-07-22T21:07:38.123456Z
```

SQLite continues to store application timestamps without timezone metadata. Blockwart
defines those existing naive values as UTC and formats them accordingly. New
application timestamps are also produced from UTC before their timezone marker is
removed for storage. No local timezone is inferred.

## REST Errors

Failed REST requests under `/api` use this envelope:

```json
{
  "error": {
    "code": "not_found",
    "message": "Catalog object not found",
    "correlation_id": "0cbb940f-a9e9-4078-9309-549ab5eb433d"
  }
}
```

Validation failures may add safe `details` containing only the field location, public
message, and validation type. The rejected input and exception context are not copied
into the response.

Stable codes currently include:

- `validation_error`
- `not_found`
- `conflict`
- `forbidden`
- `method_not_allowed`
- `db_unavailable`
- `service_unavailable`
- `internal_error`
- `http_error`

Every API response carries the same ID in `X-Correlation-ID`. A caller-supplied ID is
accepted only when it contains 1 to 64 ASCII letters, digits, dots, underscores, or
hyphens; otherwise Blockwart generates a UUID. Database diagnostics log only this
correlation ID, not SQL text, parameters, or exception details. Unexpected API
failures use the redacted `internal_error` response and are correlated the same way.

`/api/health/ready` remains an operational status document with its existing
`ReadinessOut` schema rather than an exception response.

## Corrupt Catalog Records

A catalog row whose `data_json` is invalid JSON, not a JSON object, or violates the
catalog schema is not repaired, deleted, or silently omitted. Catalog and Agent
list/search/detail reads return the row with:

```json
{
  "data": {},
  "record_state": "corrupt",
  "diagnostics": [
    {
      "code": "corrupt_record",
      "object_id": "example-id",
      "message": "Catalog object example-id has invalid data_json"
    }
  ]
}
```

The raw broken value and parser exception are never returned. Schema-invalid catalog
data is empty on the catalog API; the Agent API may retain only its sanitized form so
its existing last-resort secret redaction remains effective. Valid records use
`record_state: "valid"` and an empty diagnostics list.

## MCP Errors

The MCP wrapper keeps its local `invalid_arguments`, `tool_not_found`, and
`internal_error` contract. When the Agent API returns a structured REST error, MCP
copies only its public code, message, and validated correlation ID into the MCP tool
error. Legacy or malformed upstream errors remain the generic
`upstream_http_error`; arbitrary upstream response details are not forwarded.
