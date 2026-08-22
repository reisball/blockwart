# API Boundary Contract

Blockwart's v1, catalog-compatibility, and Agent-compatibility APIs use one
external time, error, and record-integrity contract. The HTML UI remains a
separate surface.

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

Validation failures may add safe `details`. Each detail carries exactly the
canonical published fields, in this order:

- `code`: a stable machine-readable violation type from the schema projection's
  `violation_policy` (for example `required_field_missing`, `value_not_allowed`,
  `type_mismatch`, `forbidden_key`, or `invalid_value` for any unrecognized
  rejection);
- `location`: the rejected path inside the request (for example `body.data.network.category`);
- `message`: the published description of the violation, regenerated from the
  domain violation catalog;
- `path`: the canonical path the domain rejected. That is the catalog data path
  for an object write (for example `data.network.category`) and the
  relationship command path for a relationship write (`relation_type`,
  `from_ref`, `to_ref`, `metadata`, or `metadata.<field>`), or `null` when a
  rejection did not map to a canonical path;
- `rule`: the published schema-rule name when a schema postcondition rejected
  the write (for example `reject_credential_value_keys`), or `null` otherwise.

One narrowly scoped exception exists for a rejected search page size on
`/api/v1/objects`, `/api/v1/context`, `/api/agent/search`,
`/api/agent/context`, `blockwart.search`, and `blockwart.get_context`. That
single detail keeps all canonical fields above and adds:

- `field`: always the literal `limit`;
- `minimum` and `maximum`: the server-declared allowed range of that resource;
- `received`: the sent value re-derived as a bounded integer, or `null` when it
  is not a plain integer within the published bound.

Nothing else is enriched. Every other rejected value — including a rejected
search term, filter, or cursor on the same request — keeps exactly the
canonical fields and is never echoed, so the global validation contract is
unchanged.

These are the same fields `blockwart.describe_schema` publishes in its
`violation_policy` and in the `rejection_policy` of its `relationships`
contract, so a client contract cannot drift from what the server actually
raises. A relationship rejection that only stored endpoints or the surrounding
edge set can decide is deliberately not a field violation: it stays
`409 conflict` without `details`, so it cannot become a probe for concealed
objects or edges. The rejected input, Pydantic validation context, boundary
validation type, exception text, and internal types are never copied into the
response; an unrecognized violation falls back to the generic `invalid_value`
code with `path` and `rule` set to `null`.

> **Development-only contract migration:** earlier revisions documented a
> `type` field that exposed the unstable internal Pydantic validation type.
> `type` has been removed and replaced by the stable `code`, `path`, and
> `rule` fields above. There is no compatibility alias for `type`; consumers
> that read `type` must switch to `code` (the stable violation type) and
> optionally `path`/`rule`.

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

Every UI and API request has one context ID, and every response carries the same ID in
`X-Correlation-ID`. A caller-supplied ID is
accepted only when it contains 1 to 64 ASCII letters, digits, dots, underscores, or
hyphens; otherwise Blockwart generates a UUID. Database diagnostics log only this
correlation ID, not SQL text, parameters, or exception details. Unexpected API
failures use the redacted `internal_error` response and are correlated the same way. UI
security events and object audits reuse the request context instead of generating a second ID.

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
error. For object-write and relationship tools (`blockwart.create_root`,
`blockwart.create_child`, `blockwart.update_object`, `blockwart.preview_object_update`,
`blockwart.create_attached_device`,
`blockwart.create_relationship`, and `blockwart.delete_relationship`) and for forwarded
upstream HTTP 422 validation failures, MCP also forwards sanitized `details` carrying
exactly the canonical fields above (`code`, `location`, `message`, `path`, `rule`).
Arbitrary upstream details, raw inputs, secret values, internal validation context,
and database diagnostics are never forwarded; an upstream detail that does not name a
published violation code is dropped. Read tools keep their
opaque `invalid_arguments` shape without `details`; the single exception is the
rejected search `limit` of `blockwart.search` and `blockwart.get_context`,
which publishes exactly the narrowly scoped limit detail above and describes no
other argument. MCP sends its validated or
generated ID on every outgoing API request. Legacy or malformed upstream errors remain
the generic `upstream_http_error`.
