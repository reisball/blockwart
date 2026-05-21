# API v1

Blockwart exposes the stable product API under `/api/v1`.

The REST API is the neutral data layer. It answers what Blockwart stores and returns
machine-readable canonical objects. Agent workflow guidance belongs in MCP; REST only provides
the data and one prepared object view that MCP can reuse.

## Object List

`GET /api/v1/objects`

Query parameters:

- `q`: optional search term for id, label, or summary
- `kind`: optional object kind filter
- `status`: optional status filter
- `limit`: optional limit, 1..200, default 100

The response is a list of canonical catalog objects.

## Object Detail

`GET /api/v1/objects/{id}`

Returns one canonical catalog object:

- `id`
- `kind`
- `label`
- `status`
- `summary`
- `data`
- timestamps

For public infrastructure objects (`host`, `system`, `netzwerk`, `service`), v1 responses do
not expose legacy standalone `data.ports`. Use `data.endpoints[]`.

## Object Create

`POST /api/v1/objects`

Creates a new object from a full canonical object payload. Duplicate IDs return `409`.

The payload is validated against schema v1 before it is stored.

## Object Patch

`PATCH /api/v1/objects/{id}`

Updates controlled object fields:

- `label`
- `status`
- `summary`
- `data`

When `data` is supplied, it replaces the object's complete data block and is validated against
schema v1 before it is stored. This keeps partial writes explicit and avoids unvalidated deep merge
behavior.

## Comments

`GET /api/v1/objects/{id}/comments`

Returns comments in display order. Legacy single `data.comment` values are returned first with
`actor: legacy`; new comments are stored as append-only entries under `data.comments`.

```json
[
  {
    "text": "Checked during import dry-run.",
    "actor": "agent:zoe",
    "created_at": "2026-05-17T21:07:00Z"
  }
]
```

`POST /api/v1/objects/{id}/comments`

Appends one comment without replacing the object's full `data` block:

```json
{
  "comment": "Checked during import dry-run.",
  "actor": "agent:zoe"
}
```

The response is the updated canonical object. Empty comments are rejected. Secret-shaped values are
rejected by the same payload guard used for catalog objects.

## Endpoints Replace

`PUT /api/v1/objects/{id}/endpoints`

Replaces only `data.endpoints` on an existing public object:

```json
{
  "endpoints": [
    {
      "type": "REST API",
      "url": "http://192.168.50.83:5678/api",
      "port": 5678
    }
  ]
}
```

Allowed endpoint types are `Web`, `REST API`, `MCP`, `HEC`, and `SSH`. The complete object
is revalidated after replacement.

`PUT /api/v1/objects/{id}/ports` returns `422`. Standalone ports are no longer writable through
the API.

## Access Methods Replace

`PUT /api/v1/objects/{id}/access-methods`

Replaces only `data.access_methods` on an existing object:

```json
{
  "access_methods": [
    {
      "id": "web-ui",
      "type": "web",
      "endpoint": "http://192.168.50.83:5678",
      "username": "",
      "credential_reference": "credential_reference:n8n-owner-login"
    }
  ]
}
```

Credential values are never accepted here. Store only `credential_reference` values.

## Interfaces Replace

`PUT /api/v1/objects/{id}/interfaces`

Replaces `data.network.addresses` on an existing host, system, or network object:

```json
{
  "interfaces": [
    {
      "id": "eth0",
      "name": "eth0",
      "ip": "192.168.50.83",
      "mac": "02:42:AC:11:00:7F"
    }
  ]
}
```

Services cannot store interfaces. They inherit interfaces from the linked system, so this endpoint
returns `422` for service objects.

## Relationships Replace

`PUT /api/v1/objects/{id}/relationships`

Sets the canonical parent reference for system and service objects.

For systems:

```json
{
  "host_ref": "host:fabrik"
}
```

For services:

```json
{
  "system_ref": "system:n8n"
}
```

The referenced object must exist and must match the expected kind. Invalid reference kinds return
`422`; missing referenced objects return `404`.

## Agent View

`GET /api/v1/objects/{id}/agent-view`

Returns one prepared read-only object view for agents and MCP wrappers:

- `identity`: id, typed ref, kind, label, status, summary
- `hierarchy`: resolved host/system/service summaries
- `data`: sanitized canonical object data
- `resolved`: inherited fields, for example a service's system hostname and network data
- `network`: object-owned addresses and endpoints
- `endpoints`: object-owned endpoints
- `access_methods`: object-owned access methods
- `credential_references`: reference IDs only, never secret values
- `relationships`: direct relationship edges
- `links`: next useful API calls

The route accepts a raw id such as `n8n` or a typed reference such as `system:n8n`.

## Writable Contract

The API stores canonical schema v1 objects. These are the intended write surfaces:

| Kind | Writable via subresource endpoints | Parent relationship |
| --- | --- | --- |
| `host` | `interfaces`, `endpoints`, `access_methods` | none |
| `netzwerk` | `interfaces`, `endpoints`, `access_methods` | none |
| `system` | `interfaces`, `endpoints`, `access_methods` | `host_ref` |
| `service` | `endpoints`, `access_methods` | `system_ref` |

Services intentionally cannot write these inherited fields:

- `hostname`
- `platform`
- `os`
- `os_version`
- `specs`
- `interfaces`
- `network`
- `ports`

Use `PATCH /api/v1/objects/{id}` only when replacing the complete `data` block is intended.
For targeted writes, prefer the subresource endpoints above, including comments, endpoints, access
methods, interfaces, and relationships.

## Error Semantics

- `400`: malformed request shape or path/payload id mismatch
- `404`: object or referenced object not found
- `409`: duplicate object id on create
- `422`: schema v1 violation or unsupported write for this object kind

## Compatibility

The existing `/api/objects` and `/api/agent/*` routes remain available for now. New consumers
should use `/api/v1`.
