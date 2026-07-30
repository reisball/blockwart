# API v1

Blockwart's stable machine-readable read API lives under `/api/v1`. It is
GET-only. Every request requires a service-account bearer token and is
object-authorized. Machine writes are intentionally outside this contract.

## Page contract

List resources return the same envelope:

```json
{
  "items": [],
  "next_cursor": null,
  "total": null,
  "sort": "id",
  "direction": "asc"
}
```

`next_cursor` is an opaque keyset cursor. Clients must send it back unchanged
with the same authenticated principal, effective object policy, resource,
filters, sort field, and direction. A cursor from a different principal,
policy, or query returns `400 invalid_request`; malformed cursors do not
expose their decoded contents. `limit` may change between requests.

The cursor stores the last stable sort key and a unique tie-breaker. It does
not represent a database snapshot: concurrent inserts or updates before the
cursor are not replayed, while matching rows after the cursor can appear on a
later page. A static result set is enumerated without offsets, duplicates, or
skipped equal-sort rows.

`total` is omitted as `null` by default so enumeration does not require a full
count. Set `include_total=true` when an exact authorized matching count is
needed.

## Objects

### `GET /api/v1/objects`

Returns sanitized catalog summaries. The default order is `id asc`; supported
sort fields are:

- `id`
- `label`
- `kind`
- `updated_at`

Every order uses the object ID as the final unique tie-breaker. `direction` is
`asc` or `desc`, `limit` is 1..100, and `cursor` continues a previous page.

The list accepts:

- `q`: case-insensitive ID, label, summary, or catalog-data search
- `kind`: exact object kind
- `parent`: exact typed ancestor reference, not only the immediate parent
- `ip`: exact resolved IP
- `port`: exact normalized endpoint or declared port
- `endpoint_type`: exact endpoint capability, case-insensitive
- `protocol`: exact application protocol, case-insensitive
- `exposure`: exact endpoint exposure, case-insensitive
- `status`: compatibility status
- `lifecycle`: `planned`, `active`, or `retired`
- `health`: `unknown`, `healthy`, `degraded`, `down`, or `maintenance`
- `source_type`: `unknown`, `manual`, `import`, or `discovery`
- `stale`: exact computed freshness state

Objects with `read` use the full summary. Objects with only `discover` use a
strict stub containing identity, display label, released placement, and the
caller's capabilities. Detail-field filters exclude stubs rather than probing
their hidden values; text search on stubs uses only ID, kind, and label.
Objects without `discover` are absent.

The resolver loads one bounded catalog/relationship snapshot, applies the
principal's effective policy first, and then evaluates search and structured
filters without per-object queries. Detail values are never used to prefilter
discover-only or hidden rows. This is the measured-growth path for the current
SQLite catalog; a separate authorization-aware index is not introduced
without evidence that the bounded snapshot is the bottleneck.

### `GET /api/v1/objects/{object_id}`

Returns one authorized Agent context: canonical identity and state, resolved
parent path, children, IPs, hostnames and endpoints, direct relationships,
dependency directions, source references, credential-reference IDs, and safe
record-integrity diagnostics. Every object also includes the canonical
provenance header and computed `is_stale` value described in `provenance.md`.
Credential values are never resolved. A discover-only object returns the same
strict stub as list/context reads. An object without `discover` returns
`404 not_found`, indistinguishable from an absent ID.

### `GET /api/v1/context`

Returns the same detailed contexts as a cursor page. It accepts the object-list
filters and sort fields, with a smaller limit of 1..20.

## Object resources

### `GET /api/v1/objects/{object_id}/relationships`

Returns authorized direct inbound and outbound relationship edges. Placement
edges require discoverable endpoints; every other edge requires readable
endpoints. The stable order is `relation_type`, then `from_ref`, then
`to_ref`; direction defaults to `asc`.

### `GET /api/v1/objects/{object_id}/audit-events`

Returns audit events only when the object is readable, with their stable
numeric ID and RFC3339 UTC timestamp. Discover-only and undiscoverable objects
return `404 not_found`. The stable order is `created_at`, then ID; direction
defaults to `desc`.

### `GET /api/v1/objects/{object_id}/topology`

Returns the canonical host → system → service topology for one object. This is
a single resource rather than a page.

## Errors and read-only boundary

All v1 errors use the shared REST envelope and `X-Correlation-ID`. Missing
objects return `404 not_found`, query validation returns
`422 validation_error`, and incompatible cursors return
`400 invalid_request`.

Missing or invalid bearer credentials return `401 unauthorized` with
`WWW-Authenticate: Bearer`. Authorized responses are private and non-cacheable
across principals.

`POST`, `PUT`, `PATCH`, and `DELETE` are not part of `/api/v1` and return
`405 method_not_allowed`.

## Compatibility

The existing `/api/objects` catalog representation and `/api/agent/*`
responses remain available without a removal date. They delegate to the same
catalog, placement, and Agent query services but keep their historical
response shapes.

New integrations should use `/api/v1`. The MCP wrapper now reads v1 and maps
the page items back to its established `results`/`objects` payload fields,
while also returning `next_cursor`, optional `total`, sort, and direction.
