# API v1

Blockwart's stable machine-readable API lives under `/api/v1`. Every request
requires a service-account bearer token and is object-authorized. Reads and
writes use the same effective object policy as the browser UI and MCP.

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

## Agent read projections

`GET /objects`, `GET /context`, and `POST /object-contexts` add an opt-in,
versioned, closed read projection for agent clients. `projection` is one of
`compact`, `context`, or `full`; the closed `fields` mask may only narrow it.
Non-default responses include the resolved version and sections plus one
response-level `capability_sets` table, which items reference by
`capability_set`. Only byte-identical effective permission sets share a key.

`include_recent_comments` controls the bounded comment preview on context and
batch reads. It defaults off for compact/context and on for full; the historical
no-argument full response remains unchanged. `list_comments` remains the full
history. Projections never alter visibility, authorization, concealment,
ordering, cursors, revisions, or ETags. The exact profile and budget contract
is documented in [Agent read projections](agent-read-projections.md).

## MCP contract metadata

### `GET /api/v1/mcp-contract`

Returns the non-secret API build revision plus the explicit MCP contract
version, canonical wrapper-manifest SHA-256 digest, and tool count. It uses
the ordinary authenticated service-account read boundary and returns no
catalog records, token, header, endpoint/configuration, principal, agent, or
host data. Consumers compare build revision, contract version, and digest;
tool count is only evidence. The digest is not a signature or supply-chain
proof. See [MCP server](mcp.md) for local wrapper diagnostics and the scoped
runtime-catalog refresh contract.

## Needs attention

### `GET /api/v1/attention`

Returns the authorized, catalog-wide attention view: one `summary` plus an
opaque-cursor page of `items`, both derived from exactly the same authorized,
filtered set. The request combines signals Blockwart already records. It runs no
probe, opens no source file, performs no network access, and writes no catalog,
audit, comment, coverage, or observation row.

Each item carries a closed `category`, `severity`, `reason_code`,
`signal_state`, a fixed English `description`, an optional `detail_code` from an
existing closed domain vocabulary, an optional evidence timestamp, and one
`target` with the canonical `kind:id` reference plus its detail path. Categories
are `record_integrity`, `monitoring`, `lifecycle`, `endpoint`, `placement`,
`relationship_integrity`, `provenance`, `runbook`, `knowledge`, and
`source_coverage`. Severities are
`critical`, `warning`, and `info`. Item signal states are `current`, `stale`,
and `unknown`; the summary additionally reports `not_applicable` per category.
The full reason vocabulary and its meaning are in [Needs
attention](attention.md).

Filters are exact `category`, `severity`, `reason_code`, `signal_state`, and
`kind`; `direction` is `asc` or `desc`, and `limit` is 1..100. Ordering is
severity, then the published category order, then the published reason order,
then the target reference. At most one item exists per target and category, so a
single cause is never repeated.

`summary.total`, every severity/category/reason count, the optional `total`, and
the paginated rows describe exactly that filtered set. `summary.signals` is the
one deliberate exception: its `evaluated` value reports how many authorized
inputs the category was judged against before item filters, so
`not_applicable` stays distinguishable from "filtered away".
`summary.coverage_snapshot_state` is `collected` or `not_collected` over the
authorized mapped coverage projection. When no snapshot exists, or none of its
mapped evidence is authorized, the response reports `not_collected` plus one
`coverage_not_collected` item rather than claiming zero coverage problems or
revealing a source-only collection timestamp.

Only objects the caller may read contribute items; discover-only stubs
contribute nothing. Concealing an object removes its own items and changes no
other item, count, signal state, order, cursor, or error. Runbook applicability
and canonical relationship diagnostics are evaluated only after their typed
references and relationship endpoints are projected through READ authorization;
diagnostic prose and related references are never returned. Source-only
coverage facts are never included; they stay behind the platform-admin
`scope=all` boundary of `GET /api/v1/source-coverage`.

Attention is a derived, time-dependent read model with no persisted state.
Its cursor follows the general page contract above and binds the principal,
effective object policy, resource, filters, page size, sort field, direction,
and digest of the authorized filtered projection. A signal correction therefore
invalidates a cursor issued for the older derived state. `generated_at` records
when the page was derived.

## Source coverage

### `GET /api/v1/source-coverage`

Returns the latest sanitized snapshot recorded by the explicit Markdown
collector. The HTTP request reads only the coverage tables and the already
referenced catalog rows: it never opens a workspace file, follows a source URI,
crawls OpenClaw, or writes catalog/snapshot state.

The response contains snapshot metadata, a compact `summary`, and paginated
`items` ordered by `source_uri`, then stable entry ID. Filters are exact
`source`, `classification`, `state`, and `target_kind`; `direction` is `asc` or
`desc`, and `limit` is 1..100. The controlled classifications are
`operational`, `retired`, `historical`, `research`, `migration`, `generated`,
and `ignored`. Coverage states are `mapped_current`, `mapped_stale`,
`unmapped_operational`, `intentionally_unmapped`,
`orphaned_catalog_reference`, `missing_source`, `ambiguous_mapping`,
`duplicate_mapping`, and `source_changed_since_import`.

The default `scope=mapped` first removes every mapping whose object the caller
cannot read, then resolves and counts only the remaining visible mapping set.
Entries without a visible mapped object are absent. A concealed mapping cannot
change an ordinary caller's detail, state, count, response digest, cursor, or
error behavior. `scope=all` additionally includes source-only gaps and missing
targets and therefore requires the existing explicit platform `admin` role;
ordinary callers receive the stable `403 forbidden` envelope. Platform
administration does not bypass object ACLs: existing concealed mappings remain
absent even in this scope, while missing targets can be shown because the
source-only authority supplies the otherwise absent authorization boundary.

`summary.total`, every state/classification count, optional `total`, snapshot
entry/mapping counts, and the paginated rows are derived from exactly the same
authorized, filtered detail set. The returned digest identifies that authorized
projection. Coverage cursors are bound to the principal and effective-policy
fingerprint, normalized filters, scope, ordering, page size, and projection
digest. Unlike the general object page, changing coverage `limit` invalidates a
coverage cursor. A visible snapshot change also invalidates it; a hidden-only
mapping change does not alter an ordinary projection or its cursor.

Coverage records inventory accounting, not full reference storage. Returned
fields are limited to stable identifiers/URIs, controlled decisions and state,
opaque fingerprints, timestamps, target kinds, and authorized mapping IDs. No
source excerpt, arbitrary private file content, credential, or secret value is
part of this contract.

## Objects

### `GET /api/v1/objects`

Returns sanitized catalog summaries. The default order is `id asc`; supported
sort fields are:

- `id`
- `label`
- `kind`
- `relevance`
- `updated_at`

Every order uses the object ID as the final unique tie-breaker; `relevance`
uses the label and then the ID. `direction` is `asc` or `desc`, `limit` is
1..100, and `cursor` continues a previous page. The default sort is unchanged,
so a client that does not ask for `relevance` keeps its historical order.

The list accepts:

- `q`: case-insensitive search over the closed search projection below
- `match`: `normal` (default), `exact_ref`, or `exact_label`
- `operational_only`: exclude non-operational records
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
- `decision_status`: exact canonical Decision lifecycle value
- `applies_to`: exact authorized asset `kind:id` in a Decision's canonical scope
- `runbook_status`: exact canonical Runbook lifecycle value
- `runbook_risk`: exact canonical Runbook risk value
- `project_category`: exact canonical Project category
- `project_status`: exact canonical Project lifecycle value
- `related_object`: exact authorized `kind:id` in a Project or Runbook's typed relationships
- `source_type`: `unknown`, `manual`, `import`, or `discovery`
- `stale`: exact computed freshness state

Objects with `read` use the full summary. Objects with only `discover` use a
strict stub containing identity, display label, released placement, and the
caller's capabilities. Detail-field filters exclude stubs rather than probing
their hidden values; text search on stubs uses only their ID, canonical
reference, and label.
Decision reference projections omit concealed targets, and `applies_to` returns
no match when its target is not discoverable.
Project reference projections follow the same rule. Project filters exclude discover-only stubs;
a concealed or missing relationship target yields the same empty result.
Runbook references and status/risk/relationship filters use that identical rule;
steps, commands, verification, sources, credential references, and relationships
are absent from discover-only stubs.
Objects without `discover` are absent.

### Search projection, matching, and relevance

`q` is compared against a closed, server-defined projection, never against the
serialized catalog document or the provenance header. Both the term and the
compared value use one normalization: Unicode NFKC, whitespace runs collapsed
to a single space, trimmed, and case-folded.

The `relevance` order publishes this fixed precedence, best first:

1. exact canonical `kind:id` reference or exact ID;
2. exact normalized label;
3. the term inside the ID or the label;
4. a structured domain field: hostnames, network addresses, endpoint host,
   URL, and capability, plus Decision `decision`, Runbook `purpose`, and
   Project `current_summary` and `objective`;
5. the top-level summary;
6. another explicitly allowlisted bounded field: `network.location`,
   `network.manufacturer`, `network.model`, `installed_software[].name`,
   `owner`, Decision `context`, `rationale`, `consequences`, and
   `alternatives`, Runbook `in_scope`, `out_of_scope`, `approval_requirement`,
   and step titles, and Project `next_actions`, `open_questions`, `blockers`,
   `in_scope`, and `out_of_scope`.

Equal ranks are ordered by label and then by ID, so repeated identical queries
return identical pages. A query without `q` gives every object the same rank
and therefore keeps that stable label/ID order.

Everything else is deliberately unsearchable: the serialized `data` document,
the canonical provenance header (including `source_ref` and `managed_by`),
imported `sources`, `docs`, and `source_references` entries, `schema_version`,
credential references, command bodies, component and monitoring documents, and
any other unlisted path. Generic migration or import boilerplate therefore
cannot match a term or outrank a useful record.

`match=exact_ref` matches only the exact canonical `kind:id` reference or the
exact ID. `match=exact_label` matches only the exactly normalized label. Both
exact modes evaluate the identity fields a discover-only stub already
publishes, so they neither widen nor narrow concealment.

`operational_only=true` removes records whose canonical status is `inactive` or
`deleted`, whose canonical asset lifecycle is `retired`, or whose canonical
knowledge status is retired: Runbook `retired`, `superseded`, or `deprecated`,
Decision `superseded` or `deprecated`, and Project `archived`. It reads
detail-only state and therefore excludes discover-only stubs, exactly like the
other detail filters. The default is unchanged: without the flag every
authorized record stays visible.

Ranking, filtering, counting, ordering, cursor creation, and cursor validation
happen only over the authorized result set, so a concealed object can change
neither a position, a count, nor a cursor. Cursors bind the principal and
effective policy, the normalized term, the match mode, `operational_only`,
every structured filter, the resource, the sort field, and the direction; a
cursor from a different query returns `400 invalid_request`.

Every readable detail summary — and therefore every context that extends one —
also carries `search_snippet`: one bounded,
whitespace-collapsed line of at most 240 characters (with a truncation marker
when it is shortened). It is the top-level summary, or — when the object has
none — exactly the authorized canonical knowledge field of the kind: Runbook
`purpose`, Decision `decision`, or Project `current_summary`. No other data
path, full document, imported body, concealed field, secret-shaped value, or
diagnostic becomes a snippet, and a discover-only stub never carries one.

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

Full object reads include the monotone `revision` field, a strong `etag` body
field, and the byte-identical `ETag: "rev-N"` response header plus the five
newest authorized entries in `recent_comments`. Each entry contains exact
source text and `markdown` or `plain_text` format; the API never returns stored
rendered HTML. Discover-only stubs expose neither `revision`, body `etag`, HTTP
`ETag`, nor comments. Concealed objects remain indistinguishable from absent
IDs. Clients pass the returned body `etag` unchanged as `If-Match` on
conditional object, relationship, and access-control mutations; comment
appends and child creation use their separate contracts.

A readable service includes the provider-neutral `monitoring` projection. It
contains the effective configuration and resolved target (or stable
configuration diagnostic), selected provider, interval/default marker,
effective and last observed states, freshness, HTTP status, latency, stable
redacted error code, last check, last success, next due time, and effective
health. The top-level `health` value uses that effective result for an enabled
service; manual `maintenance` always wins. Pending/stale observations publish
effective `unknown` while retaining the last observed state. Discover-only
stubs and concealed objects expose none of these fields, counts, or timestamps.
For a malformed present monitoring document, the authorized projection reports
`invalid_monitoring_config` with null provider, interval, and target rather than
applying configuration defaults or exposing the rejected value.
The same projection is used by context pages and known-ID batches. See
[Service monitoring](service-monitoring.md).

## Commands

### `GET|POST /api/v1/objects/{object_id}/comments`

`GET` requires `read` and returns the newest-first comment timeline using the
standard opaque cursor envelope, fixed `sort=created_at`, and
`direction=desc`. `limit` is 1..100. Discover-only and missing objects both
return `404`.

`POST` requires `write`, an `Idempotency-Key`, and JSON `{"body":"..."}`.
The exact 1..4000-character Markdown source is secret-scanned before storage.
A new append returns `201`, a `Location` for the matching UI timeline anchor,
the new object `ETag`, and its immutable comment; an exact replay returns `200`
with `replayed=true`. No `If-Match` is
used, so concurrent independent appends do not overwrite each other. The
object revision advances atomically while business `updated_at` stays
unchanged. API-origin comments require an authenticated `api`-audience token;
clients cannot select or spoof the origin.

Comments have no update or delete endpoint. A successful new append records
one minimal `comment_create` audit event without the comment body; replays and
failures record no object audit. The complete storage, Markdown, UI, MCP, and
migration contract is in `object-comments.md`.

### Project workspace resources

`GET /api/v1/projects` returns only detail-authorized Projects with canonical
`project_status`, `category`, `current_summary`, first `next_action`, and the
latest authorized professional chronology entry. It supports exact
`project_status` and `project_category` filters, `id`, `label`, or
`last_activity` sorting, standard direction/limit/cursor parameters, and the
normal optional total. Authorization precedes filtering, chronology lookup,
counting, ordering, and cursor creation, so stubs and concealed Projects leak
none of those derived values.

`GET|POST /api/v1/projects/{object_id}/chronology` reads or appends the curated
Project chronology. The kind is exactly `intent`, `implementation`, `result`,
`decision`, `milestone`, `blocker`, or `note`. Append uses the same trusted
channel, secret rejection, immutable attribution, Markdown source, atomic
revision bump, minimal audit, and `Idempotency-Key` behavior as object
comments. Existing untyped Project comments project as `note`; canonical
Project fields are never changed from chronology text.

### `POST /api/v1/objects/{parent_id}/children`

Requires `create_child` on the parent and an `Idempotency-Key` header containing
16..128 visible ASCII characters. The validated child, canonical `hosts`
placement edge, and a direct self-scoped owner grant for the creating principal
are committed atomically. The response is `201`, includes `Location` and
`ETag`, and contains the created object.

Keys are SHA-256 hashed at rest and bound globally per principal to the exact
operation context and canonical request payload. Repeating the same request
within `BLOCKWART_IDEMPOTENCY_TTL_SECONDS` (default 24 hours) returns the stored
result without another object or audit event. Reusing a key for another parent,
operation, or payload returns `409 conflict`. Expired records may be replaced.

### `POST /api/v1/roots`

Creates one disconnected top-level catalog root without a placement parent.
Requires an active catalog-owner principal and an `Idempotency-Key` header
containing 16..128 visible ASCII characters; platform-admin alone is not
sufficient. API writes require an `api`-audience service token, matching the
trusted-channel rule of the shared `create_root` command. The validated root and
exactly one direct self-scoped owner grant for the creating principal are
committed atomically. The response is `201`, includes `Location` and `ETag`,
and contains the created object; the idempotent replay, duplicate-ID conflict,
and changed-payload `409 conflict` semantics match child creation.

### `PUT /api/v1/objects/{object_id}`

Requires `write` on that exact object and `If-Match` with the current strong
ETag. All mutable business fields use the existing shared schema, secret,
reference, type, lifecycle, and placement validation. ACLs and delete authority
are not part of the payload. Missing `If-Match` returns
`428 precondition_required`; a stale or malformed value returns
`412 precondition_failed`.

Host and system payloads may include the ordered manual
`data.installed_software` list documented in `object-validation.md`. REST uses
the same canonical registry as MCP and the UI; the generated OpenAPI document
publishes that registry once in its top-level `x-blockwart-object-schema`
extension. Rejected kinds, list/entry types, required fields, extra entry
fields, and URL formats use the standard field-accurate validation details.
The URL field combines `format: uri` with a JSON Schema `pattern` restricted to
case-insensitive `http://` and `https://` prefixes.

Service payloads may include the bounded canonical `data.components` document.
It is written only through this parent-object command and returned only in full
readable parent detail/context; see [Service-local components](service-components.md).

Service payloads may also include the closed canonical `data.monitoring`
document. It is written through this same command and therefore uses `write`,
`If-Match`, schema/secret validation, audit, and rollback without a monitoring
bypass endpoint. An absent document is disabled. See
[Service monitoring](service-monitoring.md).

### `DELETE /api/v1/objects/{object_id}`

Requires the separate `delete` permission plus current `If-Match`. Referenced
objects remain protected by the shared relationship and typed-reference
integrity checks. Direct grants are removed only in the same successful delete
transaction.

### `POST|DELETE /api/v1/objects/{object_id}/relationships`

Requires `write` on the path object, discoverability of the peer, and current
`If-Match`. The JSON body is `from_ref`, `relation_type`, `to_ref`, and
optional `metadata`. Shared relationship, canonical-placement, last-owner, and
rollback checks apply.

`relation_type` is the closed registered vocabulary, and the accepted endpoint
kinds and metadata fields depend on that exact value. The request schema is
generated from the domain relationship registry: it publishes the closed
`relation_type` enum, the union of every metadata field, and one `allOf`
condition per relationship type that binds the accepted metadata document to
its type. `depends_on` and the other non-link types accept an empty metadata
document only; `attached_to` publishes exactly its five link fields and
`uplinks_to` those plus `mode`. `POST /attached-devices` publishes exactly the
`attached_to` metadata contract.

A rejection the payload alone decides — unknown type, invalid typed reference,
self-reference, an endpoint-kind pair the type does not accept, an unsupported
or invalid metadata field, or secret-shaped metadata — returns
`422 validation_error` with the canonical `code` and `path` described in
`api-boundary-contract.md`. Rejections that depend on stored endpoints or on
the surrounding edge set (endpoint predicates, duplicates, second placement
parent, second primary edge, cycles) remain `409 conflict` without a field.
Creating an existing triplet replaces its canonical metadata; an identical
canonical document returns `changed: false` without advancing a revision.
Delete matches the triplet only and ignores metadata. See
`relationship-integrity.md` for the published contract itself.

## Platform-admin resources

The `/api/v1/admin/principals` resources require an explicitly assigned
platform `admin` service account. They list and create principals, return one
principal's lifecycle and credential metadata, and update a principal using
its current `If-Match` ETag. Platform administration does not bypass the
caller's object policy: direct and effective assignment rows contain only
objects on which the caller currently has `manage_access`.

The principal list accepts `q`, `principal_type`, `active`, `limit` (1..200),
and the opaque, filter-bound `cursor` returned as `next_cursor`. It deliberately
does not return a total count.

```text
GET|POST /api/v1/admin/principals
GET|PUT  /api/v1/admin/principals/{principal_id}
POST     /api/v1/admin/principals/{principal_id}/grants
PUT      /api/v1/admin/principals/{principal_id}/grants/{grant_id}
DELETE   /api/v1/admin/principals/{principal_id}/grants/{grant_id}?object_id=...
POST     /api/v1/admin/principals/{principal_id}/password
POST     /api/v1/admin/principals/{principal_id}/tokens
POST     /api/v1/admin/principals/{principal_id}/tokens/rotate
DELETE   /api/v1/admin/principals/{principal_id}/tokens/{token_name}
```

Lifecycle and credential mutations advance the principal revision. Token
issue and rotation require `Idempotency-Key`; a successful response discloses
the new token exactly once and uses `Cache-Control: private, no-store`.
Replaying the completed request proves completion but does not redisclose the
secret. Existing password, token, session, and hash values are never readable.
The last-active-admin and independent last-effective-owner invariants fail
atomically.

The principal-targeted grant routes are administrative aliases for the shared
object grant command layer. They require both the platform `admin` role and the
normal object `manage_access`/Owner policy, use the object's `If-Match` ETag,
and retain the same Owner, idempotency, audit, and rollback rules. Update and
delete also bind the grant to the principal and object named by the request.

## Object access-control resources

### `GET /api/v1/objects/{object_id}/access`

Requires effective `manage_access`. The response carries the anchor object
revision and ETag plus two explicitly separate projections:

- `direct_grants`: grants stored on this exact object, including inactive
  principals so stale assignments remain administratively visible;
- `effective_access`: active principals that currently receive permissions on
  this object, with additive permissions and every direct or inherited grant
  source.

Principal fields are limited to ID, login, display name, principal type, and
active state. Credential, session, token, password, and hash fields are never
part of this projection. Undiscoverable objects return `404`; discoverable
objects without `manage_access` return `403`.

### `GET /api/v1/objects/{object_id}/access/principals`

Searches active principals by login or display name for a grant form. Query
`q` must contain 2..100 characters and `limit` is 1..20. The response uses the
same minimized identity projection as the access resource.

### `GET /api/v1/objects/{object_id}/access/preview`

Accepts `scope=self|subtree` and returns the safe object ID, kind, label, and
direct-anchor marker for every affected object. `subtree` follows canonical
placement only; other relationship types do not affect the preview.

### Grant commands

```text
POST   /api/v1/objects/{object_id}/access/grants
PUT    /api/v1/objects/{object_id}/access/grants/{grant_id}
DELETE /api/v1/objects/{object_id}/access/grants/{grant_id}
```

All commands require effective `manage_access` and current `If-Match`. Create
accepts `principal_id`, `role`, and `scope`; update accepts `role` and `scope`.
Only an effective Owner may create, change, or revoke an Owner grant. The
last-effective-owner and actor-self-lockout guards cover role changes, scope
shrinks, and revocation over the canonical placement graph.

An actual change returns the new revision and ETag and writes one immutable
object audit event. An exact duplicate create or unchanged update returns
`changed: false` without advancing the revision or writing another event.
Concurrent writers using the same ETag have one winner; later attempts receive
`412 precondition_failed`. Catalog object payloads and imports reject
ACL-shaped data and cannot mutate grant rows.

Every successful mutation advances the relevant object revision atomically and
writes exactly one immutable object audit event in the same transaction. Audit
details include principal, channel, correlation/request ID, old/new revision,
structured before/after state, and field changes. Authorization denials create
only a security event; failed validation, stale writes, and conflicts leave no
partial business data or object audit event.

### `GET /api/v1/context`

Returns the same detailed contexts as a cursor page. It accepts the object-list
filters, search parameters, and sort fields, with a smaller limit of 1..20.

### `POST /api/v1/object-contexts`

Retrieves full authorized contexts for a bounded list of already-known object
IDs in one read-only roundtrip. The JSON body is `{"object_ids": ["id", ...]}`
with 1..20 entries; each entry must match the canonical object ID pattern and
must not exceed the canonical 128-character maximum. Duplicate IDs keep their
first input position; the response preserves input order and returns exactly
one item per unique ID.

The request body is bounded at the ASGI receive level before Pydantic parsing:
a `Content-Length` header that honestly declares an oversized body is rejected
without reading any bytes, and an absent, misleading, or chunked/streamed body
is bounded while receiving. An oversized request returns one stable
`413 payload_too_large` error without echoing input; this response is
endpoint-local and does not appear on other operations.

Each readable item is field-equivalent to `GET /api/v1/objects/{object_id}`:
the same detail context, the same `revision` and body `etag`, the same five
newest `recent_comments`, relationships, parent path, children, and
credential-reference IDs. Discover-only objects return the same strict stub as
single reads. Objects the caller cannot discover and IDs that do not exist
return an indistinguishable concealed placeholder carrying only the requested
ID; the batch is never an existence oracle through status, text, counts, order,
or metadata.

Objects, relationships, and the five newest comments for every authorized
detail object are loaded in bounded snapshots, so database access does not grow
per requested ID. When the serialized response exceeds the maximum payload
size, the request fails with one whole `413 payload_too_large` error rather
than truncating an item, because every returned detail item must remain
equivalent to a single read. Malformed, empty, over-limit, and over-length
requests return `422 validation_error`. Missing and existing-but-concealed IDs
receive equivalent bounded policy-shaped work before producing the exact same
concealed placeholder, so the two cases do not take observably different
shortcuts.

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

### `GET /api/v1/objects/{object_id}/device-graph`

Returns the readable connected `attached_to` component for one anchor. The
response contains canonical edge metadata, a deterministic preferred upstream
path, and every reachable downstream reference. Non-placement edges require
`read` on both endpoints.

### `GET /api/v1/objects/{object_id}/network-topology`

Returns the policy-first network resolution for one readable host, system,
service, or network device. Systems use their own `attached_to` edge when one
exists and otherwise inherit the placement host; services inherit the explicit
system attachment or placement host. Every readable `uplinks_to` alternative
is retained and sorted deterministically, while `primary` affects order only.

The response records `direct|inherited`, the exact resolution source and
placement path, authorized nodes and edges, all bounded paths, per-path
`complete|incomplete`, overall `complete|incomplete|unconnected`, and an
explicit `truncated` flag. A terminal router or gateway is complete; another
device without an uplink is incomplete. Traversal stops before an unreadable
endpoint without disclosing its identity, category, metadata, path, or count.
The existing `/topology` resource is unchanged.

## Errors and boundary

All v1 errors use the shared REST envelope and `X-Correlation-ID`. Missing
objects return `404 not_found`, query validation returns
`422 validation_error`, and incompatible cursors return
`400 invalid_request`.

A rejected search `limit` on `/api/v1/objects`, `/api/v1/context`,
`/api/agent/search`, or `/api/agent/context` adds one narrowly scoped detail to
the standard `validation_error` envelope. Beyond the canonical detail fields it
carries `field` (`limit`), the server-declared `minimum` and `maximum`, and
`received`, which is the sent value re-derived as a bounded integer or `null`.
No other parameter and no other resource is described this way, and no other
rejected input is echoed; see
[API boundary contract](api-boundary-contract.md).

Missing or invalid bearer credentials return `401 unauthorized` with
`WWW-Authenticate: Bearer`. Authorized responses are private and non-cacheable
across principals.

Undocumented methods remain unavailable. In particular, collection-level
`POST /api/v1/objects` and all `PATCH` requests return
`405 method_not_allowed`.

## Compatibility

The existing `/api/objects` catalog representation and `/api/agent/*`
responses remain available without a removal date. They delegate to the same
catalog, placement, and Agent query services. Their endpoints and response
envelopes remain stable; readable Agent detail/context objects add the strong
`etag` field documented above.

New integrations should use `/api/v1`. The MCP wrapper now reads v1 and maps
the page items back to its established `results`/`objects` payload fields,
while also returning `next_cursor`, optional `total`, sort, and direction.
