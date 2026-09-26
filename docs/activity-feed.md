# Agent Activity Feed (#188)

The authorized, catalog-wide activity feed answers one agent question: *"What
changed since my last read?"* It is strictly a pull/read-only projection. Push
delivery and notice state remain #106; comment timelines (#131), object audit
(#143), and curated project chronology (#184) stay canonical for their own
details.

## One Application Query

`blockwart.services.activity.query_activity_page` is the single source of truth
behind all three surfaces:

- REST v1: `GET /api/v1/activity`
- MCP: `blockwart.get_activity`
- UI: `/activity`

The query is FastAPI-independent and receives a session plus one immutable
principal/policy snapshot, exactly like the attention view (#176).

## Event Model

The feed classifies existing `audit_events` rows into a closed vocabulary:

| Event type | Audit actions |
|------------|---------------|
| `object_revision` | `create`, `update`, `delete`, `seed_create`, `seed_update` |
| `relationship_mutation` | `relationship_create`, `relationship_metadata_replace`, `relationship_delete` (command path rows, which attribute their audit row to the readable target object) |
| `comment_create` | `comment_create` |
| `audit` | every other recorded action (grants, normalizers, ...) |

Observation/coverage event types from #135/#174 are deliberately **not** part
of this vocabulary yet. They are an additive, reviewed contract change later —
never an accidental pass-through.

Each item is a compact envelope: `event_id`, `event_type`, `occurred_at`
(RFC3339 UTC), the visible `object` reference (`ref`, `object_id`, `kind`,
`label`), a safe short `summary` rendered by the reviewed audit renderer,
`actor`, and a `detail_path` into the existing resource that owns the typed
details. Comment bodies, audit diffs, and project state never enter the
envelope.

## Authorization Semantics

- The visibility decision runs before items, counts, ordering, and cursors.
  Only objects with full detail visibility contribute events; discover-only
  stubs do not.
- Events without an object attribution (for example system-level relationship
  deletes written by internal paths) are dropped fail-closed.
- Deleted objects lose readability, so their past events leave the feed. A
  deletion therefore cannot leak through the feed to principals who must not
  know about the object.
- Cursors bind to the principal/policy fingerprint and the exact query
  parameters. A role or grant change invalidates the cursor (fail-closed).
  Catalog additions and deletions do not change a catalog-wide role's
  fingerprint: the next page still applies current visibility and the keyset
  predicate. Deleted objects simply leave the result set.

## Filters, Ordering, Pagination

- `since`: RFC3339 timestamp; stored naive-UTC timestamps compare in UTC.
- `event_type`, `kind`: closed vocabularies; unknown values are request errors.
- `parent`: placement-subtree scope (canonical `hosts` edges), including the
  parent itself, resolved by a parent-anchored recursive CTE that only follows
  readable targets. Unknown or concealed parents yield an empty page that is
  indistinguishable from a quiet parent.
- `object_id`: exact object attribution filter.
- Order: newest-first by default (`direction=desc`); ties break on the
  zero-padded event id, so equal timestamps keep one stable order in both
  directions.
- Cursor keyset pagination with `limit` between 1 and 100; each page reads at
  most `limit + 1` authorized rows. The continuation predicate and visibility
  filter apply in SQL before the page limit. Concealed and deleted events
  affect neither the page boundary nor the cursor.

## Size Budget

`ACTIVITY_MAX_SCAN_EVENTS = 5000` is a hard result-scan budget per operation:

- Page retrieval reads at most `limit + 1` authorized, filtered rows (and at
  most the budget). Cursor walking can reach every matching event; a full
  terminal page may have a continuation cursor leading to an empty page.
- `include_total=true` reads at most 5001 authorized, filtered event IDs: 5000
  for the count and one probe. It returns `total_status: "exact"` and an integer
  `total` only when the entire result fits. If the probe finds another row, it
  returns `total_status: "budget_exhausted"` and `total: null`. This signals
  that an exact count was unavailable; it never presents a partial count as
  exact. `include_total=false` returns `total_status: "not_requested"` and
  `total: null`.
- The page and count use the same authorization and filters; counts are over
  the full filtered set, independent of the current cursor. Narrower filters
  can make an exact count available.
- For catalog-wide readers, the policy snapshot carries the role authority
  without enumerating every catalog ID. SQL joins audit attribution to the
  current catalog, and only page objects are loaded for labels. Object-scoped
  readers use their effective readable-ID set.

The cap bounds rows returned to application code. Database work can still
depend on indexes and filter selectivity; the database may inspect more rows
to satisfy a filtered, ordered query. This is a remaining query-planning limit,
not a promise of a database execution-time bound.

Activity older than the first page stays reachable through cursor walking or
narrower filters (`since`, `event_type`, `object_id`), not through unbounded
scans.

## Conservative Design Decisions

- Deletion visibility: deleted-object history disappears entirely rather than
  surfacing a deletion marker to callers who lost access together with the
  object. Surfacing tombstones would require a new authorization model and is
  out of scope for #188.
- System-path relationship mutations without object attribution are invisible
  here; the command path (the only writer agents trigger) always attributes.
- The feed renders summaries with the existing audited English renderer; the
  UI localizes event-type labels, not per-event prose.
