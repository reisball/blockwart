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
  parameters. Losing access between pages invalidates the cursor (fail-closed);
  the next page request starts from a freshly authorized result set instead of
  skipping a concealed gap.

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
- Cursor keyset pagination with `limit` between 1 and 100; counts
  (`include_total=true`) aggregate exactly the authorized filtered set via a
  separate `COUNT` over the same WHERE chain. When the exact total exceeds
  `ACTIVITY_MAX_SCAN_EVENTS`, the response exposes `truncated: true` so callers
  can narrow their filters instead of mistaking a window for the full result.

## Size Budget

Every request performs a bounded constant amount of work:

- keyset pagination walks the authorized filtered set via a `(created_at, id)`
  predicate before `LIMIT limit + 1`, so every matching event stays reachable
  and no event is skipped or duplicated;
- `include_total` runs one authorized filtered `COUNT` over the same WHERE
  chain (no `limit + 1`), so the total is the exact full result count;
- `ACTIVITY_MAX_SCAN_EVENTS = 5000` is a documented size budget, not a hard
  scan cap: when the exact total exceeds it the response sets
  `truncated: true`;
- one bounded catalog + relationship snapshot powers the visibility decision,
  as in #176;
- no full-catalog scan grows per readable object, and no catalog database
  rewrite (event sourcing) happens or is required.

Activity older than the scanned window stays reachable through narrower
filters (`since`, `event_type`, `object_id`), not through unbounded scans.

## Conservative Design Decisions

- Deletion visibility: deleted-object history disappears entirely rather than
  surfacing a deletion marker to callers who lost access together with the
  object. Surfacing tombstones would require a new authorization model and is
  out of scope for #188.
- System-path relationship mutations without object attribution are invisible
  here; the command path (the only writer agents trigger) always attributes.
- The feed renders summaries with the existing audited English renderer; the
  UI localizes event-type labels, not per-event prose.
