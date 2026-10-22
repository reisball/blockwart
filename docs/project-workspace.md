# Project items, knowledge pages and external accesses

The focused Project view links to `/projects/{id}/workspace`. This is a deliberately small
project-management layer, not an issue-tracker replacement. It supports English and German.

## Compatibility and persistence

Revision `20261022_0027` creates only `project_records`, their instance/kind index, and
`project_record_versions` with append-only history guards. It does **not** rewrite a Project,
change its canonical schema version, migrate text lists, touch existing chronology, grants,
relationships or timestamps, or require a canonical category/status on a legacy Project merely
to use its new workspace. Tests compare every pre-existing table before and after an upgrade.

Records have stable UUIDs and belong to the Project's immutable `instance_id`, not just its
reusable catalog ID. Deleting and recreating a Project ID cannot expose the former instance's
items or history. Records are not placement children or independently grantable catalog assets.
Existing generic APIs and Project/Research fields keep their contracts.

Old `open_questions`, `blockers` and `next_actions` lists remain the original canonical lists.
Adoption is **explicit manual copying** into new items; no automatic conversion, synchronization,
list removal or interpretation of old chronology occurs. Keep the original source text when
copying; record the adoption in the chronology if it matters to the project. This permits an
incremental transition without losing or inventing history.

Downgrade refuses while either new table contains data. It never silently discards pages or
status history. Export and explicitly reconcile that data before attempting an older application;
there is no automatic destructive rollback. This feature does not itself deploy or migrate a live
instance.

## Records and workflows

All record payloads are closed, validated models in `schemas/project_workspace.py`.
The `kind` discriminator is mandatory for every REST/MCP record input; omitted kinds are
rejected during argument validation, before any REST request or mutation.

- **Item:** title, Markdown description, `item_type` (`task`, `question`, `blocker`), `status`
  (`open`, `in_progress`, `blocked`, `done`), responsibility label, optional timezone-aware
  `due_at`, parent item UUID, safe issue URL and typed object references. Responsibility is
  descriptive metadata, not an ACL or an automatic assignment notification. Any state can be
  explicitly selected. Marking done records completion time; reopening clears current completion
  time but preserves prior completion in history. Parents must be items of the same Project;
  cycles and cross-Project edits/parents fail. Lists filter type, status and overdue state.
- **Knowledge page:** title, Markdown body, optional timezone-aware `review_after`, typed object
  references to existing Runbooks, Decisions or other relevant catalog objects. This is current
  documentation, separate from the append-only chronology. Each edit keeps the previous version.
- **External access:** title/system name, safe HTTP(S) URL, purpose, descriptive account/role and
  optional `credential_reference:ID`. No Host or Service is required. Vaultwarden reference
  metadata may be created and linked atomically in the same command when permitted. The browser
  exposes a Vaultwarden item hint; REST/MCP accept the existing complete credential-reference
  model, including its other providers. This is not a new secret store. Never paste secret values.

Each record exposes creation/update times, version number, current completion time and overdue
state. Every version retains its safe payload, author ID/display-name snapshot, origin and
server timestamp. The origin is bound to the authenticated token audience (`api`/`mcp`)
or a browser session (`ui`), and mismatches fail before mutation or idempotent replay.
History is read-only and guarded against SQL UPDATE/DELETE on SQLite and
PostgreSQL. Technical audit stores only record identity/kind/version/revision metadata, never
page bodies or a second credential payload. No delete-record operation is provided; completed
items remain available, and pages/accesses retain their history.

## Rights and atomic writes

Detail visibility (`read`) on the exact Project is required for every record, history, search,
filter, total and cursor. Discover-only Projects expose none of this data.
`write` on that Project permits record creation and replacement without a global catalog role.
Typed targets must exist with the asserted kind and be readable; concealed or missing targets
have the same not-found result. Reads omit concealed references, including historical versions.
A projected browser edit preserves an existing concealed link instead of silently deleting it.
Live record references participate in catalog deletion/kind-change guards.

Creating new credential-reference metadata additionally requires
`create_credential_reference` **on this Project**. Owner/self already carries it; Editor does not.
A separately scoped `credential_reference_creator` grant can add only that permission. Nothing
changes service-bound credential creation or any global role. The creator receives Owner/self
on the one new disconnected reference; neither other Project readers nor the Project itself
receive permissions on the referenced object or external system. Existing references require
read access and never cause an implicit grant. A reference ID already used or held by a typed
reference cannot be claimed. The reference, its Owner grant, record, history, revision, audit and
idempotency result commit together or roll back together.

Every record write requires the current **Project** `If-Match: "rev-N"` and an
`Idempotency-Key` (16–128 visible ASCII characters). A successful mutation advances the Project
revision once; concurrent writes with the same revision have one winner and a 412 loser.
Authorization is refreshed after acquiring the shared principal/project locks. Identical retries
return the same record/version; changed retries conflict. Keys are bound to the Project instance,
so an ID reused for a different Project cannot replay old records. Current visibility is applied
again to references in an idempotent response.

## REST and MCP

| REST v1 resource | Operation |
| --- | --- |
| `GET /projects/{id}/workspace/{kind}` | `kind=item|page|access`; optional status, item_type, overdue, limit, cursor; includes Project ETag |
| `POST /projects/{id}/workspace/{kind}` | Create one record; JSON `kind` must match path |
| `PUT /projects/{id}/workspace/{kind}/{record_id}` | Fully replace one record of that kind |
| `GET /projects/{id}/workspace/history/{record_id}` | Immutable versions, newest first; paginated |
| `GET /projects/{id}/workspace/search?q=...` | Authorized project-local documentation search; paginated |

Paths above are relative to `/api/v1`. List/history/search page size is 1–100 (default 50).
Responses contain `items`, `total`, `next_cursor`; cursors bind principal/policy, Project instance,
resource and filters. Record-list ordering is stable `(created_at, id)`; version ordering is
stable numeric version descending. Writes return `record`, Project `revision`, `etag`, `replayed`.

MCP registers `blockwart.list_project_records`, `blockwart.save_project_record`,
`blockwart.list_project_record_history` and `blockwart.search_project_workspace`. `save` selects
creation versus replacement by optional `record_id`; `record` is the same discriminated payload
as REST. It forwards ETag, idempotency and MCP origin through the same API. The published input
schema is generated from the shared payload models. Existing tools remain unchanged; the MCP
manifest changes from 38 to 42 tools, requiring an explicitly refreshed client catalog when this
version is eventually deployed.

Example item payload:

```json
{
  "kind": "item",
  "title": "Review migration rehearsal",
  "description": "Compare the synthetic before/after snapshot.",
  "item_type": "task",
  "status": "open",
  "assignee": "Example team",
  "due_at": "2027-01-15T09:00:00Z",
  "issue_url": "https://issues.example.test/project/42"
}
```

## Project view, chronology and search

The focused Project view shows pending/overdue counts and a five-item preview, links to all three
record collections, and edits canonical lifecycle status, responsibility and timestamps with the
existing Project validator and optimistic concurrency. Omitted controls in older form clients do
not erase these fields. Submitted empty date/responsibility controls explicitly clear their
stored values, so completed Projects can be reopened without retaining a completion timestamp.
Category-specific fields and additive extensions remain untouched.

Chronology retains its existing 100-entry API page and immutable seven-kind contract. The browser
now follows `chronology_cursor` to every older page. Invalid or cross-resource cursors fail;
there is no offset traversal that duplicates or skips entries when newer chronology is appended.

Project-local search covers all declared canonical Project fields, current item/page/access text,
and the entire instance's chronology (including entries older than page 1). It does not change
the global ranked catalog search contract. It excludes unknown extension payloads, previous page
versions, credential-reference IDs and secret-store locations. Search never contacts an external
system or synchronizes a linked repository issue. Normalized Unicode/case-insensitive substring
matching and stable `(kind,id)` pagination are deterministic; there is no model/semantic search.

## Verification map

`tests/test_project_records.py` covers lifecycles/reopening, stable IDs, status history, deadlines,
filters, hierarchy cycles and cross-Project isolation, pages/version pagination, search,
optimistic concurrency, idempotency, delegated writes, credential creation isolation, metadata
rejection, empty-versus-omitted browser controls, trusted history origins (including replay),
required MCP record discriminators, rendered browser creation and safe Markdown,
MCP-to-real-API calls, and a populated
0026→0027 table-for-table compatibility snapshot. Existing Project/Research, chronology,
authorization, migration and machine-contract suites remain regression requirements.
