# Typed project management

Epic [#287](https://github.com/reisball/blockwart/issues/287), child issues #288–#296.
This is a lightweight project/POC layer. It is not a GitHub issue tracker replacement.
The package does not itself bump the product version, publish a release, or migrate a live server.

## One model across UI, REST and MCP

Workspace records still belong to one immutable project instance. UUIDs and previous history
remain valid. Stable project-local short codes supplement UUIDs, are resolvable through detail
reads, and never change on rename, reparent or archive. Migrated records get `REC-NNNNN` without
interpreting their titles; newly created records get UC/GRP/REQ/TASK/DEC/EV or kind prefixes.
Numbers are allocated under the project write lock and are never reused by a delete operation.
Records cannot be moved across project instances. There is no delete-record API.

Items add explicit `use_case`, `requirement_group`, `requirement`, `decision`, and `evidence`
types alongside existing task/question/blocker types. A hierarchy is organizational, not an
implicit claim of fulfillment. Typed directed relations carry independent meaning:

| Relation | Source → target | Meaning |
|---|---|---|
| `implements` | task/decision → requirement | Descriptive traceability; a decision does not prove implementation |
| `applies_to` | requirement → use case | Shared requirement without copying its contents |
| `depends_on` | work item → work item | Unfinished predecessor is an explicit dependency |
| `blocked_by` | task/question/requirement/use case → blocker | Scoped blocker, not a project-wide automatic status change |
| `precedes` | task/question/decision → same family | Ordering only, not an automatic blocker |
| `supersedes` | requirement/page → same semantic type | Explicit successor; never silently changes the target's disposition |
| `documents` | page → task/decision/requirement/use case/evidence | Documentation with a versioned target |
| `informed_by` | work item/requirement/use case/page → page/evidence | Narrative relies on an explicit result/page version |

Endpoints use canonical UUIDs, are in the same project instance, and are checked both inbound
and outbound on type changes. Hierarchy, dependency, ordering, and supersession cycles are
rejected. Documentation/result references are not containment. Named selectors in the UI avoid
manual UUID entry. A filtered/paged list keeps contextual branches navigable and labels branches
outside the current list instead of pretending the tree is complete. All records in a readable
workspace have the project's rights; no per-record access grants or hidden-record count channel
is introduced.

Priority is low/normal/high/urgent. Responsibility labels remain descriptive; an optional active
principal ID grants no permission and sends no notification. Deferred work, blocked work and
ordering are distinct. Archived records preserve UUID/code, status, history, comments and links.
An archived unfinished predecessor is still unfinished; archiving is not completion or acceptance.

## Requirement revisions, evidence and acceptance

**Task done ≠ requirement verified ≠ use case accepted.** There is no automatic acceptance
from a closed issue, merged PR, completed decision, parent status, or many small done tasks.

Requirements have stable criterion IDs, descriptions, and an explicit mandatory flag. The
original requirement text is immutable once recorded. Current wording, disposition and change
reason are separate. A title/description/criterion/requirement-content change increments the
requirement revision and requires a reason; status/comments/assignment do not change that
revision. Superseded, deferred and waived requirements are not represented as fulfilled.

An evidence record identifies exactly one requirement and revision, criterion IDs, outcome
(pass/fail/inconclusive), subject/build/run, scope, limitation, source URL and observed time.
The authenticated recorder and server time are retained in record history. Old evidence is
preserved with its original meaning. Reuse on another requirement revision requires a distinct
reasoned review event pinned to that exact evidence version. It is neither automatically reused
nor deleted or blanket-invalidated. A component proof does not imply an E2E proof.

`context.fulfillment` independently derives criterion coverage from current or explicitly
reused evidence. It reports the required denominator, passed criteria, mixed/inconclusive results,
proof IDs and requirement revision. It is not an assertion of acceptance. Missing implementation,
missing verification and blockers are separately visible in the overview. Empty mandatory scope
is never presented as 100%.

An `assess` command records accepted/exception/rejected/reopened with authenticated actor,
server time, reason, exact evidence snapshots and the dependency/revision basis. Accepted
requirements need all mandatory criteria proven and mandatory relevant work finished; a use
case also needs its relevant requirements accepted. An explicit, reasoned exception is a
separately counted alternative and retains the missing scope. Excepted child scope is current
at the moment of that explicit decision; later child assessments, requirement changes and
changes to selected child proof versions require renewed review. No universal zero-error criterion
or artificial detection criterion is invented. Informative/background criteria may be optional.

Reopening work, changing relevant requirement content, or editing selected proof marks a prior
assessment stale without deleting it. Reopening acceptance appends a new event. New conclusions
never overwrite history. Both old and current assertions remain inspectable.

### Scoped change example

UC-A and UC-B initially reference a shared manual-approval requirement. To change only UC-A,
create an explicitly documented successor/variant for automatic approval, link it only to UC-A,
and remove only UC-A from the original's `applies_to` relation. Preserve the original baseline and
its UC-B link. The successor relation explains provenance; it does not globally waive the original
or transfer its proofs. UC-B and its evidence remain unchanged. Review old evidence for any
reusable criteria on the new revision/variant explicitly. Never rewrite a shared requirement and
claim unaffected use cases remained unchanged.

## Task discussion and explicit commands

A direct browser URL `/projects/{project}/workspace/record/{UUID-or-code}` shows the item,
relationships, distinct assessment/fulfillment, immutable discussion/events and record history.
Comments render through the existing safe Markdown sanitizer. Every event has project-instance,
record, author ID/display snapshot, server origin/time. Discussion and assessments are not
project chronology or technical audit. Event/history pagination has project/access/filter-bound
cursors. Deleting/recreating a catalog project ID cannot expose former-instance discussions.

Legacy POST/PUT require project `If-Match: "rev-N"` and retain full-replacement semantics for
original fields. A legacy client omitting newly introduced PM fields preserves those fields.
A new client may explicitly clear valid nullable fields or submit empty lists/text; `null` on a
nonnullable field is invalid. Omitted patch keys never change other fields. Full PUT is not PATCH.

Targeted actions use the exact `record_etag` returned by record reads, not the project revision.
Two updates of one record have one CAS winner; independent records do not fail merely because
another record advanced the project revision. Every successful action still locks and CAS-updates
the project revision, reauthorizes the actor, and commits record/history/event/audit/idempotency
atomically. Project-wide graph invariants remain serialized. Every action needs an idempotency
key; exact retries do not duplicate events/versions, changed retries conflict. Audience/origin
checks happen before replay or mutation. No locks or preconditions were removed.

## Canonical homes and explicit legacy adoption

| Information | Authority |
|---|---|
| Structured work status, hierarchy, dependency, responsibility | Current structured records |
| Requirement wording/criteria | Current requirement revision, original baseline retained |
| Evidence and acceptance | Version-bound evidence and append-only review events |
| Curated summary and narrative | Human/agent-curated text, never silently regenerated |
| Historical chronology | Existing immutable project chronology |
| Non-adopted legacy list entry | Its original project list |
| Explicitly adopted list entry | Linked structured record; original list is a source/reference |

`import-legacy` requires field, occurrence index, exact original text and project revision.
The source is preserved. Adoption provenance is server-controlled: generic record creation
cannot supply `legacy_origin`; it must use the dedicated import action, which also reconciles
occurrence identity under the shared project lock. Mapping is project-instance/field/index/text-bound, deduplicated beyond
idempotency-key expiry and across different request keys. A server event retains source revision,
list fingerprint, author/time and authority transition. Identical text in two positions remains
two explicit occurrences. A stale selection cannot import another entry. Non-adopting projects
stay usable, and no automatic interpretation of titles or chronology occurs.

A `documents`/`informed_by` link captures the referenced record version. Later changes make the
claim *possibly stale*; they do not rewrite a task/page or assume semantic contradiction.
Different component/E2E scopes can remain valid simultaneously. Refresh the link version only
following an explicit text/result review. Pages have current/historical/superseded lifecycle and
explicit successor relations. Editing a historical page never promotes it to current.

## Structured GitHub links and opt-in observations

A project may have no repository or multiple `repository` records. They identify owner/name,
optional stable numeric GitHub ID and a project-local UUID. Tasks may link many typed issue,
pull and full-SHA commit references. Duplicate repository identities/references are rejected.
Existing source links and `issue_url` are preserved; adoption into structured references is
explicit. Linking alone performs no network request or external write.

Status authority is explicit: `local` keeps the stored work status; `github` requires exactly
one leading linked **issue**. Other links never randomly select the status. A closed leading
issue derives effective done only while fresh, never requirement/use-case acceptance. The local
status and its completion timestamp are preserved. Effective status is shared by filters,
overdue calculations, summaries and UI/API/MCP. A stale/failed GitHub-led status is unknown,
not successful completion; prior successful observations stay visible separately.

Observation requires both deployment `BLOCKWART_PROJECT_GITHUB_SYNC_ENABLED=true` and repository
`sync_enabled=true`. Activation requires an explicit stable numeric repository ID. Lookup by that
ID follows rename/transfer while verifying the returned identity; URLs are constructed from
validated components, not trusted upstream `html_url`. A missing/concealed object, failed auth,
rate limit, transport/TLS/policy error or changed repository configuration does not close work.
Freshness is at most 15 minutes and is bound to the configured refs/repository version.
Only an explicit manual `sync_github` action contacts GitHub. No scheduler, webhook, external
write, credential provisioning or automatic integration activation is included.

The observer uses fixed api.github.com:443, public-address policy, all-answer DNS admission,
a pinned socket, hostname-verified TLS, GET only, no redirects/proxies/retries, bounded headers/
body/deadline and a total manual action budget. Sync runs synchronously under the atomic project
command lock, so target edits cannot overtake its write. It deliberately does not introduce an
asynchronous lease/scheduler. This can briefly serialize other writes while the bounded read
finishes. Search/list/detail reads never contact GitHub.

Public anonymous access is explicit when no credential reference is configured. Private access
uses an operator-managed JSON mapping `BLOCKWART_PROJECT_GITHUB_CREDENTIAL_FILES`, from exact
`PROJECT_INSTANCE_ID/REPOSITORY_RECORD_UUID/GITHUB_NUMERIC_ID/credential_reference:<id>`
to a protected runtime token file. There is no global-reference fallback. A new project instance,
other repository record, upstream repository retarget or credential change needs a new explicit
operator binding; catalog-reference readability alone never enables credential use. Catalog metadata never supplies a
file path or secret value. Reading a reference is not permission to fetch its value: the operator
must separately configure the integration binding. The requesting actor must also be allowed to
read the reference. Required/unreadable credentials fail closed; no anonymous or inherited-token
fallback. The bounded regular-file reader rejects unsafe files and never logs paths/contents.
Tokens/response bodies/transport exception text never enter events or GitHub. Use least-privilege
read access and explicitly consent to sharing imported repository metadata with project readers.

## REST/MCP addition map

All REST paths below start `/api/v1/projects/{id}/workspace`.

| REST | MCP |
|---|---|
| `GET /record/{record_id}` | `get_project_record` |
| `GET /events/{record_id}` | `list_project_record_events` |
| `GET /overview` | `get_project_overview` |
| `POST /actions/{record_id}` | `act_on_project_record` |
| `POST /import-legacy` | `import_project_legacy` |

Action payloads use `action=patch|comment|assess|reuse_evidence|sync_github`, validated by
`ProjectActionIn`. Patch uses `changes`; comment uses `body`; assessment uses `result`, `reason`,
`evidence_ids`; reuse uses reason and evidence IDs. The shared record schema is published in
OpenAPI/MCP. Five additional tools change the manifest; refreshing deployed clients is an explicit
operational step, not evidence supplied by these source changes.

## Data preservation and release verification

Migration `20261023_0030` widens the workspace kind check, adds code/revision columns and a new
append-only event table. SQLite batch-copies the workspace table to widen its check; original
columns and every history row are preserved byte-for-byte. PostgreSQL uses the corresponding
constraint/column operations. No project text, grants, relationship, requirement classification
or existing status is changed. Downgrade is permitted only with empty workspace/event data;
otherwise it refuses and requires a verified pre-upgrade recovery backup.

A populated synthetic migration test and a protected consistent live-state backup rehearsal
compare every original table/column before and after migration, including record JSON, IDs and
versions. The live application is not stopped or changed for that rehearsal. Private instance
metadata and backup contents stay outside the repository. Technical test commands and outcomes
belong in the PR and [implementation plan](planning/project-management-287.md).

### Legacy occurrence reconciliation

An imported entry retains its original field, position, text, source revision,
source fingerprint and occurrence count. A unique text occurrence remains linked
to that same structured record after a source-list reorder; its historical
origin is not rewritten. Identical text occurrences can initially be imported
separately while the source fingerprint is unchanged. If their source changes
and occurrence identity is ambiguous, overview returns
`authority: reconciliation_required` and import refuses with a conflict. Resolve
the source provenance explicitly before importing; no duplicate is guessed.
Older provenance without an occurrence count remains valid at its exact source
fingerprint but requires reconciliation after an ambiguous source change.

Acceptance considers unresolved `depends_on` and `blocked_by` predecessors,
not order-only `precedes`. GitHub-led work uses the fresh leading issue's
observed state, never a locally stored `done` fallback. A failure observing a
secondary issue/PR does not override a successful, current leading issue.
Use-case acceptance becomes stale when a mandatory child's selected proof or
assessment is no longer current. Decisions remain visible traceability but are
not counted as implementation tasks in coverage.

Record listing supports `depends_on` (direct predecessor UUID or local short
code) and `blocked` (unresolved dependency/blocker, explicit blocked state or
reason) on REST, MCP and UI. Pagination tokens are bound to the normalized
filters, project instance and authenticated principal.
