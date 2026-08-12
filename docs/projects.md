# Canonical Project Knowledge

Project is Blockwart's canonical container for reviewed work knowledge. It keeps the existing
top-level `project` kind and uses `data.category` to distinguish implementation, migration,
research, experiment, incident-review, and other work. A Project is not an asset: top-level
`lifecycle` and `health` are rejected, while the legacy catalog `status` remains separate from
the Project lifecycle described here.

`blockwart.domain.object_schema` is the single validation source for the UI, REST/API v1, Agent
API, MCP, search/context, seed and import services, migration tooling, and OpenAPI. MCP
`blockwart.describe_schema(kind="project")` publishes the fields, bounds, typed-reference kinds,
normalization, conditional rules, and the Project-specific contract from that registry.

## Common contract

Every canonical Project requires `schema_version: 1`, one closed `category`, and one closed
`project_status`.

| Field | Shape | Contract |
|---|---|---|
| `category` | enum | `implementation`, `migration`, `research`, `experiment`, `incident_review`, or `other` |
| `project_status` | enum | `planned`, `active`, `paused`, `completed`, `cancelled`, or `archived` |
| `objective` | text | Reviewed purpose, at most 4,000 characters |
| `in_scope`, `out_of_scope` | text arrays | Explicit scope, up to 50 nonblank entries of at most 2,000 characters |
| `managed_by` | closed object | Provenance only: `{kind: principal, principal_id: ...}` or `{kind: person|team, label: ...}`; it grants no access and carries no credentials |
| `started_at`, `completed_at`, `review_after` | RFC 3339 timestamps | Timezone required and normalized to UTC |
| `related_assets` | typed-reference array | Existing `host`, `system`, `network`, `device`, or `service` targets |
| `related_runbooks` | typed-reference array | Existing `runbook` targets |
| `related_decisions` | typed-reference array | Existing `decision` targets |
| `related_projects` | typed-reference array | Existing `project` targets |
| `sources` | source-entry array | Up to 50 closed, safe external references; Blockwart never fetches them |
| `current_summary` | text | Current reviewed state, at most 4,000 characters |
| `open_questions`, `recommendations`, `next_actions` | text arrays | Distinct machine-readable current knowledge and follow-up lists |
| `lessons_learned` | text array | Retrospective knowledge shared by all categories |

`planned` rejects `started_at` and `completed_at`. Active and paused work requires
`started_at` and rejects `completed_at`. Completed work requires both timestamps. Cancelled and
archived records may represent work that never started, but if `completed_at` is present then
`started_at` is also required. Completion cannot precede start, and `review_after` cannot precede
completion (or start when there is no completion).

Unknown extension fields are additively preserved, but cannot replace these fields or bypass the
global nested secret checks. A field belonging to a different category is rejected at its exact
path rather than retained as contradictory canonical content.

## Safe sources and evidence

Each `sources` item requires a unique local `id`, `source_type`, `title`, and `url`. Source type is
the #144 shared vocabulary: `original`, `documentation`, or `reference`. Optional provenance is
`author`, `publisher`, `published_at`, and `retrieved_at`. Timestamps are timezone-aware;
retrieval cannot precede publication. Entries are closed, titles and provenance are bounded, and
URLs must be absolute HTTP(S) URLs without embedded credentials or secret-shaped query
parameters. Active-content schemes, executable/body fields, and secret-shaped keys or values at
any depth fail validation. The URL is stored and rendered as a safe external link only; Blockwart
does not download, preview, or import the original text.

Research `findings` are an ordered array. Each finding has a unique local `id`, a nonblank
`statement`, and one evidence grade:

- `source_backed` requires one or more unique `source_ids` that resolve to entries in `sources`;
- `observed` records a direct observation;
- `inferred` records an interpretation rather than presenting it as observation.

Optional `observed_at` and `verified_at` remain distinct from the catalog object's `updated_at`;
verification cannot precede observation. Multiple findings may conflict. Blockwart preserves
their separate IDs, statements, grades, sources, and timestamps and never merges one over another.

## Category fields

The category discriminator controls the allowed result fields:

| Category | Additional fields |
|---|---|
| `research` | `research_questions`, `hypotheses`, `methodology`, `findings`, `limitations`, `conclusions` |
| `experiment` | `hypothesis`, `setup`, `expected_result`, `observed_result`, `measurements`, `conclusion`, `reproducibility_notes` |
| `incident_review` | `incident_window`, `impact`, `detection`, `timeline_reference`, `root_cause`, `contributing_factors`, `remediation`, `prevention` |
| `migration` | `source_state`, `target_state`, `migration_plan`, `verification`, `rollback`, `outcome` |
| `implementation`, `other` | Common fields only |

An `incident_window`, when present, requires both ordered timestamps. A completed incident review
cannot complete before the incident ended. `timeline_reference` either names the append-only
object comments (`type: object_comments`) or one declared source (`type: source` plus
`source_id`). Experiment measurements are closed entries with a required name and quantity plus
optional unit and observation time; repeating the same name at the same time is ambiguous and is
rejected.

## Knowledge layers and authorization

Project fields are the current reviewed result state. Object comments are append-only chronology
and discussion. No comment or LLM output is automatically promoted into a finding,
recommendation, conclusion, status, or Decision. Audit records material canonical-field changes
and minimal comment metadata; it does not copy comment bodies or secret content. Typed Decision
links point to binding choices, and typed Runbook links point to resulting operational or recovery
procedures. Large originals stay in external documentation and only their safe minimized source
metadata is stored here.

Writes require every typed target to exist with the asserted kind. Authorized commands also
require read access to each target. Missing, wrong-kind, unauthorized, and concealed targets have
the same fail-closed public result. Read projections remove concealed typed links. Structured
`project_category`, `project_status`, and `related_object` filters require detail visibility;
discover-only stubs never expose or match hidden Project fields, evidence, source data, counts, or
relationship targets. Compact stubs contain no comments, while detail context returns
`recent_comments` separately from canonical `data`.

## Research example

This completed research keeps questions, evidence, limitations, conclusions, and next steps
separate:

```json
{
  "id": "cache-read-path-research",
  "kind": "project",
  "label": "Shared-cache read-path research",
  "data": {
    "schema_version": 1,
    "category": "research",
    "project_status": "completed",
    "objective": "Determine whether a shared cache should be piloted for read-heavy APIs.",
    "in_scope": ["Search and catalog-read endpoints", "p95 and p99 latency"],
    "out_of_scope": ["Write-heavy batch jobs", "A production rollout"],
    "managed_by": {"kind": "team", "label": "Platform Engineering"},
    "started_at": "2026-05-01T09:00:00Z",
    "completed_at": "2026-05-16T15:00:00Z",
    "review_after": "2026-08-16T15:00:00Z",
    "research_questions": [
      "Which read paths gain enough latency headroom to justify a shared cache?",
      "What invalidation risks appear during write bursts?"
    ],
    "hypotheses": [
      "A shared cache lowers p99 for repeated catalog reads.",
      "Write bursts temporarily erase that benefit."
    ],
    "methodology": "Replay an anonymized week of request shapes against an isolated two-node setup.",
    "sources": [
      {
        "id": "http-semantics",
        "source_type": "original",
        "title": "HTTP Semantics",
        "url": "https://standards.example/rfc/http-semantics",
        "author": "HTTP Working Group",
        "publisher": "Standards Archive",
        "published_at": "2022-06-01T00:00:00Z",
        "retrieved_at": "2026-05-02T09:30:00Z"
      },
      {
        "id": "replay-report",
        "source_type": "original",
        "title": "Isolated cache replay report",
        "url": "https://engineering.example/reports/cache-replay-2026-05",
        "publisher": "Platform Engineering",
        "published_at": "2026-05-10T10:00:00Z",
        "retrieved_at": "2026-05-10T10:05:00Z"
      }
    ],
    "findings": [
      {
        "id": "read-tail-improved",
        "statement": "Repeated catalog reads showed a 31 percent lower p99.",
        "evidence_grade": "source_backed",
        "source_ids": ["replay-report"],
        "observed_at": "2026-05-08T11:00:00Z",
        "verified_at": "2026-05-12T14:00:00Z"
      },
      {
        "id": "write-burst-regression",
        "statement": "Invalidation traffic raised p99 during the largest write burst.",
        "evidence_grade": "observed",
        "source_ids": ["replay-report"],
        "observed_at": "2026-05-09T13:00:00Z"
      },
      {
        "id": "bounded-pilot-inference",
        "statement": "A read-only pilot is safer than enabling the cache for every endpoint.",
        "evidence_grade": "inferred",
        "source_ids": ["http-semantics", "replay-report"]
      }
    ],
    "limitations": ["The replay excluded production user identifiers.", "Only two nodes were tested."],
    "conclusions": ["Pilot the cache on read-only catalog endpoints only."],
    "lessons_learned": ["Measure invalidation traffic independently from cache hit rate."],
    "current_summary": "Research is reviewed; a bounded pilot is recommended.",
    "open_questions": ["What is the acceptable stale-read budget?"],
    "recommendations": ["Create a binding Decision before the pilot."],
    "next_actions": ["Draft the cache pilot Decision.", "Write the cache-disable Runbook."],
    "related_assets": ["service:catalog-api"],
    "related_decisions": ["decision:cache-pilot-scope"],
    "related_runbooks": ["runbook:disable-shared-cache"]
  }
}
```

A comment such as “Replay rerun queued after the write-burst anomaly” is chronology on this
object. It does not replace either finding or change the recommendation.

## Incident-review example

```json
{
  "id": "upload-outage-review-2026-04",
  "kind": "project",
  "label": "Upload outage review",
  "data": {
    "schema_version": 1,
    "category": "incident_review",
    "project_status": "completed",
    "objective": "Explain the upload outage and prevent recurrence.",
    "managed_by": {"kind": "person", "label": "Incident Commander"},
    "started_at": "2026-04-02T03:00:00Z",
    "completed_at": "2026-04-09T12:00:00Z",
    "incident_window": {
      "started_at": "2026-04-02T01:10:00Z",
      "ended_at": "2026-04-02T02:40:00Z"
    },
    "impact": "Uploads failed for 38 percent of requests for ninety minutes.",
    "detection": "The synthetic upload probe alerted six minutes after the first failure.",
    "timeline_reference": {
      "type": "object_comments",
      "note": "Timestamped responder chronology is retained in this object's comments."
    },
    "root_cause": "A stale database connection pool was not recycled after failover.",
    "contributing_factors": ["The pool had no post-failover health check.", "The alert omitted the pool generation."],
    "remediation": ["Recycled the pool and drained failed workers."],
    "prevention": ["Add pool-generation health checks.", "Exercise failover quarterly."],
    "lessons_learned": ["Recovery checks must validate new connections, not only process health."],
    "current_summary": "Review approved and prevention work assigned.",
    "related_assets": ["service:upload-api", "system:upload-db-primary"],
    "related_decisions": ["decision:database-pool-health-policy"],
    "related_runbooks": ["runbook:recover-upload-db-failover"]
  }
}
```

The Decision is the binding health-policy choice. The Runbook is the executable recovery
procedure. Responder comments remain the append-only timeline; none becomes `root_cause` or
`prevention` without an explicit, audited Project update.

## Migration example

```json
{
  "id": "postgres-14-to-16",
  "kind": "project",
  "label": "PostgreSQL 14 to 16 migration",
  "data": {
    "schema_version": 1,
    "category": "migration",
    "project_status": "completed",
    "objective": "Move the catalog database to PostgreSQL 16 without data loss.",
    "in_scope": ["Catalog database", "Audit and comment history", "Rollback rehearsal"],
    "out_of_scope": ["Application feature changes"],
    "managed_by": {"kind": "principal", "principal_id": "svc-database-migration"},
    "started_at": "2026-06-01T08:00:00Z",
    "completed_at": "2026-06-12T22:00:00Z",
    "source_state": "PostgreSQL 14 single primary with nightly backups.",
    "target_state": "PostgreSQL 16 primary and verified streaming replica.",
    "migration_plan": [
      "Restore a production-shaped backup into the rehearsal environment.",
      "Run the schema and data verification suite.",
      "Freeze writes, perform the cutover, and retain the old primary read-only."
    ],
    "verification": [
      "Compare per-table row counts and foreign-key integrity.",
      "Verify IDs, grants, comments, audit events, and sequence next values.",
      "Run API, MCP, and installed-package smoke checks."
    ],
    "rollback": "Stop writes, point the application at the retained PostgreSQL 14 primary, and replay no partial changes.",
    "outcome": "Cutover completed in the maintenance window; all integrity checks passed.",
    "lessons_learned": ["Sequence verification belongs in every populated rehearsal."],
    "related_assets": ["system:catalog-db-primary", "system:catalog-db-replica"],
    "related_decisions": ["decision:adopt-postgresql-16"],
    "related_runbooks": ["runbook:rollback-postgresql-cutover"],
    "sources": [
      {
        "id": "pg16-upgrade",
        "source_type": "documentation",
        "title": "PostgreSQL 16 upgrading guidance",
        "url": "https://database.example/docs/postgresql-16/upgrading",
        "publisher": "Database Documentation Team",
        "published_at": "2026-01-10T00:00:00Z",
        "retrieved_at": "2026-05-20T09:00:00Z"
      }
    ],
    "current_summary": "Migration completed and the rollback window closed.",
    "next_actions": ["Archive the retained PostgreSQL 14 volume after the approved retention period."]
  }
}
```

## Legacy classification and migration

Existing free-form Project rows remain readable with the same IDs and data. Any rewrite must
satisfy the canonical contract. Blockwart never guesses category or status and never imports
external source text. `blockwart-db projects` performs a deterministic, read-only dry run by
default and reports blockers for missing or invalid category/status, ambiguous or contradictory
category fields, malformed source/evidence sections, invalid canonical lifecycle, stale digests,
and mappings for unknown or already-canonical objects.

A reviewed version-1 YAML mapping binds a shallow `data_patch` to the SHA-256 of the exact old
canonical JSON data. Unmentioned extension fields are preserved:

```yaml
version: 1
projects:
  - object_id: postgres-14-to-16
    expected_data_sha256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    data_patch:
      category: migration
      project_status: completed
      started_at: "2026-06-01T08:00:00Z"
      completed_at: "2026-06-12T22:00:00Z"
      source_state: PostgreSQL 14 single primary
      target_state: PostgreSQL 16 primary and replica
```

Review without writes:

```bash
blockwart-db --mapping projects.yaml projects
```

Apply is separately explicit:

```bash
blockwart-db --mapping projects.yaml --apply projects
```

Apply rejects every plan with a blocker and rejects a plan if any source row changed after
planning. The enclosing transaction makes a multi-row apply all-or-nothing. Successful changes
preserve IDs and unknown fields, increment the existing revision exactly once, and add a minimal
`project_normalize` audit event. There is no table-shape change, so #145 adds no Alembic revision;
SQLite and PostgreSQL 16 use the same data-only workflow without changing unrelated rows,
relationships, grants, comments, audit history, sequences, or foreign keys.
