# Needs attention

The attention view is one authorized, read-only answer to "what should someone
look at right now?". It introduces no new truth: it classifies the canonical
signals Blockwart already records into one deduplicated, severity-ordered list
that the HTML UI, REST v1, and MCP share.

An attention read is strictly a read. It runs no probe, opens no source file,
performs no DNS or network access, claims no lease, and writes no catalog,
audit, comment, coverage, or observation row. It also has no remediation model:
correcting a signal still uses the ordinary authorized write path of the domain
that owns it.

## Signals

`blockwart.domain.attention` owns the closed vocabulary; `blockwart.services.attention`
is the FastAPI-independent application resolver every surface consumes. Ten
categories stay semantically distinct, because they answer different questions
and are corrected in different places:

| Category | Question | Source of truth |
|---|---|---|
| `record_integrity` | Does the stored row satisfy the canonical schema? | catalog record diagnostics |
| `monitoring` | What does the current observation say? | the provider-neutral projection (`service-monitoring.md`) |
| `lifecycle` | What did an operator manually record? | canonical `lifecycle`/`health` |
| `endpoint` | Does the endpoint contract resolve one target? | monitoring target resolution |
| `placement` | Is the object placed in the canonical hierarchy? | canonical placement state |
| `relationship_integrity` | Do authorized relationships and typed references satisfy the domain rules? | canonical relationship diagnostics |
| `provenance` | Is the recorded provenance still fresh? | `provenance.md` |
| `runbook` | Is the Runbook reviewed and verified, and does a critical service have one? | `runbooks.md` and explicit service criticality |
| `knowledge` | Is the Decision/Project review current? | canonical review timestamps |
| `source_coverage` | Does the mapped inventory still match? | `source-coverage.md` |

Severities are `critical`, `warning`, and `info`. Item signal states are
`current` (present evidence asserts the problem now), `stale` (evidence exists
but passed its freshness boundary), and `unknown` (the signal applies but no
usable evidence exists). A whole category may additionally be
`not_applicable` in the summary when nothing in the authorized scope produces
that signal at all; an item never carries that value.

The closed reason codes are:

| Reason | Category | Severity | Signal state |
|---|---|---|---|
| `record_corrupt` | `record_integrity` | `critical` | `current` |
| `monitoring_observed_down` | `monitoring` | `critical` | `current` |
| `monitoring_check_error` | `monitoring` | `warning` | `current` |
| `monitoring_config_invalid` | `monitoring` | `warning` | `unknown` |
| `monitoring_observation_stale` | `monitoring` | `warning` | `stale` |
| `monitoring_never_observed` | `monitoring` | `info` | `unknown` |
| `lifecycle_health_down` | `lifecycle` | `critical` | `current` |
| `lifecycle_health_degraded` | `lifecycle` | `warning` | `current` |
| `lifecycle_health_unknown` | `lifecycle` | `info` | `unknown` |
| `lifecycle_maintenance` | `lifecycle` | `info` | `current` |
| `endpoint_target_unresolved` | `endpoint` | `warning` | `unknown` |
| `placement_missing` | `placement` | `warning` | `unknown` |
| `placement_relationship_invalid` | `placement` | `warning` | `current` |
| `relationship_target_unresolved` | `relationship_integrity` | `warning` | `unknown` |
| `relationship_primary_ambiguous` | `relationship_integrity` | `warning` | `current` |
| `knowledge_relationship_invalid` | `relationship_integrity` | `warning` | `current` |
| `relationship_domain_invalid` | `relationship_integrity` | `warning` | `current` |
| `provenance_stale` | `provenance` | `warning` | `stale` |
| `provenance_unverified` | `provenance` | `info` | `unknown` |
| `runbook_review_overdue` | `runbook` | `warning` | `stale` |
| `runbook_unverified` | `runbook` | `warning` | `unknown` |
| `runbook_deprecated_unresolved` | `runbook` | `info` | `current` |
| `critical_service_runbook_missing` | `runbook` | `warning` | `unknown` |
| `knowledge_review_overdue` | `knowledge` | `warning` | `stale` |
| `knowledge_review_unscheduled` | `knowledge` | `info` | `unknown` |
| `coverage_import_drift` | `source_coverage` | `warning` | `stale` |
| `coverage_mapping_ambiguous` | `source_coverage` | `warning` | `current` |
| `coverage_not_collected` | `source_coverage` | `info` | `unknown` |

An item carries only bounded safe content: the closed classification, a fixed
English `description`, an optional `detail_code` taken from an existing closed
domain vocabulary, an optional evidence timestamp, and one authorized
navigation reference (`kind:id` plus its detail path). No message, exception
text, endpoint, path, credential, source excerpt, or private mapping is part of
this contract. The browser view translates `reason_code` through the EN/DE
catalogs rather than rendering the machine `description`.

## Deduplication and ordering

Raw signals are collapsed to at most one item per target and category. Within a
category the registry order in `blockwart.domain.attention` is the published
priority, so the strongest raw signal wins and the weaker ones disappear
instead of repeating the same cause.

Ordering is severity, then category declaration order, then reason declaration
order, then the target reference. That total order is stable and does not
depend on database row order or dictionary iteration. Two facts are
deliberately reported in exactly one place: `mapped_stale` coverage is object
provenance and belongs to `provenance`; declared maintenance suppresses the
observed monitoring incident and is reported once as `lifecycle_maintenance`.

## Not an incident

An intentional state must never be published as a problem:

- planned and retired assets, and finished or withdrawn Runbooks, Decisions,
  and Projects, contribute no signal except record integrity;
- an active asset whose manual health has never been assessed remains
  `unknown`; this is distinct from disabled monitoring and from an observed
  incident;
- service Runbook readiness applies only when the schema-valid service document
  explicitly declares `criticality="critical"`; a missing value means
  `standard`, and no name, prose, tag, health, or monitoring state is used to
  infer criticality;
- a service without a monitoring document, or with `enabled=false`, is exactly
  "not monitored" and produces no monitoring or endpoint signal; its category
  reports `not_applicable` when nothing else is monitored either;
- declared `maintenance` is authoritative and silences the observed incident
  without deleting or hiding the observation;
- an explicitly declared unassigned placement is a reviewed decision, not a
  gap; only a missing parent without that declaration is reported;
- stale or missing evidence is reported as `stale` or `unknown` and is never
  re-interpreted as healthy;
- when no coverage snapshot exists at all, or the current snapshot contains no
  authorized mapped evidence, the summary reports
  `coverage_snapshot_state="not_collected"` and one `coverage_not_collected`
  item instead of claiming zero coverage problems or revealing source-only
  collection facts.

## Authorization and concealment

Authorization precedes items, counts, ordering, cursor binding, and errors. Only
objects the caller may read contribute signals; discover-only stubs contribute
nothing, so a detail-only fact cannot become a discover-only hint.

The derivation is authorization-stable by construction. Scalar signals are
read only after the object is readable. Runbook applicability and relationship
diagnostics use only READ-authorized typed references and relationships; the
canonical relationship diagnostic resolver runs on that projected snapshot,
and Attention consumes only its closed code plus a readable target. Diagnostic
messages, locations, and related references are never returned. A missing
endpoint is considered only when its ID is itself in the policy's READ scope,
so hidden, discover-only, and ordinary absent endpoints are equivalent. The
resolver reads the canonical placement state of the stored row rather than the
projected one, because a concealed parent downgrades the projected state to
`unknown`. Coverage rows come from the existing authorized resolver, which
removes concealed mappings before state resolution. Concealing an object
therefore removes its own items and changes nothing else: not another item,
count, signal state, order, cursor, or error.

Attention consumes only the object-scoped `mapped` coverage projection. Its
`collected` state is derived from that authorized projection and carries no
global snapshot timestamp. Source-only facts — unmapped operational entries,
missing sources, and orphaned references — stay behind the existing
platform-admin boundary of
`GET /api/v1/source-coverage?scope=all` and never appear here.

## Cost

The resolver loads catalog rows and relationships once and reuses that snapshot
for placement, Runbook applicability, and relationship diagnostics. It also
loads the observation index and bounded coverage snapshot once per request.
Database access does not grow per readable object, and concealed and absent
single objects take the same statement path.

## Surfaces

- `GET /api/v1/attention` — see `api-v1.md`.
- `blockwart.get_attention` — see `mcp.md`.
- `/attention` in the browser UI, linked from the catalog navigation, with EN
  and DE labels for every category, severity, signal state, and reason.

All three call `blockwart.services.attention.query_attention_page` and therefore
share one vocabulary, one deduplication rule, one order, and one authorization
decision.
