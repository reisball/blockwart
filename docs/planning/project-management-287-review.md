# Project-management acceptance and review follow-up

> Historical implementation/review evidence. For current usage and contracts,
> see [Project management](../project-management.md) and
> [Project workspace](../project-workspace.md). Past task ownership, commands and
> verification results below do not authorize new operations or prove another build.


Refs #287–#296; implementation PR #298. The general RBAC proposal #297 and
OpenClaw integration #173 are separate work, not included in this PR.

## Independent review R1

Reviewed immutable revision: `e8254b63a9a338f43b9b7762e0ad2d5e66d6b57b`.
The Quality route completed with 14 actionable findings (four P1, ten P2).
A successful review harness execution is **not** acceptance of the code.
The parent implementation owner reproduced the reported behavior before fixing it.

| Finding | Correction and regression coverage |
| --- | --- |
| F1: pre-lock access policy used for GitHub credentials | Refresh policy after the locked save and before credential use/projection; reauthorize idempotency replay under principal/project locks. Revoked-reference regression uses a synthetic token reader and no real network. |
| F2: concealed references in patch events | Project event changes with the same visibility rules as record/history data; discard nested credential-creation metadata. |
| F3: use-case acceptance survives stale child proof | Recursively require current mandatory child assessments; selected proof versions remain part of each child's acceptance basis. |
| F4: acceptance ignores effective GitHub status | Shared effective-work-state calculation across acceptance, derived context, blockers, filters and summary. Unknown upstream state does not count as done. |
| F5: acceptance ignores dependency predecessors | Include `depends_on` in acceptance scope; retain separate order-only `precedes` semantics. |
| F6: old PUT creates an invalid typed hybrid | Preserve explicitly classified PM types on omitted type fields, then revalidate the complete merged payload before storage. |
| F7: historical task edits corrupt requirement revision lookup | Replay the actual write-side revision algorithm, including explicit task-to-requirement classification. |
| F8: short-code self-parent bypass | Canonicalize parent UUID before checking the full parent chain. |
| F9: cross-type supersession | Require both endpoints to be the same semantic type, including inbound-edge revalidation. |
| F10: secondary GitHub failure overrides leading issue | Check repository-version freshness only for the authoritative leading reference; retain secondary failures as diagnostic observations. |
| F11: completed decision counts as implementation | Keep decision traceability but only genuine implementation tasks satisfy implementation coverage. |
| F12: reordered legacy source produces duplicates | Preserve unique source-occurrence identity across reordering; require reconciliation for ambiguous identical text; never rewrite original import provenance or create a speculative duplicate. |
| F13: dependency filters absent from channel surfaces | REST/MCP/UI filters for direct dependency and unresolved blocking state; query-bound pagination, canonical IDs, concealment and parity tests. |
| F14: stale schema/tool/migration expectations | Update reviewed MCP schema digest, exact tool inventory, all five new OpenAPI operations, database table/head expectations, installed-package and container probes. |

Durable regressions are in `tests/test_project_review_regressions.py`,
`tests/test_project_management.py`, `tests/test_project_dependency_filters.py`
and the existing migration/contract suites. Tests use synthetic catalog data.

## Data-preservation rehearsal

A consistent read-only SQLite backup of the existing installation was migrated
in a private isolated candidate database from schema 0029 to 0030. All original
columns/rows across **24 original tables** retained identical fingerprints;
integrity and foreign-key checks passed. The original database and running
service were not modified. Raw snapshots and private operational details are
not repository artifacts.

## Delivery boundary

The package version remains **0.1.0** pending completed verification and Kai's
separate merge/release decision. **0.2.0 is a candidate**, not an already-created
release. No automatic issue closure, production rollout or destructive downgrade
is part of the implementation evidence. A populated downgrade refuses to erase
PM records/events.

The PR contains revision-bound test/review outcomes; an earlier result must not
be presented as verification of a later commit.

## Native independent review R2

Exact reviewed revision: `072bbd9b1cb06d20a7cece893169fe2a944514c5`.
Quality-route admission was unavailable because Nova's Kutscher MCP was not
connected. An independent native reviewer examined the immutable checkout;
this is **not** a second Quality-route review success.

Three P2 findings were independently reproduced by the parent on both SQLite
and PostgreSQL (six desired-behavior failures before correction):

1. After deleting one of two identical legacy source entries, unique current
   text did not establish unique historical identity. The import event now
   persists original occurrence cardinality, and only originally and currently
   unique occurrences qualify for reorder matching. Ambiguous deletion remains
   reconciliation-required; original provenance is preserved.
2. Requirement overview listed only direct blockers while acceptance correctly
   rejected blockers on implementation work. Overview now derives unresolved
   `depends_on`/`blocked_by` predecessors from the same relevant work scope,
   without including unrelated project blockers.
3. Overview displayed a historical accepted result without its stale flag.
   It now explicitly renders current/review-required assessment state, matching
   the record detail view; derived coverage still excludes stale acceptance.

The three independently authored desired-behavior reproductions are retained
in `tests/test_project_review_regressions.py`. Subsequent PR evidence names the
corrected exact revision and its own checks; R2 is not approval of the fixes.

The full 072bbd9 suite additionally exposed two legacy network-classification CLI assertions still expecting schema 0029. The isolated reproductions confirmed that classification behavior was correct and only the exact schema-head expectation needed updating to 0030. These assertions remain strict rather than dropping the revision check.


## Native independent review R3

Exact reviewed revision: `c2f868a23eb96df3bc50219927cdccfb067fb1bd`.
The native reviewer verified all three R2 corrections and found two additional
P2 boundaries. The parent reproduced both on SQLite and PostgreSQL: four
expected failures and six successful adjacent checks before correction.

- A use-case exception for explicitly unaccepted child scope was immediately
  stale. Exception currentness now permits precisely the recorded unaccepted
  children, while assessment identity, requirement revision, effective work
  state and selected child proof versions remain part of its review basis.
  Later child assessments and edits to already-stale child proofs invalidate
  the exception and require a renewed review. Ordinary acceptance remains
  strict and accepted children still undergo recursive currentness checks.
- Generic record creation could forge `legacy_origin`, bypassing historical
  ambiguity checks and import-event provenance. Only the dedicated import
  service may create adoption provenance; the shared write validator also
  repeats reconciliation under the project lock. Generic API/MCP/UI saves
  cannot opt into that internal service flag. Existing provenance is immutable.

Permanent regressions include both reproductions, unique-provenance forgery,
subsequent exception staleness, preserved import-event cardinality and scoped
transitive blocker behavior. No database migration or version bump is added.
Exact corrected-revision test and review evidence is recorded on PR #298.

The completed historical 072bbd9 full run had 2412 passed and four failures:
the two network CLI assertions above plus seed CLI and SQLite backup/restore
assertions still pinned to 0029. The latter two were also independently
reproduced against the R3 checkout, showing actual migrated head 0030 versus
expected 0029. All current-head assertions are updated strictly to 0030;
intentional downgrade targets, migration history and deterministic release
host-fake revision fixtures remain unchanged.
