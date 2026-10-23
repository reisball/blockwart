# Project-management acceptance and review follow-up

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
