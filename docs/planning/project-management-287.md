# Project management implementation plan · #287

> Historical implementation/review evidence. For current usage and contracts,
> see [Project management](../project-management.md) and
> [Project workspace](../project-workspace.md). Past task ownership, commands and
> verification results below do not authorize new operations or prove another build.


Authorized 2026-10-23. Candidate 0.2.0 is a post-completion decision, not a release or version bump. Main baseline: `c0d6c8d1b53bcbdca650dae69c45c7361cb51530`.

## Scope and evidence

Implement all nine child issues with the synthetic practice scenarios recorded in their comments. The general RBAC concept #297 and OpenClaw wrapper #173 are separate. Existing projects are never automatically reclassified.

| Issue | Implemented surface | Durable verification |
|---|---|---|
| [#288](https://github.com/reisball/blockwart/issues/288) | Typed items/relations, original and revised requirement wording, same-type supersession; `schemas/project_workspace.py`, `services/project_management.py` | `test_typed_shared_requirements_stable_codes_and_invalid_graphs`, `test_scoped_requirement_variant_does_not_change_other_use_case`, same-type supersession regression |
| [#295](https://github.com/reisball/blockwart/issues/295) | Shared targeted patch/comment/assess/reuse/sync commands, record ETags, atomic project invariants; REST and five MCP tools | `test_record_cas_independent_edits_omitted_empty_and_idempotent_comments`, `test_parallel_record_updates_and_global_cycle_invariant`, `test_mcp_targeted_action_and_record_resolution_match_rest` |
| [#289](https://github.com/reisball/blockwart/issues/289) | Stable codes, UUID/code detail navigation and contextual hierarchy; `ui/project_workspace.py`, workspace/detail templates | Stable-code/parent normalization tests, paged contextual-tree assertions in `tests/test_project_management_ui.py`; installed-wheel browser assets |
| [#290](https://github.com/reisball/blockwart/issues/290) | Record detail with immutable actor/time discussion and safe Markdown, distinct paginated events/history | `test_comments_pagination_access_and_new_instance_concealment`, UI detail/comment workflows and trusted-origin regressions |
| [#291](https://github.com/reisball/blockwart/issues/291) | Criterion/revision-bound proofs, explicit acceptance/reuse/exception, scoped overview and stale review state | Decision/partial-proof/reuse tests, stale-child-proof regressions, current exception and later-proof-change tests |
| [#292](https://github.com/reisball/blockwart/issues/292) | Priority, assignee label/principal, archive, separate dependency/blockade/order and channel-parity filters | `test_priority_archive_preserves_identity_history_and_discussion`, `tests/test_project_dependency_filters.py`, transitive scoped-blocker regressions |
| [#293](https://github.com/reisball/blockwart/issues/293) | Optional multiple repository records; typed issue/PR/full-SHA references and unique identities | Repository validation and reference tests in `tests/test_project_management.py`; malformed/cross-project references and concealment |
| [#296](https://github.com/reisball/blockwart/issues/296) | Explicit legacy adoption/provenance, curated versus derived authority, versioned narrative references and historical successors | Legacy import/reorder/cardinality/forgery regressions; `test_requirement_original_immutable_and_documented_pages_detect_drift` |
| [#294](https://github.com/reisball/blockwart/issues/294) | Explicit GET-only opt-in observer with one leading issue, freshness, bounded public HTTPS and exact credential binding; `services/project_github.py` | `test_repository_link_validation_and_optin_observations_are_not_acceptance`, DNS rejection, credential ownership/revocation and secondary-observation regressions |

Test names above are in [PM service/API/MCP tests](../../tests/test_project_management.py),
[record compatibility tests](../../tests/test_project_records.py),
[review regressions](../../tests/test_project_review_regressions.py),
[dependency parity tests](../../tests/test_project_dependency_filters.py) and
[rendered UI tests](../../tests/test_project_management_ui.py).
The additive schema is covered by `test_populated_0029_upgrade_preserves_all_original_columns`,
existing migration/SQLite/PostgreSQL tests and installed wheel/container probes.

## Verified practice requirements translated into synthetic checks

The read-only practice analysis recorded on [the epic](https://github.com/reisball/blockwart/issues/287#issuecomment-6368585440)
and linked child comments is the public evidence boundary. Private project text,
endpoints and runtime artifacts are not copied into this repository. These are
model/workflow requirements, not a claim of acceptance of another project's runtime.

| Practice finding | Implemented synthetic acceptance case |
|---|---|
| A completed decision is not implementation or proof | Decision traceability stays visible but cannot remove `without_implementation`; ordinary acceptance still needs explicit mandatory criteria/proofs. |
| UC-A changes manual to automatic approval, UC-B stays manual | Scoped successor/variant retains original baseline and UC-B links; old evidence is neither silently transferred nor deleted. |
| Component success does not imply E2E/use-case acceptance | Criterion-scoped proof leaves missing E2E criteria and unaccepted child scope visible; explicit reasoned exceptions are distinct and become stale after subsequent relevant change. |
| Informative/background scope creates no artificial detection obligation | Optional criteria remain outside the mandatory denominator; no invented zero-error or technical-chain criterion. |
| Executable work, prerequisite, external blocker and deferred work differ | `precedes` only orders; `depends_on`/`blocked_by` affect relevant scope; unrelated blockers are excluded; archive/defer is not completion. |
| Current result and older narrative may diverge without being a contradiction | `documents`/`informed_by` pin exact versions; stale references warn without rewriting curated text or automatically completing work. |
| Historical content and current authority must stay explicit | Page lifecycle/same-type successor links and immutable events preserve history; most recent edit alone never confers authority. |
| Projects may have zero or several code repositories | No repository is required for local work; optional repository records and multiple typed links remain separate from task/requirement authority. |
| Duplicate legacy text cannot be guessed after source changes | Originally unique occurrences retain identity across reorder; ambiguous cardinality changes require reconciliation; generic saves cannot forge provenance. |

## Delivery sequence

1. Typed models, immutable history and additive migration; record-scoped CAS actions without weakening project invariants (#288/#295).
2. Hierarchy, task detail/discussion, planning, repository references (#289/#290/#292/#293).
3. Requirement baselines/revisions, scoped evidence, explicit acceptance and legacy authority (#291/#296).
4. Opt-in read-only GitHub observation with one leading issue and explicit freshness/error state (#294).
5. Full regression, SQLite/PostgreSQL migration preservation, API/MCP parity and browser workflow; independent exact-revision review and documented fixes.

## Invariants

- Task done, implemented, criteria verified and requirement/use-case acceptance are separate facts.
- Decision completion never supplies implementation proof; evidence binds a requirement revision, criterion set, subject/run/version and scope.
- Old evidence is not silently reused on changed requirements. Explicit reuse decisions and exceptions retain actor/time/reason.
- Existing UUIDs, record JSON, history, project lists and curated summaries survive migration. New short codes supplement UUIDs.
- Legacy imports are explicit, deduplicated and retain original text; imported entries point to the structured authority, not two current sources.
- Project instance, authorization, trusted channel provenance, idempotency and atomic project CAS remain enforced.
- No credential values in data or GitHub; integration is opt-in, GET-only, no implicit acceptance, no background integration credential provisioning.

## Data-preserving verification

Use synthetic databases first. For live-state migration rehearsal use a verified consistent backup in an isolated test instance; compare original objects, relationships, grants, records and append-only histories before/after. Do not migrate or overwrite the live instance merely to run tests. Any authorized instance test creates isolated synthetic records; existing POC content is not edited. Preserve recoverable backup and document integrity evidence before any rollout.

## Coordination

Nova owns integration, repository evidence, implementation and final verification. Bounded native subagents audit acceptance/migration and GitHub semantics and implement non-overlapping UI files. Workboard `blockwart`; session Goal tracks the full objective. PRs reference issues without automatic closure. Merge, issue closure and final release are separate decisions unless explicitly authorized.
