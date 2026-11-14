# Search consistency — contribution requirements

## Goal and authority

Define the five-domain search follow-up for upstream PR #340. This is a focused UX-v5 correction; maintainer review and required checks remain prerequisites for merge. Preparing the contribution does not authorize a production deployment.

## Required behavior

1. Local search filters the active area. Global results are available separately through “Search everywhere” / Ctrl+K, never implicitly while typing into local search.
2. The five areas use the same search position, composition and interaction. Scope labels are explicit: “Katalog durchsuchen”, “Topologie durchsuchen”, “Projekte durchsuchen”, “Hinweise durchsuchen”, “Aktivität durchsuchen” (and complete English equivalents). Preserve compact header/toolbar geometry and responsive wrapping.
3. Catalog and topology share query and compatible object filters: switching changes representation, not the selected object set. Unsupported filters must be visibly explained, not silently discarded. Preserve category/services/network/mode state where applicable.
4. Projects, hints and activity each retain their own query and structured filters on departure and return. Do not inject a catalog query into these unrelated domains. Clearing affects only the current domain, or the shared catalog/topology domain. Native GET forms/deep links must remain valid without JS. Persist state only in principal-scoped, tab/session-local state; do not expose it across users. Explicit URL state wins over stale stored state.
5. Projects searches projects plus searchable project contents, with explicit result types and authorized navigation to matched content. Hints searches visible hint contents and referenced objects. Activity searches event text, permission-safe resolved author labels and target objects. Existing target search remains a separate structured filter, not a replacement for text search. Existing structured filters combine with query.
6. Global Ctrl+K starts with All Types independent of local type filter. An explicit global type selection may survive close/reopen as already agreed until reload. “Search everywhere for ‹query›” copies local text only on an explicit click. Global search does not overwrite local states.
7. Empty results keep the local query and offer the explicit global-search action. Displayed match counts apply to the query plus structured filters; inventory counts remain distinct. Do not present loaded rows as a full paginated total.

## Acceptance / regression proof

- Catalog → topology → catalog keeps query and compatible filters; unsupported-filter handling is visible. Both native forms still submit correctly, including JS-disabled operation.
- Distinct project/hint/activity queries and filters survive navigation out/back; one-domain reset does not change another. Browser back/deep links and user-scope boundaries covered.
- Each domain returns actual matches and excludes nonmatches with combined filters; projects include page/task/log matches with labeled types. Activity matches permitted display-name and target-object examples without revealing restricted profiles; pagination/cursors stay correct for all text filters.
- Explicit global handoff preserves query, starts with All Types, and does not alter local query/filter state; Enter/Escape/focus/stale-response contracts remain.
- Search content is escaped; no new secrets, hidden/discover-only content or authorization leaks. SQLite and PostgreSQL contracts remain supported. No migrations or public REST/MCP envelope changes unless unavoidable and separately surfaced.
- Real fixture browser checks: 1440 and 390px, Light/Dark, no whole-page overflow, visible operable controls, zero unexpected JS/console errors. Regression checks against the existing UX-v5 acceptance matrix.

## Boundaries / rollback

No auth-policy rewrite, data migration, timestamp-default/cache-header task, production DB/write, deployment or topology-graph redesign. Existing full object columns, parent rows, tree depth behavior, stock/count semantics, hint priorities, activity attribution/time formatting, settings/release/source coverage remain intact. Additions beyond PR340 are explicitly the five-domain search behavior and shared state above. Rollback is revert of this isolated follow-up commit; production remains unchanged.

## Source evidence

The upstream-review corrections and their bounded, source-specific verification
are recorded in [PR340-REPAIR.md](PR340-REPAIR.md). That evidence does not replace
the unchanged requirements above or the independent review/final CI gates.

The existing UX-v5 acceptance baseline is recorded in [ACCEPTANCE.md](ACCEPTANCE.md): five direct destinations, no left rail or global root-create, compact navigation, global grouped search, full catalog rows, separate stock/match/visible counts, and domain-safe activity display and filters. The requirements above make the follow-up local/global search contract explicit for review in PR #340.
