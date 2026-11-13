# UX v5 — local acceptance / handoff

2026-11-13, branch t0449-ux-v5, unchanged base HEAD
b3c586c39f8d3bfd831565e44cb8f22ccc59d268.
No commit, push, PR, merge, deploy, runtime/config/secret/auth/RBAC/database-model change.

## Acceptance matrix

| Area | Implementation and local evidence | Result |
|---|---|---|
| Navigation | Shared five destinations: Catalog, Topology, Projects, Hints, Activity. No left rail. Existing right inspector retained. Global search and Settings separate; Updates/Integrations under Settings. Root/child creation remains in content. | PASS |
| Search | First global entry is All Types, independent of catalog type. Explicit choice and text survive dialog close/reopen until page reload. Catalog search remains type-bound. Visible removable chip and zero-result expansion retain text. Object and project-content groups stay independent; Enter opens, Escape closes and restores focus. Debounced stale requests cannot reopen obsolete hits. | PASS |
| Counts | Authorized stock by type is independent of text/depth. Full object matches come from the existing unpaginated server result, visible object rows counted separately, synthetic headings excluded, real hardware roots included. Content total 25 vs loaded 20/5 exercised; hidden/discover-only content and release counts excluded. All numbers here are synthetic fixtures, not inventory claims. | PASS |
| Tree | Full hardware parent rows have eight cells and real fields/ref/detail action. Roots / Through hosts / Through services: fixture 2 / 7 / 10 object rows. Direct hardware service is hidden through hosts, shown once through services. An unrelated manually opened branch does not reveal it. Radio keyboard arrows/Home/End, manual marker, detail-return state and immutable named snapshots exercised. Saved views are principal-scoped, session/tab-local, not server records. | PASS |
| Hints | Critical / Warnings / Information links toggle off on second click; All and removable active-filter link reset priority without losing other filters. Filter form retains priority, cursor resets appropriately. Original Critical=1 assertion preserved against rendered badge plus API count, with wrong-number negative control. Existing 102-row pagination tests remain green. | PASS |
| Activity | Berlin Today/Yesterday/date + HH:mm; exact unchanged datetime/title, other year visible, invalid time unknown. Spring/autumn DST and midnight tested. Active stable-ID principals resolve in one batch only for self/admin/existing target access-manager visibility; Human / Service account are evidenced account types, never invented Agent/System. Legacy logins, inactive/missing/unavailable identities stay Not assigned; absent attribution stays Not recorded; technical value is disclosed only in details. Canonical searchable targets combine with existing filters; invalid input retains previous target and gives an error, never broadens to All. Existing service cursor/filter/API envelope tests stay green. | PASS |
| Settings | Badge counts available readable service updates (fixture 1 among 3 enabled monitors), not messages or app installations. Existing release view reachable from Settings, not main navigation. Integration page reads mapped source coverage, never crawls/collects; absent evidence remains unknown. | PASS |
| Responsive/theme | Real local FastAPI + migrated synthetic SQLite, Chromium at 1440/1024/390 in Light/Dark. Local table/type/nav scrolling, all columns retained, no whole-page horizontal overflow in exercised pages. Screenshots inspected, no JS/console errors or external runtime requests. | PASS |

## Raw evidence (ignored, retained locally)

All paths below are relative to repository root, under exports/ux-v5/:

- acceptance-tests.log: **210 passed** (UI, new UX-v5, attention filters, activity, workspace search, release monitoring), 187.48s.
- adjacent-tests.log: **51 passed** (attention view/tasks, source coverage), 17.36s. These add 51 distinct tests; **261 unique tests** across those two gates. Not a full repository suite.
- activity-final-projection.log: **46 passed**, 23.04s, targeted recheck after replacing heavy browse/tree construction with the existing lightweight authorized object projection for activity choices.
- browser-results.json, browser-summary.json, browser.log, server.log: **90 browser checks / 6 viewport-theme runs / 48 screenshots**, PASS. Zero console errors, zero external requests, zero non-aborted request failures. net::ERR_ABORTED entries are cancelled search requests or page-navigation cancellation, not suppressed application failures.
- browser-final-projection-results.json and browser-final-projection.log: final lightweight activity-target projection additionally rechecked at 1024 Light, **15 checks / 8 screenshots, PASS**. Other viewport/theme evidence concerns unchanged rendering/interaction paths.
- browser.cjs, browser_app.py, run-browser.sh: exact local fixture/runner, loopback only. Existing production auth is not modified: test-only dependency override uses synthetic principals. Pollers disabled in that local fixture. Test server is stopped after each run; no live system touched.
- lint.log, js-check.log, diff-check.log: Ruff, all three changed JS syntax checks, whitespace check.
- inherited.patch, resumed-handoff.patch, concurrent-observed.patch: takeover snapshots. Foreign in-progress changes were retained and audited. Only positively identified temporary _zzz_dbg3 debug code was removed. The transient dataclass ordering error disappeared after the confirmed freeze; inherited catalog 500 was caused by undefined release_update_count and fixed at its source.
- final.patch includes tracked and new source/tests/docs; final-manifest.json binds file hashes for handoff.

Use the editable .venv-ux environment: .venv points at an installed package and does not prove this source tree. Tests use isolated fixture databases only. Do not restart the invalidated old baseline.

## Manual dependency/contract audit (GitNexus unavailable)

Complete dispatch/preflight registry: 12 repositories, no Blockwart index. A later read-only recheck failed with MCP runtime-disposed; raw failure in gitnexus-recheck-error.txt. No unrelated repo selected and no index writer/reindex run. Graph impact/freshness stays **UNKNOWN**, not clean.

Direct source tracing covered:

- query_catalog_browse → _index_template_context → index.html → index.js; callers include catalog, integrated object details, failed create/edit rerenders. Shared browse/count query unchanged.
- query_attention_page → UI + existing REST/MCP consumers; priority links are a UI projection, existing severity vocabulary/query/cursor unchanged.
- query_activity_page → UI, REST v1 and MCP; optional display fields do not change the explicit public envelope. Existing actor string and stored audit time are not rewritten. Page/total/cursor authorization remains the existing service contract. Target choices use list_catalog_objects rather than building topology/monitoring.
- search_workspaces → existing workspace UI/REST/MCP + new smart-search UI; same authorization/total/cursor semantics, object type does not restrict content.
- query_release_overview → existing release UI/REST + read-only navigation count; same status/authorization/total semantics.
- query_source_coverage_page(scope=mapped) → existing service consumers + read-only Settings view; no snapshot recording or source-file access.
- Shared navigation included only in touched primary/Settings/search surfaces. No project-detail redesign, topology-focus mode, mobile fixed column, migrations, external sends or prototype edits.

## Limits / follow-up gates

- Local acceptance only. Parent owns independent review, any required remote CI/forge approval, and separate publication/runtime authorization. No production behavior or user acceptance claimed.
- No full repository suite, full WCAG audit, real mobile-device test, production login/session test, large-inventory performance benchmark, or live upstream release fetch.
- Legacy login attribution is intentionally unresolved: current login uniqueness cannot prove historical ownership/recycling. No identity or RBAC redesign is hidden in this display work. Service account is not automatically an Agent. Inactive/unavailable profiles never receive invented names.
- Saved views last for this browser tab/session and are bound to the current principal; they are not synchronized persistence or a new data model. Existing catalog has no sort control to persist.
- Tables and tab strips scroll locally at narrow widths. No fixed identity column or new mobile scroll-affordance experiment was added.
