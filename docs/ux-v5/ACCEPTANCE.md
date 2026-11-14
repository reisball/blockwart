# UX v5 acceptance and review status

## PR #340 review-repair applicability

The later local repair is documented in [PR340-REPAIR.md](PR340-REPAIR.md). Its
real-role regressions and source-bound browser counterchecks are separate from
the historical PASS matrix and release/CI evidence below. They do not authorize
merge or deployment; independent review and final required remote CI remain open.

The implementation and compact-mockup follow-up are committed. The previous isolated
UI-only release is 8128797959d4b82ed1b6329e153110e0d02b01d5.
The release coordinator recorded [full CI success](https://github.com/reisball/blockwart/actions/runs/43525957700)
for that exact commit: 2,999 tests and 39 subtests, plus OpenAPI, installed-package
and container gates. Its rollout was separately verified by the coordinator.
That evidence does **not** certify the later upstream-integrated PR head.

The PR branch now normally merges upstream main
b3c586c39f8d3bfd831565e44cb8f22ccc59d268, preserving release ancestry and all
upstream Safe, project-instruction, schema and CI content. This is upstream-review
preparation, not another production rollout. Final-head full CI, applicable
independent review/forge approval, and maintainer/human acceptance remain gates.
See [deployment boundaries](DEPLOYMENT.md).

## Approved scope and compact composition

The existing functional criteria below remain unchanged. The screenshot follow-up
standardizes all seven header buttons and places native catalog search/scope in
the same toolbar as root creation, child creation and View. The approved compact
SOLL composition otherwise remains: initially collapsed
View disclosure; contextual closable right inspector; compact global-search
query/type/Escape row and grouped results; actionable hint results before collapsed
diagnostics; readable activity target/event/date controls with secondary filters;
and a compact Projects heading with native filter disclosure. No sidebar, deleted
object columns, mobile fixed-column experiment, or project-detail redesign.

Activity's friendly date edits submit midnight UTC; an existing exact RFC3339
instant remains untouched until edited. Without JS the original RFC3339 control
still works. This does not repair or offset stored audit timestamps. Service
accounts are labelled Service account / Servicekonto, never invented Agent/System.
The scoped topology GET search retains mode, type, category, services and query;
it remains independent of global smart search and placement topology.

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

## Header and catalog-toolbar screenshot follow-up

The isolated correction is 0050e3f85b252f44ae99ea82e3b49bc45a66ab8e, directly
based on 8128797959d4b82ed1b6329e153110e0d02b01d5, with no upstream Safe,
schema, authorization or configuration changes. It changes only UI assets,
templates/cache tokens and the native-form regression test. It is also normally
merged into the upstream-integrated candidate; neither new candidate inherits
the previous release's full-CI or rollout approval.

Numerical Chromium checks at 1200px and 1440px in Light/Dark show all seven
header buttons at 40px height, 7px radius and 8px vertical / 12px horizontal
padding. The active destination remains distinct. Search input, submit, root,
child and View share one horizontal toolbar centerline. At 390px the toolbar
wraps, with no whole-page overflow and all five controls operable. Native search
retains view/kind/q, including JS-disabled submission; global smart search is
unchanged. Synthetic catalog-owner fixtures exercise both creation controls
without submitting writes. Six screenshots and per-control measurements live
under exports/ux-v5-header-toolbar/; the exact source and image hashes are in
its local evidence manifest. These are focused local checks, not full CI.

## Evidence applicability

- The original 173-test run preceded the final asset-cache-version edits. It is
  historical evidence, not an exact release-head or final PR-head gate.
- The compact-composition browser run at f069ae7 exercised 120 checks across
  six viewport/theme combinations and retained 66 screenshots. Its independent
  review was PASS_WITH_NOTES for 1574db2..f069ae7, not approval of later merges.
- The 8128797 repair passed 55 scoped tests and a nine-case decisive gate,
  including six negative controls. Wrong topology target/missing network mode
  and wrong Project target/method/missing controls fail rather than being hidden
  by the unrelated global-search form. The intended versioned Explorer stylesheet
  is fetched and its 19px tree-toggle minimums are checked, without pinning a stale
  cache token. Thirty-five browser scenarios across seven contexts included
  JS-disabled native submits. Full release CI is linked above.
- The upstream integration has its own scoped source-bound test/browser evidence;
  retained local logs are under exports/ux-v5-upstream/. Results and exact source
  hashes are recorded there. They are not a second full-suite or production check.

## Reproducing focused source checks

Use an isolated environment with project development dependencies installed.
Do not assume an interpreter's installed package is this checkout. Before testing:

~~~sh
PYTHONPATH="$PWD/src" "$PYTHON" -c 'from pathlib import Path; import blockwart; assert Path(blockwart.__file__).resolve().is_relative_to(Path.cwd() / "src")'
~~~

Here PYTHON is the selected isolated environment's Python executable. Run scoped
UX, network/project forms, locale, authorization, project-instruction and Safe-UI
seams against owned synthetic fixtures only. Do not supply production DSNs, real
provider credentials or a real user's browser profile. Keep raw logs and screenshots
outside tracked source. Independent review probes and final required remote CI
remain separate from author self-verification.

## Dependency and security seams

GitNexus's complete live registry has no Blockwart record. Graph impact/freshness
is **UNKNOWN**, not clean; no unrelated repository or reindex was substituted.
Direct source tracing covers shared browse/detail/validation contexts, attention
and activity UI/REST/MCP consumers, workspace search, authorized release counts,
and mapped source coverage. Existing service authorization, totals, cursors and
public envelopes remain the contracts. Escaped dynamic markup/Jinja autoescape
must not be replaced by unescaped interpolation.

Integration must preserve both language dictionaries, all upstream Safe and
project-instruction keys, and all UX keys. The locale resolution is a structural
three-way union, not choosing one entire side. Upstream security, migration,
configuration and audit code is retained as upstream content, not redesigned by
this UI work. Safe value reveal/write permissions and CSRF remain independent
from ordinary metadata access; values are not prefetched or inserted into search.

## Limits and follow-ups

No full WCAG audit, physical-device test, large-inventory benchmark, production
login/session test or live release-provider fetch is claimed by local UI probes.
Saved views remain principal-bound, tab/session-local snapshots, not synchronized
server persistence. Tables and tab strips scroll locally at narrow widths.
Legacy identities remain unresolved when current data cannot prove historical
ownership. Timestamp-default investigation and Cache-Control consistency on
activity/hints/projects remain separate follow-ups, not hidden changes in this PR.

## Five-domain search follow-up (14 November)

The isolated follow-up implements SEARCH-CONSISTENCY.md on PR340 base
33d8a77df8b5a24e0d516b806bb961faf6073946. It is not deployed.

- All five destinations render the same compact native GET search component in
  the heading/toolbar with explicit English/German domain labels. Local typing
  never invokes global search. The explicit query handoff opens All Types;
  ordinary global close/reopen retains the chosen global type until reload.
- Catalog/topology share query/type and retain network mode/category/services in
  native cross-view links. Unsupported object types and placement-inapplicable
  network options are explained visibly, not silently removed. Topology may show
  context parents; these are representation context, not additional matches.
- Projects, hints and activity retain independent structured filters/text through
  principal-scoped sessionStorage navigation links. Current URLs (including empty
  queries), deep links and browser history are authoritative. Clearing removes
  only that domain. No localStorage query persistence or server storage.
- Projects search authorized project metadata plus current pages/tasks/logs with
  explicit result types and existing permission-checked links. Category/status
  filters apply before paging; private UI project hits do not alter the REST/MCP
  workspace-search envelope or its accepted public kinds.
- Hints filter authorized derived items' visible translated reason/help and target
  text before summary/count/pagination. Activity filters the existing safe event
  summary/type, permitted resolved author label and target label/reference, not
  raw audit JSON or restricted profiles. Its target picker remains a separate
  intersecting filter. Text cursors bind query and existing filters. Activity
  scans bounded chunks and may return an empty continuation page at the scan
  budget; loaded-row counts are never presented as a full paginated total.
- Escaping, public search envelopes, discover/concealed-content denial, native
  forms and existing attention/activity cursor regressions are exercised.
  Separate small original-agreement repair: Settings has an inline decorative
  gear plus accessible text/title; seven header-control geometry is preserved.

Focused raw evidence remains local/untracked under exports/ux-v5-search/:
final-search-gate.log (66 tests), new-tests-gate.log (7 focused new tests),
and the final combined frozen-focused-gate.log (84 tests),
topology-tests-final.log (16 tests), browser-results.json, fenced fixture/server/request logs,
and twenty screenshots (five domains x 1440/390 x Light/Dark). Source imports
are explicitly bound to this checkout; no production database or IP network.
Browser proof covers actual matches/nonmatches, domain isolation and reset,
deep links/back, explicit global handoff, global type retention/Escape, JS-disabled
native GETs, visible Settings icon/name, control hit-testing, no whole-page
horizontal overflow and no unexpected console/JS errors. Screenshots inspected.
Measured query-input widths are 272–754px at 1440 and 281–288px at 390;
all seven navigation/action buttons retain 40px height, 7px radius and 8/12px
padding. The visibility oracle rejects an intentionally hidden submit button.

GitNexus's complete live registry has 21 repositories and no Blockwart:
impact/index freshness remains UNKNOWN. direct-callers.txt traces UI, REST and
workspace service callers; MCP retains its existing shared API/query path. No
unrelated index was substituted. SQLite execution is proven; SQL uses existing
SQLAlchemy/keyset/permission projections without dialect-specific additions,
but live PostgreSQL execution is not claimed. Remote full CI, independent review,
Forge approval and maintainer/human acceptance remain the parent's gates.

### Intermediate-width correction to the search follow-up

Parent remeasurement of 30e5e77 exposed a gap in the endpoint-only responsive
oracle: catalog/topology inputs shrank to 131/112px at 1200, 182/91px at 1024,
and 206/118px at 768. The label's minimum covered its scope text plus input,
not the editable input alone. This supersedes any inference of intermediate-
width usability from the earlier 1440/390-only browser evidence.

The focused CSS correction gives the actual input a nonshrinking 200px flex
basis, lets scope labels wrap, and gives topology's search group a meaningful
wrap basis instead of squeezing it beside the title. Optional handoff text may
wrap anywhere; topology's existing type toolbar scroll stays local at widths
above its former mobile-only containment rule. Header/control sizes and search
semantics are unchanged. The catalog query/submit/root-create centerline remains
aligned when the shared row fits.

The rendered assertion is committed in tests/browser/local-search-responsive.cjs.
The same outbound-fenced, source-bound synthetic fixture runs it across catalog
and topology at 1440/1200/1024/768/390, both themes, English/German and short/long
queries. Each case verifies input width >=200px, hit-testing, 40px header-control
geometry, no whole-page overflow, actual native query submission and explicit
global handoff/Escape. A temporary browser-only old-rule mutation must fail the
width assertion before restoring and passing. Raw results, screenshot hashes,
runner, fence/server logs and final head/source binding are retained under
exports/ux-v5-search/responsive-*. Existing 84-test service/state results are
reused only for the unchanged Python/JS/templates/tests; no full suite, CI, push,
production operation or reviewer-worktree write is part of this correction.

The 80-case matrix passed with zero unexpected browser errors and forty
screenshots. English short-query catalog/topology widths (px) are 371/272 at
1440, 358/443 at 1200, 263/267 at 1024, 286/449 at 768 and 366/362 at 390.
Across all translated/long-query cases the minimum was 201.25px. The old-rule
mutation reproduced a 112.30px topology input at 1200 and was rejected; restoring
the corrected rules passed. At 1440 the fitting catalog row's query/submit/root
centerlines match within 1px. Parent's earlier endpoint-only 281–288px mobile
measurement is historical, not the corrected geometry above.
