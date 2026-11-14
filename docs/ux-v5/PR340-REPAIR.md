# PR #340 review repair

## Scope and source

Product-source checkpoint: `68ae5ae505c4f56bdcd5558bbbf9774a4f48b5ae`, based on
`72f55abda5e562d5ef42dfacaec1a3a920bf3cfe`. Later documentation-only commits do
not change that source identity. These are local synthetic checks, not approval
of an older release, final remote CI, merge, or deployment.

The five-domain requirements in [SEARCH-CONSISTENCY.md](SEARCH-CONSISTENCY.md)
and the composition in [ACCEPTANCE.md](ACCEPTANCE.md) remain unchanged.

## Corrections

- Activity targets use the established materialized read projection, including
  global Catalog Owner/Viewer authority and readable project/runbook/decision
  and credential-reference metadata. Metadata READ never grants reference-content
  access. Concealed and discover-only targets remain excluded.
- Actor labels recognize global access-management authority, but not global
  viewing authority. Batch enrichment also checks each event target: visibility
  on one target must not expose the same author's identity on another target.
- Every type offered by both global-search forms is accepted by the route.
  Unknown types remain invalid; project-content results remain independent.
- Topology's explicit category/services controls are no longer rewritten by the
  catalog's compatibility-preservation loop. Catalog/Topology navigation retains
  query, kind, mode, category and services.
- Topology detail search submits to the overview in the objects domain; it cannot
  overwrite independent Activity state. Detail-return tokens are not search filters.
- Severity badges count their actual destinations, retaining all other filters.
  An active badge toggles severity off, so its destination count is the All count.
  The filtered summary and cursor still describe only the selected result set.
- Project-name matching now shares NFKC, collapsed-whitespace and casefold
  normalization with page/task/log matching; comparisons remain literal.
- Local chronology titles reuse the existing English/German presentation keys.
- Invalid Activity targets preserve a valid previous target when available.
  Otherwise a separate boolean UI error state keeps native submissions and local
  navigation fail-closed. Neither an internal object-ID sentinel nor a fabricated
  target label is presented or persisted. A valid selection or Clear recovers.
  Sanitized parent values, not raw concealed input, reach hidden search fields.

The changed local-search script has a new asset version. No schema migration,
authorization-policy rewrite, Safe/auth implementation, or public REST/MCP
response-envelope change is part of this repair.

## Reproduction and evidence boundaries

`tests/test_pr340_review_repairs.py` exercises the real authentication and browser
read-access dependencies with synthetic browser sessions. Only database persistence
is substituted in its role fixture. Owner, Viewer, local Owner, ordinary reader
and discoverer cases cover target selection, identity privacy, and every rendered
global-search option. Exact result IDs/types, native error-state round trips,
reference-content concealment, localized chronology titles and severity-link
destinations are asserted.

The same desired-behavior tests reject the original base product sources; baseline
failures are retained separately from setup/locator errors. Product files are
restored byte-for-byte after the countercheck. A browser mutation restores only
the original local-search script and rejects both topology reset controls; the
unchanged desired navigation assertions pass with the repaired script.

At the product-source checkpoint, the affected gate passed **136 tests**,
including 29 new review regressions and focused header/locale seams (one existing
Starlette deprecation warning). The same new regressions against base product
sources produced **18 failures / 11 passes**. Chromium passed **70/70 checks**,
including 30 five-area geometry cases; restoring only the original script
produced 12 expected failures (both reset controls and error-state retention).
Both browser runs recorded zero unexpected page/console errors. These are
decisive local counterchecks, not full CI.

Focused affected suites, invoked through the audited offline launcher:

```text
tests/test_pr340_review_repairs.py
tests/test_search_consistency.py
tests/test_ux_v5.py
tests/test_activity_feed.py
tests/test_attention_filters_313.py
tests/test_attention_view.py
tests/test_application_queries.py
tests/test_workspace_search.py
tests/test_reference_content_activity_review_315.py
```

Python probes inherit kernel AF_INET/AF_INET6/AF_PACKET denial before application
imports, use a clean environment and owned SQLite/HOME/TMP paths, assert effective
settings and checkout imports, and retain descendant negative probes. Chromium
runs non-root in a separate loopback-only network namespace with no routes.
Browser requests are allowlisted and fulfilled with authenticated synthetic
application responses and this checkout's assets. No production browser/profile,
DB, network service or provider is used.

Browser coverage includes actual category/services navigation, native detail
search submission, independent Activity state, Catalog/Topology compatibility,
independent-domain reset/deep-link behavior, invalid-target recovery, and five-area
geometry at 1440/390px. JS runs verify Light/Dark; no-JS runs use the actual default
Dark theme. Measurements retain all seven header buttons at 40px height/7px radius,
local control-center hit tests and no whole-page overflow. Geometry negative
controls reject deliberate size drift. Raw logs, rendered responses, request
lists, measurements, source hashes and inspected screenshots are retained in
the author's separately handed-off evidence bundle, not private session paths
in this contribution.

## Remaining gates

Independent review and final required remote CI belong to the release coordinator.
No full-suite or PostgreSQL run, production login/deployment, physical-device
accessibility or large-inventory performance is claimed here. The live GitNexus
registry has no Blockwart index: graph impact is UNKNOWN, not cleared; direct
callers and affected service/UI seams were traced and tested instead.
