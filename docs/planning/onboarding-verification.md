# First-value onboarding verification

Scope: documentation and fictional evaluation assets for the next version;
no application/security-policy change, production deployment or release publication.
The agent-skill template tracked in #317 remains separate work.

## Delivered path

- README: intended audience, capabilities/non-goals, honest installation effort,
  human/agent entry paths, release-vs-main distinction and actual UI preview.
- Local quickstart: source acquisition, locked Python install or source-built
  container, database migration, ownership bootstrap, four-object optional seed,
  loopback application, executable Caddy HTTPS, login, tour and first saved edit.
- Agent quickstart: separate client-side wrapper, protected token-file provisioning,
  common stdio client configuration and scoped first search/full-context read.
- No authentication downgrade, automatic inventory/discovery promise, RAG claim,
  runbook execution, prebuilt-image promise or unmeasured setup-time estimate.

## Verification performed

- New seed imported into a disposable migrated SQLite database: four objects,
  three relationships, complete active Owner coverage and catalog-owner readiness.
- Existing seed/import/bootstrap regression selection: 25 tests passed.
- Added first-run seed regression: validates current schema/import, placement,
  linked operating knowledge, unknown health and full database readiness.
- Caddy 2.10.2 validated the exact Caddyfile. The initial runtime probe exposed its
  implicit HTTP redirect listener on port 80; the final local example explicitly
  disables those redirects and binds HTTPS only to loopback on port 8443.
- Actual Caddy → loopback Uvicorn → SQLite browser check: sign-in with Secure
  cookies, placement chain, draft runbook, summary edit, save and reload passed.
  Screenshots were captured from that fictional catalog, not product mockups.
- HTTPS readiness also passed with curl using the disposable Caddy root CA and
  direct loopback routing. Host system/browser CA trust was not modified; the
  isolated test browser accepted this test CA. Host-specific CA installation is
  documented but was not exercised in the host trust store.
- Actual Python MCP SDK stdio session: initialize, tools/list, service search and
  full object context/ETag passed using a Viewer/self grant on the demo service.
- GitHub repository description and infrastructure/documentation/MCP topics were
  set and read back to improve discovery. These repository settings are separate
  from the versioned documentation; no project website is claimed.
- Local relative Markdown files/images and heading anchors checked in all six
  entry guides; Ruff, whitespace and OpenAPI-contract checks passed.

Full exact-revision CI and independent review are recorded on the pull request.
These local results do not benchmark download/setup time, validate native
Windows/macOS, certify a production deployment, or prove the current release
already contains the new documentation.
