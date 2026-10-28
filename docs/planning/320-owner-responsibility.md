# Owner operational responsibility — #320

Approved scope: extend the existing role/grant/relationship/policy model, not a
parallel authorization system. Delivery includes review, merge and verified deployment.

## Contract

- Additional `owner/responsibility` scope on Host, System or Service only.
- One shared recursive reach for effective rights, preview, inherited sources and
  Owner protections: canonical descendants plus terminal Operations Runbooks.
- `operations_runbook_for` points from Runbook to exactly one infrastructure
  responsibility target at most. Descriptive links remain non-authorizing.
- Online association changes require prior Owner of both endpoints or Global
  Catalog Owner. Deletion preserves per-object coverage and administrative self-access.
- Credentials receive only effective Viewer metadata from the three documented
  reference-list paths. They never become Owner descendants; the original grant
  ID/anchor/scope remains the source of their effective Viewer projection.
- Existing self/subtree grants remain unchanged. Migration 0032 preserves rows and
  refuses downgrade while new scopes or association types remain.
- UI defaults new Owner assignments to responsibility only on eligible anchors;
  stored scopes remain selected. Preview explicitly shows the selected role/scope.
  JS preview navigation copies no CSRF state.

## Evidence before independent review

- 11 new shared-policy/coverage/migration cases passed on SQLite.
- 47 REST/MCP boundary cases passed: actual object updates, wrong role/kind/scope,
  hidden/excluded links, original grant provenance and credential content isolation.
- 158 adjacent relationship, preview, grant-management and reference-content tests passed.
- 118 UI/current-head migration, CLI, health, network and SQLite runtime checks passed.
- 8 existing PostgreSQL fresh/migration checks and 2 new responsibility checks passed.
  The new real lock-wait case confirms a stale relationship writer waits for a
  competing scope revocation and then fails its Owner authorization check.
- New UI tests render role/scope-specific previews and preserve stored selections;
  the shipped JS handlers execute under Node for default/scope-change/preview behavior.
- Ruff, JavaScript syntax, working-tree-bound OpenAPI snapshot and diff checks passed.

Full CI, independent exact-head review, merge, deployment, live verification and
OpenHAVoice association/grant reconciliation remain pending at this implementation
snapshot. Local focused results are not full CI or production evidence.
