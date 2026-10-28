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


## Exact-head review follow-up (2026-10-28)

Independent Kutscher Quality review of `99e0619bc96f0af4b1d8cc5c94d56403d12ea953`
was **not approved**. Its three findings are delivery gates, not accepted risks:

1. Responsibility preview required `manage_access` but not prior Owner authority,
   disclosing a linked Runbook to an access-manager-only actor. Reproduced through
   actual REST and MCP adapters (hidden object GET 404, preview unexpectedly 200).
   Responsibility preview now applies the same Owner delegation gate as grant
   creation before resolving or returning reach; existing self/subtree semantics
   remain unchanged. A manually selected denied browser scope falls back to a
   safe Discoverer/self preview (regression reproduced 500 before that adapter
   correction), without exposing hidden labels or changing the service denial.
2. Raw malformed Owner/responsibility grants on Runbook or CredentialReference
   anchors were ignored by policy but counted as direct ownership by recovery;
   managed removal/repair then rejected their prospective scope. Reproduced both
   count disagreement and update/revoke exceptions. A shared valid-Owner SQL
   predicate now aligns direct/inherited coverage and initial-owner recovery.
   Existing-grant reach validates the full stored target before preserving its
   actual coverage, allowing authorized repair/removal without bypassing Owner,
   revision, audit, last-owner or self-lockout protections.
3. The reviewed MCP manifest digest still described the old schemas. Its
   intentional contract delta was compared in full against the parent manifest:
   exactly six tools change (grant create/update/preview and relationship
   create/delete/schema); all other fields, 47 tools and contract version remain
   unchanged. The reviewed digest is now `16c952d4…`.

The initial delayed `ember-wharf` failure was a test savepoint ordering error
already corrected before the reviewed commit: the expected exception must cross
`begin_nested()` before `pytest.raises` handles it. The reviewed HEAD was
independently rechecked: 11 policy cases and Ruff passed. This stale notification
is distinct from the three actionable independent-review findings above.

The follow-up revision requires fresh exact-head independent review and full CI.
The prebuilt image/migration rehearsal for 99e0619 is superseded as a deployment
candidate; it is retained only as evidence and must not be deployed as the fix.

Follow-up verification before re-review:

- 82 current policy, REST/MCP boundary, UI/Node and MCP manifest cases passed.
- 114 policy/boundary/UI plus adjacent ownerless recovery and grant-management
  cases passed before the final browser adapter change; 17 PostgreSQL-only cases
  were explicitly skipped in that SQLite-focused run, not counted as passed.
- Both focused PostgreSQL responsibility reach/unique-target and real competing
  scope-revocation lock-wait cases passed using the existing isolated test server.
  An earlier attempt used the wrong test URL and skipped; only the corrected
  credential-bound run is PostgreSQL execution evidence.
- Repository Ruff and diff whitespace checks passed.
- No live changes, merge, acceptance or issue closure have occurred.


## Final CI packaging follow-up (2026-10-28)

- Exact `a20e9b61c19ddd6b01a069b7e7edabeeb6e5ba21` received independent
  Kutscher Quality **APPROVE**, run `1793209118-e158cd62`: no reproducible
  findings, 82 focused cases and seven additional boundary/migration probes.
- CI run [40710091505](https://github.com/reisball/blockwart/actions/runs/40710091505)
  passed all 2,902 tests, lint and reviewed OpenAPI, then failed the installed-wheel
  smoke's exact relationship vocabulary assertion. Its expected list omitted
  the intentional `operations_runbook_for` addition. This is a smoke contract
  expectation correction, not a product-policy change.
- The original assertion failure was reproduced in an isolated checkout. Adding
  only the expected relationship type made the real Python 3.12 installed-wheel
  smoke pass outside the repository, including MCP compatibility/drift checks.
  Three focused contract tests, Ruff and whitespace checks also passed.
- This final test/documentation revision still requires its own exact-head
  independent review and green CI. No merge, live migration or grant/Runbook
  association is claimed here. Existing production is still the #321 build.
