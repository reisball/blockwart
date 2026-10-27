# Changelog

Notable product changes are recorded here. Versions follow the
[versioning policy](docs/versioning.md); publication does not deploy an instance.

## [Unreleased]

### Added

- Independently delegated read/update permissions for existing credential-reference
  locator content across the web UI, REST API and MCP (#315).

### Changed

- Credential-reference metadata grants no longer expose or modify `data.reference`.
  Existing Viewer/Editor and Global Catalog Reader grants remain metadata-only;
  Owners retain full control. Migration `20261026_0031` preserves existing grants
  and supports explicit assignment of the new content roles. Omitted locator
  content is preserved during metadata updates; see `docs/auth-rbac.md`.

## [0.2.0] - 2026-10-26

Project management workflows, stronger access controls, and clearer validation errors.

### New

- [#298](https://github.com/reisball/blockwart/pull/298) — Add typed requirements, decisions, evidence, and task workflows with API/MCP support.

### Fixes

- [#301](https://github.com/reisball/blockwart/pull/301) — Strengthen authorization checks and clarify global catalog roles.
- [#300](https://github.com/reisball/blockwart/pull/300) — Return structured validation errors across REST and MCP.
- [#303](https://github.com/reisball/blockwart/pull/303) — Identify invalid project-record fields and length limits precisely.
- [#279](https://github.com/reisball/blockwart/pull/279) — Prevent stale ETags from becoming valid after object recreation.
- [#280](https://github.com/reisball/blockwart/pull/280) — Prevent changed monitoring targets from inheriting old health results.
- [#282](https://github.com/reisball/blockwart/pull/282) — Keep release-data freshness independent of retry delays.
- [#281](https://github.com/reisball/blockwart/pull/281) — Allow project saves with untouched empty source rows.
- [#283](https://github.com/reisball/blockwart/pull/283) — Reliably reject circular decision and runbook supersessions.
- [#286](https://github.com/reisball/blockwart/pull/286) — Show form errors instead of server errors for non-object JSON.

### Maintenance & documentation

- [#266](https://github.com/reisball/blockwart/pull/266) — Update the MCP SDK to 1.30.0.
- [#285](https://github.com/reisball/blockwart/pull/285) — Validate OpenAPI against the current source checkout.
- [#305](https://github.com/reisball/blockwart/pull/305) — Restructure the README around capabilities and getting started.
- [#307](https://github.com/reisball/blockwart/pull/307) — Align API/MCP and operating guides, and add an agent quickstart.

**Upgrade:** Database migrations are required. REST endpoints remain under `/api/v1`.

## [0.1.0] - 2026-10-22

First versioned public release. This is a baseline of the existing product,
not a claim that every capability was introduced on this date or that the
Development/Staging pilot has become a production service.

### Included

- Typed infrastructure catalog, relationships, placement and network topology.
- Human UI, object-authorized REST API v1 and stdio MCP server.
- Human/service identities, scoped grants, credential-reference metadata,
  audit, optimistic concurrency and idempotent commands; no stored secret values.
- Canonical Projects, Decisions and Runbooks, append-only chronology and comments.
- Project workspace with tasks/questions/blockers, versioned Markdown knowledge
  pages, external accesses and append-only record history.
- Service health observations and public GitHub stable-release monitoring.
- Reviewed import, knowledge planning/apply, source coverage and explicit
  container deployment/backup/rollback tooling.
- One product-version source for Python package metadata, API/OpenAPI, health
  responses and the MCP handshake; documented versioning and publication rules.

### Compatibility and known limitations

- REST remains `/api/v1`; product version `0.1.0` is not an API path version.
- The included database head is `20261022_0027`. Upgrade/rollback requirements
  remain those in [deployment](docs/deployment.md) and the
  [Project workspace contract](docs/project-workspace.md).
- The pilot remains Development/Staging; publication alone changes no instance.
- Known open bugs at this baseline include
  [release-monitoring freshness (#268)](https://github.com/reisball/blockwart/issues/268),
  [monitoring target attribution (#269)](https://github.com/reisball/blockwart/issues/269),
  [non-object JSON in UI creation (#270)](https://github.com/reisball/blockwart/issues/270),
  [knowledge supersession cycles (#271)](https://github.com/reisball/blockwart/issues/271),
  [ETag reuse after recreation (#272)](https://github.com/reisball/blockwart/issues/272),
  and [empty workspace source rows (#275)](https://github.com/reisball/blockwart/issues/275).
  They are not fixed by this versioning/documentation change.

[Unreleased]: https://github.com/reisball/blockwart/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/reisball/blockwart/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/reisball/blockwart/releases/tag/v0.1.0
