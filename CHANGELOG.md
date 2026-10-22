# Changelog

Notable product changes are recorded here. Versions follow the
[versioning policy](docs/versioning.md); publication does not deploy an instance.

## [Unreleased]

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

[Unreleased]: https://github.com/reisball/blockwart/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/reisball/blockwart/releases/tag/v0.1.0
