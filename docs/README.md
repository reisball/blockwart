# Documentation Index

This index separates current product contracts from historical evidence and
reference material. Nothing in the historical or raw/reference sections is
deleted by this classification.

## Active Operating Documentation

- [Configuration](config.md) and [deployment readiness](deployment.md)
- [Reproducible builds and CI](ci.md), including the host-neutral parity
  contract for `.gitea/workflows/ci.yml` and `.github/workflows/ci.yml`
- [Markdown import](markdown-import.md) and [canonical English/UI
  localization](internationalization.md)

## Active API Documentation

- [Agent API](agent-api.md), [API v1](api-v1.md), and the [API boundary
  contract](api-boundary-contract.md)
- [MCP server](mcp.md)
- [Object comments](object-comments.md)

## Active Security Documentation

- [Authentication and object authorization](auth-rbac.md)
- [Security policy](security.md)
- [Catalog object validation](object-validation.md)

## Active Architecture And Data Documentation

- [Asset domain model](domain-model.md) and [relationship
  integrity](relationship-integrity.md)
- [Canonical Decision objects](decisions.md), including lifecycle, links, and
  dry-run-first legacy classification
- [Canonical Project knowledge](projects.md), including category-specific results,
  evidence, typed links, and reviewed migration
- [Application read models](read-models.md) and [service
  interfaces](service-interfaces.md)
- [Source coverage and import drift](source-coverage.md)
- [Append-only object comments](object-comments.md)
- [Catalog provenance and freshness](provenance.md)

## Historical Migration Evidence

[Gitea to GitHub migration runbook](github-migration.md) records the completed
cutover and preserves the pre-cutover procedure as evidence. Keep
`scripts/migration/export_gitea.py` and its tests, especially
`tests/test_gitea_migration_export.py`, as reproducible migration evidence.
The Gitea workflow remains part of the documented host-neutral CI parity
contract, rather than an obsolete workflow to remove.

## Raw And Reference Material

- [UI requirements — raw notes](ui-requirements-raw.md)
- [Type field schema analysis](type-field-schema-analysis.md)

These historical and raw/reference documents are classified for discovery;
they are retained rather than removed.
