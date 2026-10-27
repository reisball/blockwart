# Documentation Index

Start with the guide for your task. Current usage and interface contracts are
listed separately from historical plans and verification evidence.

## Start here

| You want to… | Read first | Then |
| --- | --- | --- |
| Understand Blockwart and try the catalog | [Project overview](../README.md) | [First useful catalog, local HTTPS and UI tour](quickstart.md) |
| Install or operate an instance | [Deployment](deployment.md) | [Configuration](config.md), [security model](security.md), [release workflow](release-workflow.md) |
| Connect an AI agent or automate catalog work | [Agent quickstart](agent-quickstart.md) | [MCP](mcp.md), [REST v1](api-v1.md), [permissions](auth-rbac.md) |
| Contribute code or documentation | [Contributing](../CONTRIBUTING.md) | [Development and CI checks](ci.md), [versioning](versioning.md) |

For typed project requirements, evidence, acceptance and GitHub observations,
use [Project management](project-management.md). The older
[Agent API](agent-api.md) is a read-only compatibility interface; new REST
integrations use `/api/v1`.

Generated discovery (`blockwart.describe_schema`, OpenAPI and MCP `tools/list`)
provides the machine contract for the installed revision. Examples are not
permission grants, and a historical test result is not evidence for your build.

## Active Operating Documentation

- [Local evaluation and first useful catalog](quickstart.md), including prerequisites,
  Python/container alternatives, local HTTPS and an optional fictional demo

- [Product versioning, changelog and GitHub releases](versioning.md)
- [Configuration](config.md) and [deployment readiness](deployment.md)
- [Reproducible builds and CI](ci.md), including the host-neutral parity
  contract for `.gitea/workflows/ci.yml` and `.github/workflows/ci.yml`
- [Atomic container release workflow](release-workflow.md), including the
  versioned specification, immutable evidence, candidate gates, cutover, and
  verified backup/image rollback contract
- [Markdown import](markdown-import.md) and [canonical English/UI
  localization](internationalization.md)
- [Write-free Knowledge planning](knowledge-planning.md)
- [Reviewed Knowledge apply and rollback](knowledge-apply.md) / [Geprüftes
  Knowledge-Apply und Rollback](knowledge-apply.de.md)

## Active API Documentation

- [Agent quickstart](agent-quickstart.md)
- [Agent API](agent-api.md), [API v1](api-v1.md), and the [API boundary
  contract](api-boundary-contract.md)
- [MCP server](mcp.md)
- [Agent read projections](agent-read-projections.md), including the versioned
  compact/context/full profiles, the closed field mask, capability
  deduplication, scoped schema reads, and the synthetic context budgets
- [Object comments](object-comments.md)

## Active Security Documentation

- [Authentication and object authorization](auth-rbac.md)
- [Security policy](security.md)
- [Catalog object validation](object-validation.md)
- [Public repository publication checklist](public-release.md) (reusable visibility
  gate; the canonical repository is already public)

## Active Architecture And Data Documentation

- [Asset domain model](domain-model.md) and [relationship
  integrity](relationship-integrity.md)
- [Service-local components](service-components.md), including local identity,
  directed dependencies, bounds, cycle semantics, and the global-service boundary
- [Service monitoring](service-monitoring.md) and the [Gatus pull
  adapter](gatus-pull.md), including provider-neutral observations,
  deterministic targets, leased polling, SSRF policy, and recovery
- [Public GitHub release monitoring](release-monitoring.md), including the
  service-only opt-in, conservative comparison, fixed provider boundary,
  leased scheduling, authorized views, rate limits, and recovery
- [Canonical Decision objects](decisions.md), including lifecycle, links, and
  dry-run-first legacy classification
- [Canonical Project knowledge](projects.md), including category-specific results,
  evidence, typed links, and reviewed migration
- [Typed project management](project-management.md): requirements, evidence,
  record-scoped actions, acceptance and opt-in GitHub observations
- [Project workspace](project-workspace.md): items (tasks, questions, blockers),
  versioned knowledge pages and external accesses, with shared UI/REST/MCP
  authorization and append-only history
- [Canonical Runbook contracts / Kanonische Runbook-Verträge](runbooks.md), including
  operating, rollback, recovery, authorization, and reviewed legacy migration
- [Application read models](read-models.md), [agent read
  projections](agent-read-projections.md), and [service
  interfaces](service-interfaces.md)
- [Needs attention](attention.md)
- [Agent activity feed](activity-feed.md)
- [Source coverage and import drift](source-coverage.md)
- [Reviewed Knowledge source coverage](source-coverage-manifest.md), including
  the closed manifest, dry-run evidence, record gates, and recovery boundary
- [Append-only object comments](object-comments.md)
- [Catalog provenance and freshness](provenance.md)

## Historical plans and verification evidence

These documents explain past implementation and cutover work; they are not
current installation instructions or an authorization to repeat operations.
Current behavior is documented in the active references above.

- [Project-management implementation plan](planning/project-management-287.md)
- [Project-management review evidence](planning/project-management-287-review.md)

### Migration evidence

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
