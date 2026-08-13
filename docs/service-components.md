# Service-local components

Blockwart may describe the internal structure of one deployed `service` without
promoting its parts to global catalog objects. The canonical v1 storage is the
optional `service.data.components` document:

```json
{
  "components": {
    "items": [
      {
        "id": "api",
        "name": "Public API",
        "role": "api",
        "description": "Handles the documented HTTP boundary."
      },
      {
        "id": "database",
        "name": "Catalog database",
        "role": "database",
        "description": "Stores this deployment's catalog state."
      }
    ],
    "dependencies": [
      {
        "component_id": "api",
        "depends_on": "database",
        "description": "Reads and writes catalog records."
      }
    ]
  }
}
```

The direction is literal: `component_id` depends on `depends_on`. It mirrors the
meaning of the global `depends_on` relationship but does not use, extend, or
alter that global relationship storage.

## Canonical v1 contract

Local IDs are 1..64 lowercase ASCII characters, start and end with a letter or
digit, and may contain `_` or `-`. They are unique only inside their parent
service. Names are trimmed, nonempty, and at most 128 characters. Descriptions
are trimmed, nonempty, and at most 512 characters. The closed v1 role vocabulary
is `application`, `api`, `database`, `worker`, `cache`, `queue`, and `other`;
`other` is the explicit forward-compatible escape hatch.

The document contains at most 100 components and 400 directed dependencies.
Every dependency endpoint must name an item in the same document. Self-edges and
duplicate `(component_id, depends_on)` pairs are rejected. An optional edge
description is trimmed, nonempty when present, and at most 512 characters.
Cross-service component references are structurally impossible.

Cycles are allowed. This is the smallest v1 rule consistent with Blockwart's
existing generic global `depends_on` graph, which does not impose an acyclic
architecture. Consumers must use visited sets and the published bounds of 100
nodes and 400 edges; the current UI renders a flat bounded item/edge projection
and never recursively expands a dependency. Self-reference remains invalid even
though multi-node cycles are valid.

Normalization sorts items by `id`, `name`, `role`, and `description`, and sorts
dependencies by `component_id`, `depends_on`, and description. Input order has
no business meaning. Therefore an update that differs only in order or
normalizable whitespace is a true parent-object no-op: no revision, timestamp,
or audit event advances.

## Security, authorization, and lifecycle

Components have no catalog-object ID, typed reference, grant, identity,
placement, lifecycle, health, provenance, revision, ETag, audit object, or
independent delete semantics. They inherit all visibility, RBAC, revision,
ETag/CAS, audit, provenance, transaction, and lifecycle boundaries from the
parent service. The complete document is detail-only data. Discover-only and
concealed projections expose no component name, count, edge, or indirect
structure hint.

The global secret and ACL-shaped-data detectors run before the component schema
at every normal write/import boundary. This applies equally to component and
edge descriptions. Secret-like keys or values, connection strings carrying
credentials, raw configuration values, grants, and permission fields are not a
component model and fail closed. Credential references remain separate catalog
objects using the existing safe contract.

REST API v1 and MCP use the ordinary object create/update commands and the
generated object schema; no component-specific machine mutation endpoint or MCP
tool exists. Agent context returns the canonical document only when it already
returns readable parent `data`. The human editor uses safe component forms but
submits their result through the same parent-service application command.

Existing services with no `data.components` remain valid and byte-for-byte
unchanged. Seed, Markdown import, reviewed Knowledge apply, export, REST, and MCP
all pass the field through the canonical `CatalogObjectIn` validation and
normalization boundary, so no database migration is required.

## Boundary with global services

An embedded database that is deployed, governed, and retired only as an
internal part of one service may be a `database` component. A database that is
independently deployed, shared, placed, granted, monitored, or lifecycle-managed
remains its own global `service` catalog object. The consuming service then uses
the unchanged global `depends_on` relationship to that service. The same rule
applies to caches, queues, workers, and APIs.
