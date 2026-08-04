# Application Read Models

Blockwart separates HTTP and template delivery from catalog read orchestration.
`blockwart.services.queries` owns the FastAPI-independent query boundary used by
the current catalog JSON API and the HTML UI.

## Catalog read model

The catalog model is the faithful read representation of a stored object. It
includes the validated catalog data, canonical lifecycle and health, placement
state, root-to-parent path, timestamps, and safe record-integrity diagnostics.
The unversioned `GET /api/objects` compatibility routes expose this model only
with `read`. `discover` produces a separate strict stub model; no-discover
objects are omitted or concealed.

Catalog browse and detail queries additionally resolve these internal models:

- public object counts and deterministic browse ordering;
- all relationships for one object, grouped by direction;
- object audit history;
- the five newest append-only object comments;
- the canonical host → system → service topology;
- relationship cards used by the existing HTML templates.

The query module does not import FastAPI requests, responses, templates, or form
types. Routers parse transport input and render a response; they do not query
relationships or build placement graphs themselves.

The query boundary receives one immutable principal/policy snapshot. Counts,
search, topology, relationships, audit, and pagination operate on its
authorized projection. Detail predicates exclude stubs, placement edges
require discoverable endpoints, and non-placement edges require readable
endpoints.

## Agent context

Agent context is intentionally not the catalog record with a different route.
It is a compact, defensively sanitized projection for agents and MCP. It adds
resolved endpoint, network, dependency, child, and credential-reference
summaries while preserving the canonical parent path and placement state.
It applies the same object visibility decision and strict stub fields as the
catalog/UI projection.

A readable detail adds the five newest entries as `recent_comments`. The
entries remain exact Markdown or legacy plain-text source plus a format marker;
rendered HTML is a browser-only projection. Discover-only stubs never contain
comments. The exhaustive newest-first timeline is a separate opaque-cursor
resource; see `object-comments.md`.

Catalog topology and Agent context both resolve placement through
`blockwart.domain.placement.PlacementGraph`. This keeps placement semantics in
one domain implementation without forcing the two public response shapes to be
identical.

## HTTP boundary

The versioned `/api/v1` object, Relationship, Audit, and Topology resources
consume this query layer without importing UI code. Agent summaries and
contexts use the shared Agent resolver on top of the same placement and
endpoint domain contracts. See `api-v1.md`.

The existing `/api`, UI URL, redirect, form, and template contracts remain
compatible. Query extraction and v1 delivery do not make HTML templates part
of the machine API.
