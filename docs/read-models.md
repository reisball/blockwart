# Application Read Models

Blockwart separates HTTP and template delivery from catalog read orchestration.
`blockwart.services.queries` owns the FastAPI-independent query boundary used by
the current catalog JSON API and the HTML UI.

## Catalog read model

The catalog model is the faithful read representation of a stored object. It
includes the validated catalog data, canonical lifecycle and health, placement
state, root-to-parent path, timestamps, and safe record-integrity diagnostics.
The unversioned `GET /api/objects` compatibility routes expose this model.

Catalog browse and detail queries additionally resolve these internal models:

- public object counts and deterministic browse ordering;
- all relationships for one object, grouped by direction;
- object audit history;
- the canonical host → system → service topology;
- relationship cards used by the existing HTML templates.

The query module does not import FastAPI requests, responses, templates, or form
types. Routers parse transport input and render a response; they do not query
relationships or build placement graphs themselves.

## Agent context

Agent context is intentionally not the catalog record with a different route.
It is a compact, defensively sanitized projection for agents and MCP. It adds
resolved endpoint, network, dependency, child, and credential-reference
summaries while preserving the canonical parent path and placement state.

Catalog topology and Agent context both resolve placement through
`blockwart.domain.placement.PlacementGraph`. This keeps placement semantics in
one domain implementation without forcing the two public response shapes to be
identical.

## HTTP boundary

This query extraction does not add new public resources. Versioned,
paginated Relationship, Audit, and Topology endpoints belong to issue #43.
Those endpoints can consume the same query layer without importing UI code.
Existing `/api`, UI URL, redirect, form, and template contracts remain
compatible during that work.
