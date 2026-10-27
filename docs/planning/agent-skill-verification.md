# Agent-skill template verification (#317)

Scope: portable client instructions and documentation for the next version,
following the first-value onboarding changes in #318. No product/API, workflow,
authentication, installed-agent, live catalog, runtime or deployment change.

## Delivered path

- `docs/agent-skill.md`: prerequisites, whole-directory copy/adaptation, client
  namespaces, workspace routing, read-only adoption and revision compatibility.
- `examples/agent-skill/blockwart/SKILL.md`: contract-led, scoped catalog workflow;
  different object/access/Project/record/append preconditions remain distinct.
- Bundled optional quick-reference workflow: fictional quickstart service and
  Runbook, additional explicitly illustrative entries, scoped reconciliation,
  retained unresolved entries and complete/partial coverage reporting.
- Agent quickstart and documentation index: discoverable after the first read,
  without repeating installation or full API documentation. Changelog: Unreleased.

## Focused local checks

- Skill frontmatter passed AgentSkills quick validation (`name`, `description`).
- Copied the entire skill directory into a disposable workspace skill location;
  both Markdown resources and every relative supporting link remained usable.
- Checked 108 local links/anchors across five entry/template/reference documents;
  absolute public `main` links were mapped to this checkout to verify targets.
  Network availability and an arbitrary client's discovery UI were not tested.
- Parsed six JSON examples in the integrated agent path and checked tool-call
  arguments against the generated MCP input schemas; scoped schema discovery
  also rendered successfully without contacting a catalog.
- Checked the eight fully qualified tool names mentioned in these documents
  against the generated catalog; manually compared the narrow command table,
  Project/record ETag semantics, protected locator omission and access boundaries
  with current source and public contract documentation.
- Checked 15 operation-precondition/batch-boundary assertions against generated
  schemas. These are static contract checks, not write execution or live grants.
- Ruff, OpenAPI snapshot check and `git diff --check` passed. New examples were
  reviewed for neutral synthetic content and absence of private installation data.

Full exact-revision CI, independent review, merge and post-merge results belong
on the pull request and issue. These local checks do not claim arbitrary-client
compatibility, a deployed feature, automatic indexing or permission to execute
external procedures. The previous onboarding evidence is a historical snapshot;
this issue supplies the separately tracked template it left out.
