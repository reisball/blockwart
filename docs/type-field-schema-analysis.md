# Blockwart Type Field Schema Analysis

Date: 2026-05-17

## Current State

Blockwart currently has a stable object header table and flexible JSON payloads:

- `catalog_objects`: `id`, `kind`, `label`, `status`, `summary`, `data_json`, timestamps
- `relationships`: string references such as `system:n8n`
- `audit_events`: audit trail per object/action

Type-specific fields are not modeled as configurable metadata today. They live inside
`catalog_objects.data_json` and are interpreted by hardcoded Python validators,
route handlers, templates, and importers.

Relevant hardcoded areas:

- Object kinds and validation: `src/blockwart/schemas/catalog.py`
- CRUD/persistence: `src/blockwart/services/catalog.py`
- UI form handling and panel extraction: `src/blockwart/ui/routes.py`
- Object list/detail templates: `src/blockwart/ui/templates/index.html`,
  `src/blockwart/ui/templates/object_detail.html`
- Markdown/seed imports: `src/blockwart/services/markdown_import.py`,
  `src/blockwart/services/seeds.py`

The public UI currently exposes only `host`, `system`, `netzwerk`, and
`service`, while the backend also knows `credential_reference`, `runbook`,
`decision`, and `project`.

## Important Findings

- `Hostname` is currently both a UI label and a storage behavior. On create/edit,
  the submitted hostname updates `data.network.hostnames[0]` and also becomes
  `catalog_objects.label`.
- Detail panels such as `Netzwerk` and `Zugriff` are rendered only when data
  exists. This blocks adding missing rows from empty objects.
- Field and panel validation is procedural, not declarative.
- Secret safety must remain global. A configurable schema must not be able to
  allow raw secret/value fields by accident.
- Existing tests mostly create tables from SQLAlchemy metadata, not Alembic
  migrations, so migration drift is not currently caught.

## Recommended Target Model

Keep `catalog_objects` as the stable identity/header table and keep
`data_json` as the canonical flexible payload for now. Add a declarative schema
layer around it instead of prematurely splitting all object values into EAV tables.

Proposed new concepts:

- `object_types`
  - `id`, `label`, `description`, `is_public`, `status`,
    `current_schema_version`
- `object_type_versions`
  - `type_id`, `version`, `json_schema`, `ui_schema`, `migration_notes`
- `object_type_fields`
  - `type_id`, `version`, `path`, `label`, `field_type`, `required`,
    `default`, `validation`, `reference_target_kind`, `secret_policy`,
    `sort_order`
- `object_type_panels`
  - `type_id`, `version`, `panel_key`, `label`, `sort_order`,
    `field_paths`, `visibility_rules`

Longer term, add an indexed scalar field table only for fields that need fast
filtering/reporting. Do not normalize every JSON value before there is a real
query requirement.

## Pragmatic Build Path

1. Add schema metadata and default built-in type definitions that reproduce the
   current behavior.
2. Add a schema/settings page, likely `/settings/schema`, with a type dropdown
   and editable field list.
3. Convert create/detail forms to read labels, visibility, required/optional,
   and ordering from schema metadata.
4. Keep internal storage paths stable at first, for example:
   - `label`
   - `data.network.hostnames[0]`
   - `data.network.addresses[]`
   - `data.ports[]`
   - `data.endpoints[]`
   - `data.access_methods[]`
5. Move validation rules behind the schema layer while preserving current
   hardcoded safety checks as non-optional global checks.
6. Add migration tests before changing live storage behavior.

## Test Plan

- Unit tests for schema loading, duplicate field rejection, invalid paths,
  field types, required/default/enum/reference validation.
- API tests for schema-driven object create/update and structured validation
  errors.
- UI tests for per-type field labels and visibility, especially `Service Name`
  vs `Hostname`.
- UI tests for always-visible panels and add-row behavior.
- Import regression tests for seed and markdown imports.
- Alembic migration tests using a real temp SQLite DB and `alembic.command.upgrade`.
- Migration preservation tests for existing `catalog_objects`, relationships,
  audit events, timestamps, unknown extra JSON fields, and secret-safety behavior.

## Suggested Issue Split

- Schema foundation: DB models, migration, default type definitions, registry.
- Schema-driven validation: keep current behavior but route through metadata.
- Schema settings UI: type dropdown plus field add/edit/delete/reorder.
- Schema-driven object forms/panels: labels, visibility, required fields, add rows.
- Migration/test hardening: Alembic tests and existing-data preservation.
