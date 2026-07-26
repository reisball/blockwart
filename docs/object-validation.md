# Catalog Object Validation

Blockwart validates catalog input through one fixed in-code schema registry in
`blockwart.domain.object_schema`. It does not load executable field definitions
from the database, UI settings, seed files, or Markdown.

## Boundary

`CatalogObjectIn` is the single validation entry point used by catalog service
calls, seed import, Markdown import, and stored-record integrity checks.
Consequently, every write/import path receives the same object-kind rules
before persistence.

The registry covers the existing object kinds:

- `host`
- `system`
- `netzwerk`
- `service`
- `credential_reference`
- `runbook`
- `decision`
- `project`

Top-level identity, kind, lifecycle, health, and status remain Pydantic model
fields. The registry validates fields below `data`.

## Declarative Fields

Each immutable `FieldSpec` declares a dotted path and one field type. Array
segments use `[]`, for example:

- `network.addresses[].ip`
- `endpoints[].port`
- `access_methods[].credential_references[]`
- `applies_to.systems[]`

Supported types are string/text, strict integer, strict boolean, enum, URL, IP,
port, object, array, string-or-object, and typed reference. Required fields and
fixed literal values are also supported. Validation errors contain the resolved
record path, such as `data.network.addresses[1].ip`.

Unknown additional data remains allowed to preserve the current flexible
catalog contract. Tightening unknown-field handling requires a separate
compatibility decision.

Complex conditional rules remain explicit schema-bound postconditions. Current
examples are the credential-reference raw-value rejection and the mandatory
approval rule for disruptive/destructive runbooks.

## Secret Policy

Secret rejection is global and runs independently before the object-kind
schema. A schema cannot disable that policy. Registry construction also rejects
field paths whose key would represent a raw secret or credential value.

Credential-reference metadata such as a provider name, a protected storage
path, or a credential reference ID is allowed. Raw passwords, tokens, private
keys, cookies, sessions, and generic raw/value fields are not.

## Related Validators

The declarative registry owns field/path/type validation. Existing domain
validators remain authoritative for behavior that depends on multiple fields:

- interface normalization and endpoint identity
- canonical placement metadata
- lifecycle/health state resolution
- relationship target existence and graph integrity

This keeps one field-rule registry without duplicating richer domain logic.

## Non-Goals

- no schema database tables or migrations
- no editable storage paths or field types
- no schema-driven UI generation
- no new public catalog fields
- no change to REST/OpenAPI or the persisted `data_json` format
