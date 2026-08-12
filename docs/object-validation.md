# Catalog Object Validation

Blockwart validates catalog input through one fixed in-code schema registry in
`blockwart.domain.object_schema`. It does not load executable field definitions
from the database, UI settings, seed files, or Markdown.

## Boundary

`CatalogObjectIn` is the canonical validation entry point used by catalog service
calls, seed import, and Markdown import. Consequently, every write/import path receives the same
object-kind rules before persistence. Stored-record reads use the same rules with one explicit
migration exception: existing Network rows without a category remain readable.
Existing free-form Decision rows without `decision_status` have the same read-only compatibility
boundary; see [Canonical Decision objects](decisions.md). Any update must satisfy the new schema.
Existing free-form Project rows without a canonical category have the same read-only boundary;
see [Canonical Project knowledge](projects.md). Category and status are never inferred, and every
updated Project must satisfy the canonical category-conditioned contract.

The registry covers the existing object kinds:

- `host`
- `system`
- `network`
- `device`
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
port, RFC 3339 timestamp, object, array, string-or-object, and typed reference. Required fields,
fixed literal values, closed enums, whitespace normalization, and string length bounds are also
supported. Validation errors contain the resolved record path, such as
`data.network.addresses[1].ip`.

Device writes require `data.device.category` from
`antenna|sensor|adapter|controller|ups|other`. Optional manufacturer and model values are trimmed,
must remain non-empty, and are limited to 128 characters. Network writes require
`data.network.category` from
`segment|switch|router|access_point|mesh|firewall|gateway|other_device`; optional manufacturer and
model use the same 128-character rule and location is limited to 255 characters.

The Network exception is read-only and transitional. Any write through `CatalogObjectIn`,
including an otherwise unrelated update to a legacy row, fails until the caller provides an
explicit valid category. Blockwart does not infer or backfill one.

### Installed software

`host` and `system` objects may carry an ordered `data.installed_software`
list. Every entry is a closed object with required, non-empty string fields
`name` and `version` plus an optional absolute HTTP(S) `url`:

```json
{
  "installed_software": [
    {
      "name": "Docker Engine",
      "version": "1:27.5.1-1~ubuntu.24.04",
      "url": "https://docs.docker.com/engine/release-notes/27/"
    }
  ]
}
```

Versions are opaque and are stored exactly as supplied. Validation never
interprets, normalizes, sorts, deduplicates, or merges entries, and URL
validation only parses the string locally; it never retrieves the URL. The
field is explicitly forbidden on every other object kind. This inventory is
manual catalog data, not discovery, release monitoring, download, upgrade, or
deployment automation.

The canonical machine projection publishes the URL as `format: uri` together
with the JSON Schema pattern `^[Hh][Tt][Tt][Pp][Ss]?://`. The format retains
the general absolute-URI contract while the pattern exposes the narrower,
case-insensitive HTTP(S)-only scheme rule enforced by runtime validation.

Unknown additional data remains allowed to preserve the current flexible
catalog contract. Tightening unknown-field handling requires a separate
compatibility decision.

Complex conditional rules remain explicit schema-bound postconditions. Current
examples are the installed-software entry closure and required-field rules,
the credential-reference raw-value rejection, and the mandatory approval rule
for disruptive/destructive runbooks.

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
- no API v1 relationship-metadata commands or device-graph endpoints in this slice
