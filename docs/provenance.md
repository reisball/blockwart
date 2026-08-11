# Catalog provenance and freshness

Every catalog object has a canonical `provenance` header separate from its
kind-specific `data`. The header is stored as validated JSON in
`catalog_objects.provenance_json` and returned by catalog REST, Agent API,
`/api/v1`, and MCP read models.

## Contract

The header contains:

- `source_type`: `unknown`, `manual`, `import`, or `discovery`
- `source_ref`: optional stable identifier or reference for the source
- `managed_by`: optional party responsible for maintaining the record
- `observed_at`: optional time at which the source observation was made
- `verified_at`: optional time at which the fact was explicitly checked
- `stale_after`: optional absolute time after which the record is stale
- `manual_override`: whether an import must preserve the whole canonical record
- `is_stale`: read-only value derived from `stale_after` and current UTC time

All provenance timestamps are timezone-aware RFC3339 and are normalized to UTC
with `Z`. `updated_at` is different: it records when Blockwart last wrote the
catalog row. It does not claim that the underlying fact was observed or
verified at that time.

`stale_after` is an absolute boundary, not a duration. Missing freshness
timestamps mean "not known"; they are never replaced with an invented current
time. Consequently, a record without `stale_after` has `is_stale=false` while
remaining explicitly unverified when `verified_at` is null.

## Write and import ownership

Ordinary catalog writes default to `source_type=manual` and
`manual_override=true`. The override protects the entire canonical object,
including kind, label, state, summary, data, and provenance. An import may keep
its candidate outside the canonical record for comparison, but it must not
silently replace or mutate those canonical values.

Seed and workspace Markdown imports set `source_type=import`,
`manual_override=false`, and deterministic source metadata. Seed-level
`updated_at` and `last_verified` values become `observed_at` and `verified_at`
respectively; a missing source timestamp remains null. Re-running an import
updates records it owns while preserving a manual override.

Discovery is a reserved source type only. Active discovery, monitoring,
automatic deletion, and automatic freshness scheduling are outside the
current contract.

## Legacy migration

Alembic revision `20260726_0006` adds the canonical header without rewriting
`data_json`:

1. a non-empty legacy `data.source` becomes an import `source_ref`;
2. otherwise the first non-empty `source_references[].uri` is used;
3. otherwise the presence of `import_notes` produces
   `source_ref=legacy:import_notes`;
4. records without a reliable signal, including malformed legacy JSON, become
   `source_type=unknown`.

Legacy `source`, `source_references`, and `import_notes` fields remain available
for compatibility. The canonical header wins for provenance filters and import
ownership. No migration value is inferred from `updated_at`, because a database
write is not proof of an observation or verification.

Invalid or secret-shaped stored provenance is treated as a safe
`corrupt_record`: read surfaces fall back to an unknown header and never return
the raw invalid JSON.

## Source coverage is a separate registry

`CatalogProvenance.source_ref` remains provenance for one catalog object. It is
not overloaded as source inventory identity or as a mapping registry. Source
coverage uses separate immutable `source_snapshots`, `source_entries`, and
`source_entry_mappings` records so one entry may map to several objects and one
object may be covered by several entries without changing object provenance.

The coverage edge records the imported entry fingerprint and import/verification
times. Runtime resolution compares that fingerprint with the current entry,
checks whether the target still exists, and uses the object's canonical
provenance only for `mapped_stale`. Deletion, rename/missing entry, duplicate or
ambiguous edges, and source changes therefore remain distinct states.

The explicit Markdown dry run is the trust boundary that reads source files
and records a sanitized snapshot. REST and MCP never collect, follow, or store
the underlying source content. Inventory coverage says the configured entry is
mapped or intentionally excluded; it does not say its reference prose is stored
as a Blockwart object.
