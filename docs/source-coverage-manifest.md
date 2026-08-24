# Reviewed Knowledge source coverage

`blockwart-source-coverage` is the offline, dry-run-first collector for a
complete reviewed Knowledge inventory. It records inventory coverage only. It
does not plan or apply catalog objects and it is not a crawler available to the
API, MCP server, UI, or normal runtime requests.

## Version 1 manifest

The v1 manifest is a closed JSON/YAML contract. Print its machine-readable
schema with:

```console
blockwart-source-coverage --print-schema manifest
```

The top-level expected source and entry counts must equal the declared arrays.
Each source belongs to exactly one declared closed directory. At collection
time, the matching direct child files in every closed directory must equal the
declared paths exactly, and every file SHA-256 must match. Files outside those
closed directories are neither crawled nor opened.

Sources use stable sanitized `knowledge://`, `repository://`, or
`workspace://` URIs, never an absolute local path. Every entry has a stable ID,
`present`/`absent` presence, an opaque SHA-256 fingerprint, one controlled
classification/intent/reason decision, and either explicit primary/derived
catalog mappings or the explicit `no_catalog_object` decision. Mapping target
kinds and imported entry fingerprints are reviewed facts. Unknown fields,
duplicate keys and identities, incomplete counts, unstable paths/URIs/IDs,
unclassified decisions, raw secret-shaped values, ACL-shaped data, and
unbounded inputs are rejected.

The public synthetic example is
[`examples/source-coverage/manifest.json`](../examples/source-coverage/manifest.json).
It is intentionally excluded from the catalog and contains no private
instance facts.

## Deterministic dry run

Dry-run is the default and is write-free:

```console
blockwart-source-coverage \
  --database-url "$BLOCKWART_DATABASE_URL" \
  --manifest reviewed-coverage.json \
  --source-root /path/to/reviewed/source-snapshot \
  --principal-id "$BLOCKWART_PRINCIPAL_ID"
```

JSON is the default output. It contains the canonical manifest and input
digests, normalized source snapshot digest and counts, classification/state/
presence counts, missing targets, ambiguous and duplicate mappings, sanitized
unsafe-finding codes, blockers, semantic no-op status, and complete sanitized
target evidence. Row, source, and mapping order do not affect any digest or
output order. Source bytes, excerpts, secret values, private paths, catalog
object bodies, and ACL rows are never printed or stored.

The normalized opaque entry fingerprints are domain-separated with each
declared file SHA-256 before the canonical snapshot is built. The existing
aggregate source fingerprint rule is retained, while the snapshot digest is
therefore also bound to the exact verified file bytes.

The input digest binds the canonical manifest, exact verified file hashes, and
the previous current coverage snapshot used to create deterministic absent
tombstones. The target evidence digest binds the effective principal, its
policy fingerprint, every mapped target's existence/visibility, expected and
actual kind, revision, and an opaque fingerprint of its exact current catalog
row.

Retain the complete `target_evidence` object as JSON along with all four
digests. For example, when the dry-run result is saved as `coverage-plan.json`:

```console
jq '.target_evidence' coverage-plan.json > reviewed-target-evidence.json
```

## Explicit record gates

Recording is a separate `record` action and requires every retained digest and
the complete evidence document:

```console
blockwart-source-coverage record \
  --database-url "$BLOCKWART_DATABASE_URL" \
  --manifest reviewed-coverage.json \
  --source-root /path/to/reviewed/source-snapshot \
  --principal-id "$BLOCKWART_PRINCIPAL_ID" \
  --target-evidence reviewed-target-evidence.json \
  --expected-manifest-digest "$MANIFEST_DIGEST" \
  --expected-input-digest "$INPUT_DIGEST" \
  --expected-snapshot-digest "$SOURCE_SNAPSHOT_DIGEST" \
  --expected-target-digest "$TARGET_SNAPSHOT_DIGEST"
```

Before opening a write transaction, the command repeats the exact dry-run and
checks all retained evidence. It repeats the check again in the transaction.
Recording fails closed for source or prior-snapshot drift; stale, missing,
concealed, kind-mismatched, incomplete, ambiguous, or duplicate target
evidence; an inactive/missing principal; or any dry-run blocker. A complete new
manifest never erases prior current entries: omitted entries and sources are
carried forward with `presence=absent`, which resolves to `missing_source`.
New and changed entries continue to use the canonical source-coverage drift
resolver. A semantically changed collection must use a `collected_at` later
than the current snapshot; this prevents equal-time digest tie-breaking from
leaving an older inventory current.

The transaction calls the existing `record_source_snapshot` service and may
write only `source_snapshots`, `source_entries`, and
`source_entry_mappings`. It never mutates catalog objects, relationships,
grants, comments, audit events, runtime state, or Knowledge source files. An
identical normalized snapshot is a semantic no-op.

## Runtime boundary and workflow separation

Only the two explicit offline collectors may open their declared inputs:
`blockwart-import-markdown` for `TOOLS.md`, and
`blockwart-source-coverage` for an exact reviewed manifest source set. REST
`GET /api/v1/source-coverage`, MCP `blockwart.get_source_coverage`, the UI, and
all other runtime requests read only already-recorded sanitized database rows.
They never resolve source URIs or inspect a workspace.

The workflows remain separate:

1. `blockwart-knowledge-plan` classifies and previews potential Knowledge
   catalog changes without writing.
2. `blockwart-knowledge-apply` explicitly applies a reviewed plan and owns its
   object/relationship backup and rollback contract.
3. `blockwart-source-coverage record` records only sanitized coverage facts
   after the catalog state exists and is visible to the effective principal.
4. Any later private instance collection is a separately reviewed operational
   run. It is not part of a public code change or release.

## Backup and recovery

Use the deployment platform's tested database backup before a production
record operation. For SQLite, stop writers and use SQLite's online backup
facility (or copy a verified stable database snapshot, including WAL state).
For PostgreSQL, take a consistent `pg_dump`/managed snapshot that includes
`source_snapshots`, `source_entries`, and `source_entry_mappings` and their
constraints. Record the backup identifier, database revision, dry-run digests,
and target-evidence digest outside Blockwart.

Recovery restores the database backup using the platform's normal maintenance
procedure, runs `blockwart-db check` and `blockwart-db integrity`, then reruns a
write-free coverage dry run. Do not repair coverage by editing rows manually:
the three tables are an immutable snapshot set with foreign-key and digest
relationships. Because recording does not mutate catalog/runtime data and old
snapshots remain immutable, a semantic replay normally requires no recovery.
