# Relationship Integrity

Blockwart stores every cross-object graph edge as one directed relationship. The registry in
`blockwart.domain.relationships` is the canonical vocabulary:

| Type | Direction |
|---|---|
| `hosts` | `host → system`, `host → service`, `system → service` |
| `depends_on` | asset → asset; the source depends on the target |
| `supports` | service → service |
| `feeds` | service → service |
| `exposes` | service → service |
| `documents` | runbook, decision, or project → any catalog kind |
| `uses` | any catalog kind → any catalog kind |
| `related_to` | any catalog kind → any catalog kind |

`provides` is obsolete placement storage and is not an allowed type.

## Dependency storage

`depends_on` is the only storage for the generic upstream/downstream dependency graph. If
`service:a depends_on service:b`, `service:b` is upstream of `service:a`. The Agent API derives
the reciprocal downstream view from the same relationship.

Alembic revision `20260724_0004` converts legacy `data.dependencies.upstream` and
`data.dependencies.downstream` values into directed `depends_on` relationships, deduplicates the
same logical edge across the two legacy views, and removes only the obsolete `dependencies`
member. New object payloads containing `data.dependencies` are rejected. The seed importer accepts
that legacy input shape only as an import adapter and stores the normalized relationships.

## Enforcement

Every supported writer resolves both typed references against the catalog and verifies the asserted
kind before adding a relationship. It also rejects unsupported types or directions, self-references,
duplicate triplets, and a second placement parent.

The database independently enforces:

- one unique `from_ref + relation_type + to_ref` triplet;
- `from_ref != to_ref`;
- the registered relationship type set;
- at most one `hosts` relationship for each child.

Direction and typed-reference existence remain service-layer rules because the object kind and ID
are encoded in one typed-reference column. The migration validates those rules before its first
data or schema write.

Object data may contain typed references in documented fields such as credential references,
runbook targets, or related projects. All writers validate those references against the same
catalog identity map.

## Kind changes and deletion

A kind change changes the object's typed reference. Blockwart therefore blocks the change while
any relationship or JSON typed reference still uses the old reference. Callers must update those
references explicitly in a separate reviewed operation before retrying the kind change.

Deletion follows the same fail-closed contract. Blockwart blocks deletion while any incoming,
outgoing, or JSON typed reference exists; it does not silently cascade or orphan data. After the
caller explicitly removes the references, deleting the now-unreferenced object retains its audit
history.

## Diagnosis

Run the read-only integrity check after migration and before deployment:

```bash
blockwart-db integrity
```

Success reports the current revision and zero diagnostics. Failures use stable codes such as
`dangling_typed_reference`, `typed_reference_kind_mismatch`,
`invalid_relationship_direction`, `duplicate_relationship`,
`multiple_placement_parents`, and `obsolete_data_dependencies`.

Application rollback does not remove the new constraints or reconstruct `data.dependencies`.
Restore the paired pre-upgrade database backup together with the matching previous image.
