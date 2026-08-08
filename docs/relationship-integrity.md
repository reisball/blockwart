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
| `attached_to` | `host|system → network-device`; `device → host|system|network-device|device` |
| `uplinks_to` | network-device → network-device |

`provides` is obsolete placement storage and is not an allowed type.

## Machine-readable contract

`blockwart.domain.relationship_projection` projects this registry as a
JSON-safe contract. It is generated from the same rules that validate every
write, so no boundary keeps a second relationship list. The projection
publishes:

- the closed `relation_types` vocabulary, exactly the registry;
- per type the accepted `directed_pairs` of endpoint kinds — for `hosts` those
  are narrower than the endpoint kind sets, so the pairs are the contract;
- the endpoint predicate by name and description, with
  `decidable_from_request: false` and the published network-device category
  vocabulary where a predicate additionally reads stored endpoint data;
- the type-dependent metadata fields, their JSON types, bounds, enums, and the
  JSON Schema of each type's metadata document;
- the declared graph rules of each type;
- the revision, replacement, and no-op semantics of the commands; and
- the rejection catalog with the stage that decides each code.

It never contains a stored object, edge, metadata value, or category of a
concrete record. `blockwart.describe_schema` publishes it under
`relationships`, `/api/v1` publishes the same generated shape in its OpenAPI
document for `V1RelationshipCommandIn` and `V1AttachedDeviceCreateIn`, and
`docs/mcp.md` and `docs/api-v1.md` describe the boundary behavior.

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
duplicate triplets, and a second placement parent. Endpoint descriptors carry the endpoint kind and
validated object data, so category-sensitive rules reject services, Network segments, and Networks
without a device category fail-closed.

Each relationship stores canonical JSON metadata in `metadata_json`; the database default is `{}`.
Every other relationship type accepts only `{}`. `attached_to` and `uplinks_to` accept optional,
trimmed `source_interface` and `target_interface_or_port` values (maximum 128 characters),
`link_kind`, boolean `primary`, and a maximum-512-character `note`. `uplinks_to` alone also accepts
`mode`. Unknown fields, empty or excessive strings, invalid enum values, non-boolean primary values,
and secret-shaped content are rejected by the same validator used for writes, import, and diagnosis.
The closed link-kind vocabulary is
`ethernet|wifi|mesh|zigbee|bluetooth|usb|serial|gpio|power|virtual|other`; uplink mode is
`access|trunk|routed|bridged|mesh|other`.

The device-to-device `attached_to` graph and network-device `uplinks_to` graph are acyclic. Multiple
parents or uplinks are valid, but only one edge per source and relationship type may carry
`primary=true`. Missing `primary` is false and stays absent from canonical JSON.

The Network read resolver consumes only the policy-projected `hosts`,
`attached_to`, and `uplinks_to` snapshot. Placement edges may expose their
existing discover-safe stubs, while every Network edge requires `read` on both
endpoints. Alternative uplinks remain visible; `primary` changes deterministic
ordering but never discards a route.

## Rejection stages

Every rejection publishes one stable code and the stage that decided it:

| Stage | Decided by | Boundary result |
|---|---|---|
| `request` | the command payload alone | `422 validation_error` with `code` and `path` |
| `catalog` | the stored endpoints | `409 conflict` without a field |
| `graph` | the surrounding edge set | `409 conflict` without a field |

Request-stage rejections are `unsupported_relation_type`,
`invalid_typed_reference`, `self_reference`, `invalid_relationship_direction`,
`invalid_relationship_metadata`, and `secret_relationship_metadata`. Their
canonical paths are `relation_type`, `from_ref`, `to_ref`, `metadata`, and
`metadata.<field>`, so a client can bind a rejection to the exact request
field. Direction is decided from the kinds the typed references assert, which
is why it is a request-stage rule; whether an endpoint is a network device is
decided from stored data and stays a conflict.

Catalog- and graph-stage rejections deliberately publish no field and no
detail. They depend on state the caller may not be able to read, so they are
never turned into a probe for concealed objects or edges.

The database independently enforces:

- one unique `from_ref + relation_type + to_ref` triplet;
- `from_ref != to_ref`;
- the registered relationship type set;
- at most one `hosts` relationship for each child.

There is deliberately no database unique index for attachment primary state. Cycle and primary
constraints depend on canonical metadata and endpoint categories and are enforced by the central
collection validator. The existing hosts-only partial placement index is unchanged.

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
`multiple_placement_parents`, `invalid_relationship_metadata`,
`multiple_primary_relationships`, `relationship_cycle`, and `obsolete_data_dependencies`.

Alembic revision `20260801_0013` rebuilds both SQLite tables after validating the complete existing
catalog and relationship set, and copies existing edges with `{}` metadata. Its downgrade is
intentionally refused. Application rollback requires the paired pre-upgrade database backup and
matching previous image.
