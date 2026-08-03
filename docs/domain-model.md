# Asset Domain Model

Blockwart version 1 models concrete infrastructure assets:

- `host` is physical hardware, for example a server, workstation, NAS, or
  single-board computer.
- `system` is one concrete runtime environment on hardware, for example an
  LXC container, VM, or WSL instance.
- `network` is either a segment or a network device, distinguished by the
  required closed `data.network.category` vocabulary on new writes.
- `device` is a non-compute equipment asset such as an antenna, sensor,
  adapter, controller, or UPS. Its required `data.device.category` is
  `antenna`, `sensor`, `adapter`, `controller`, `ups`, or `other`.
- `service` is one concrete running deployment instance. A distributed service
  is represented by multiple service objects until an explicit grouping model
  is introduced.

`network`, `device`, and the non-public catalog kinds are not placement levels.

English identifiers are the canonical backend contract. Alembic revision
`20260729_0007` migrates the former `netzwerk` identifier and every valid typed
reference to `network` before the application starts. UI labels are localized
independently; see `internationalization.md`.

## Lifecycle and operational health

Infrastructure assets use two independent, closed dimensions:

- `lifecycle`: `planned`, `active`, or `retired`
- `health`: `unknown`, `healthy`, `degraded`, `down`, or `maintenance`

The values are stored in dedicated `catalog_objects` columns for `host`, `system`, `network`,
`device`, and `service`. They are absent for knowledge objects such as runbooks and decisions. Free-form
`data.lifecycle` and `data.health` fields are rejected.

The legacy `status` column remains a derived compatibility field while UI work is out of scope:
`retired` maps to `deleted`; `planned`, `down`, and `maintenance` map to `inactive`; all other
active-lifecycle pairs map to `active`. Health is never inferred as healthy. A legacy `active`
record becomes `active`/`unknown`, `inactive` becomes `planned`/`unknown`, and `deleted` becomes
`retired`/`unknown`.

The database enforces the vocabulary, asset-only presence, and compatibility mapping. Seeds,
Markdown import, catalog REST, Agent API, and MCP use the same contract. Lifecycle and health
changes are named separately in object-update audit summaries.

## Canonical placement

Placement has one storage source: a `hosts` relationship whose direction is
parent to child.

The valid version 1 shapes are:

```text
host hosts system
host hosts service
system hosts service
```

This produces either `host → system → service` or a service running directly on
hardware. A valid runtime system has exactly one hardware parent, and a valid
service has exactly one host or system parent. Inventory may also be deliberately
unassigned. That state uses no placement relationship and carries an explicit
marker in object data:

```json
{
  "placement": {
    "state": "unassigned",
    "reason": "No canonical placement parent has been assigned."
  }
}
```

The marker is valid only for `system` and `service`. A missing parent without the
marker remains an unresolved migration decision, while a parent plus the marker
is contradictory. Creating a canonical `hosts` relationship clears the marker
in the same transaction. Placement is never inferred from names, IP addresses,
or arbitrary JSON data.

The shared placement graph is used by the catalog REST API, Agent API, MCP, and
the UI topology. Multiple canonical parents fail closed instead of being
silently ordered. Invalid or dangling relationships do not become placement
edges; the central diagnostics and enforcement for every relationship type are
tracked in #34.

`service.data.system_id` and `provides` relationships are legacy placement
sources. Alembic revision `20260724_0003` reconciles them with any existing
`hosts` edge, rejects conflicts, creates a missing canonical edge, converts
`provides`, and removes only `system_id` from the JSON document. New payloads
containing `system_id` and new `provides` writes are rejected.

## Device and network links

Attachment and uplink edges are separate from placement. Their canonical directions are
child/endpoint to immediate parent/upstream:

```text
host|system attached_to network-device
device attached_to host|system|network-device|device
network-device uplinks_to network-device
```

A `network` object is a network device only when `data.network.category` is one of `switch`,
`router`, `access_point`, `mesh`, `firewall`, `gateway`, or `other_device`; `segment` is explicitly
not a device. Services and segments cannot be attachment endpoints. These links do not propagate
RBAC and do not change the existing `hosts` placement hierarchy.

Existing Network rows without a category remain readable during the migration transition. Every
new or updated Network payload through the canonical schema service is fail-closed until it has an
explicit category. No migration guesses or mutates that classification.

`blockwart-db networks` is the write-free classification gate. It emits one
canonical JSON record per existing Network with the exact current category,
evidence-backed target category, evidence source, planned action, and blockers.
An explicit mapping file uses schema version 1 and contains only `object_id`,
`target_category`, and `evidence_source` rows. Missing evidence, unknown mapping
references, invalid mappings, or malformed stored data fail closed. Even with a
complete plan, `blockwart-db --apply networks` is deliberately unavailable;
the reviewed apply transaction belongs to the later pilot-import slice. For a
persistent SQLite source, the gate reads a stable temporary database/WAL
snapshot so the source file, journal mode, and WAL/SHM sidecars remain byte-for-byte
unchanged even when the source directory itself is not writable. A non-zero
hot or unrecovered rollback journal fails closed because a lock-free file copy
cannot distinguish committed pages from an in-flight transaction. Empty
journals and zero-header journals retained after a successful SQLite `PERSIST`
commit are stable non-hot sidecars and do not block the dry run.

The shared Network resolver starts from direct host/system attachments or the
canonical placement host inherited by a system/service. It traverses every
authorized `uplinks_to` edge, treats `primary` only as a stable sort hint, and
reports router/gateway terminals as complete. Other terminals are incomplete;
missing start points are unconnected. Policy projection precedes traversal and
path/count calculation, so unreadable neighbors leave no graph fragment or
indirect count. API v1, Agent API, and MCP use this same resolver.

## Object identity

`catalog_objects.id` is globally unique because it is the table's primary key.
The prefix in a typed reference such as `service:blockwart` is a kind assertion
and routing aid, not a separate namespace. `host:shared` and `system:shared`
cannot coexist as different objects.

Seed input rejects duplicate IDs across kinds. A kind change retains the same
global identity, but updating existing typed references during kind changes is
part of the general referential-integrity contract in #34.

## Migration boundaries

This contract chooses the hierarchy and canonical storage. It does not guess
which real hardware owns an unassigned runtime or service.

- #34 owns the complete relationship vocabulary, database constraints,
  referential integrity, and diagnostics.
- #38 owns classification of live and pilot inventory, including hardware kind
  corrections, runtime metadata, and the explicit unassigned state.

The complete implemented relationship and object-lifecycle contract is documented in
`relationship-integrity.md`. Generic dependencies are stored only as directed `depends_on`
relationships; they are not duplicated in object JSON.

Application rollback does not automatically downgrade canonical placement.
Restore the verified pre-upgrade database backup together with the matching
application image.
