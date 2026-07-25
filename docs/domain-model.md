# Asset Domain Model

Blockwart version 1 models concrete infrastructure assets:

- `host` is physical hardware, for example a server, workstation, NAS, or
  single-board computer.
- `system` is one concrete runtime environment on hardware, for example an
  LXC container, VM, or WSL instance.
- `service` is one concrete running deployment instance. A distributed service
  is represented by multiple service objects until an explicit grouping model
  is introduced.

`netzwerk` and the non-public catalog kinds are not placement levels.

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
service has exactly one host or system parent. Temporarily unassigned inventory
is represented by the absence of a placement relationship; it is never inferred
from names, IP addresses, or arbitrary JSON data.

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
  corrections, runtime metadata, and explicit decisions for unassigned assets.

The complete implemented relationship and object-lifecycle contract is documented in
`relationship-integrity.md`. Generic dependencies are stored only as directed `depends_on`
relationships; they are not duplicated in object JSON.

Application rollback does not automatically downgrade canonical placement.
Restore the verified pre-upgrade database backup together with the matching
application image.
