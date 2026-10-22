# Catalog object concurrency

Object ETags remain strong, quoted `"rev-N"` tokens. Clients must treat them as
opaque and echo the current token for PUT, DELETE, rename, relationships and
project workspace writes. A newly created ID starts at revision 1, but a reused
ID no longer restarts at 1. No client should assume that creation means `rev-1`.

## Revision continuity (Refs #272)

Migration `20261022_0028` introduces `object_revision_clocks`, a durable per-ID
high-water mark without a foreign key to the catalog. Database triggers allocate
a revision above the retained floor on every INSERT and retain at least the last
revision on DELETE. This covers ORM, command and direct SQL writes. PostgreSQL
uses an atomic UPSERT/RETURNING to serialize allocation; SQLite uses its serialized
writer transaction and an AFTER INSERT trigger. The normal post-insert refresh
reads the allocated revision before returning a response.

This is the monotonically increasing revision alternative to adding instance IDs
to public tokens. Existing authorization, If-Match parsing and atomic ID/revision
CAS all use the same persistent revision namespace. The unchanged wire format
also preserves UI/MCP/admin-token separation. No new runtime configuration is
required. Polling does not allocate revisions.

On upgrade, existing objects seed their current revisions without being changed.
Revision continuity is guaranteed from this migration forward; it cannot recover
identities or revision history already deleted before upgrade. Clocks are part of
the database backup and must not be pruned or reset while old tokens may exist.
They contain only an object ID and integer, not deleted object contents.
Downgrade refuses to discard nonempty clock history. Restore the complete database
(including clocks); a partial catalog-only restore does not preserve concurrency.

Regression coverage includes REST delete/recreate followed by stale PUT and
DELETE (412), a valid replacement token, changed and no-op stale plans at the
atomic SQL boundary, raw SQL deletion, repeated revisions and rollback. Both
SQLite and PostgreSQL are covered. Ordinary same-instance revision/no-op semantics
are unchanged. No deployment or issue closure is implied by this change.

Monitoring's target binding is separate from the catalog revision clock. A
monitoring observation does not claim or advance an object's business revision.
