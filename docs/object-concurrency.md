# Catalog object concurrency

Object ETags remain strong, quoted `"rev-N"` tokens. Clients must treat them as
opaque and echo the current token for PUT, DELETE, rename, relationships and
project workspace writes. A newly created ID starts at revision 1, but a reused
ID no longer restarts at 1. No client should assume that creation means `rev-1`.

## Revision continuity (Refs #272)

Migration `20261022_0028` introduces `object_revision_clocks`, a durable per-ID
high-water mark without a foreign key to the catalog. Database triggers allocate
a revision above the retained floor on every INSERT, retain every UPDATE high-water
mark, and retain at least the last revision on DELETE. This covers ORM, command and direct SQL writes. PostgreSQL
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

## UPDATE enforcement and delayed imports

Every representation-changing database UPDATE now retains its high-water mark,
not only creation/deletion. If a legacy ORM importer or maintenance helper writes
a lower revision (or changes stored fields without advancing the revision), the
database allocates a revision above the current row instead. An exact SQL no-op
retains its revision. This keeps the namespace monotone even for helpers that do
not use the public command CAS and may hold an old ORM snapshot. These existing
unversioned import operations keep their replacement semantics; they cannot lower
the concurrency counter or cause a later incarnation to reuse an issued token.

SQLite performs the correction in an AFTER UPDATE trigger with a conditional
inner revision write; it terminates with recursive triggers either enabled or
disabled. PostgreSQL normalizes NEW before UPDATE and serializes the clock UPSERT.
Application response paths refresh stored rows before publishing the resulting
ETag; public expected-revision/CAS and true no-op behavior remain unchanged.
The migration and model-create definitions contain the same UPDATE guard.

The independent review's real seed-import/REST interleaving is covered on both
databases: import reads1, REST publishes2/3/4, delayed import cannot lower the
stored revision, delete/recreate cannot reuse4, and the original rev4 PUT is412.
Raw lower/equal/omitted increments, exact SQL no-op, clock retention and subsequent
recreation are checked separately. This corrects a review finding; initial CI
success alone did not establish this cross-write-path invariant.
