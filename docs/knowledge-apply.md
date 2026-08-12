# Reviewed Knowledge apply and rollback

`blockwart-knowledge-apply` is the offline, explicitly mutating companion to
the write-free [`blockwart-knowledge-plan`](knowledge-planning.md) command. It
does not add an apply flag to the planner and is not exposed by the running
HTTP, UI, or MCP service. Phase B supports persistent SQLite catalogs because
the required local backup can be created and verified atomically; other
database backends fail closed before a write-capable connection is opened.

The command is dry-run-first by construction. A controller must retain the
three independent digests from an apply-ready Phase-A result and supply all of
them to `apply`: `classification_digest`, `target_snapshot_digest`, and
`plan_digest`. Apply reloads the reviewed manifest and sanitized target
snapshot, re-hashes the closed source bundle, verifies the implementation
commit/tree and every schema/planner version, and rebuilds the complete Phase-A
plan. A mismatch or `apply_ready=false` stops before backup or transaction.

## Apply contract

The read-only preflight compares every declared object kind, revision, and
sanitized canonical field with the live catalog and verifies every declared
relationship presence and metadata value. It rejects stale or invalid state,
manual-override drift, missing relationship evidence, unsafe or ACL-shaped
content, incomplete provenance, unresolved classification, source-entry
idempotency conflicts, and relationship-integrity failures. Authorization is
recomputed from the current principal and grant tables. Existing objects and
both endpoints of a new relationship require `discover` and `write`; creating
a new Runbook, Decision, or Project additionally requires an active global
Catalog Owner. Every denial has the same concealed error.

Only Runbook, Decision, and Project objects may be created. Asset facts may
update an existing asset's explicitly mapped `data.*` fields while preserving
its provenance. Secret values, ACL fields, authors, source timestamps, and
comments are never imported. Every candidate still passes the ordinary
canonical object, provenance, typed-reference, and relationship validators.

Immediately before mutation, apply creates a SQLite online backup in a
caller-selected owner-protected directory, validates SQLite and foreign-key
integrity, checks a logical whole-database digest, changes the backup and its
paired receipt to mode `0400`, and verifies the same state again under the
write lock. The single transaction then repeats authorization and drift
checks, performs optimistic object updates and relationship creation, checks
the exact planned deltas, owner coverage, comments, and relationship
integrity, and writes one bounded audit record. Audit evidence contains only
digests, counts, IDs, and typed relationship identities. Each identity holds
its endpoint references and relation type plus a domain-separated digest of
canonical metadata; canonical metadata and mapped values are never included.
Document bodies are never included either.

An identical invocation finds the durable batch audit by `plan_digest`, checks
stable `source_id/entry_id` ownership and the current post-state digest, and
returns `changed=false`, `replayed=true` without a transaction, audit, or new
backup. Reusing a source entry under another plan fails closed.

```bash
blockwart-knowledge-apply apply \
  --database-url sqlite:////protected/candidate.sqlite3 \
  --manifest /review/manifest.json \
  --source-root /read-only/source-bundle \
  --target-snapshot /review/target-snapshot.json \
  --expected-classification-digest "$CLASSIFICATION_DIGEST" \
  --expected-target-digest "$TARGET_DIGEST" \
  --expected-plan-digest "$PLAN_DIGEST" \
  --implementation-commit "$IMPLEMENTATION_COMMIT" \
  --implementation-tree "$IMPLEMENTATION_TREE" \
  --principal-id "$CATALOG_OWNER_ID" \
  --backup /protected/backups/knowledge-before.sqlite3
```

## Explicit paired rollback

Rollback is a different subcommand. It requires the protected receipt, its
independently retained digest, the plan and post-state digests, and the exact
whole-database digest returned by apply. It revalidates the receipt, backup
file mode and content digest, backup integrity, current Catalog Owner, unique
apply audit, current post state, and the whole live database. Any intervening
catalog or audit change prevents rollback. Rollback never restores in place.
It copies the protected backup into a private candidate beside the active
database, adds the bounded rollback audit there, validates integrity and all
logical digests, fsyncs the candidate, and rechecks that the active database
is byte-for-byte unchanged. Only then does one same-filesystem atomic replace
make the candidate active. The development catalog is deliberately restored
as a whole; no post-Apply rows are merged or preserved. A pre-replacement
failure leaves the active database untouched. CLI errors report
`database_replaced=false` before that boundary and `database_replaced=true`
when a failure occurs after replacement, so the outcome cannot be mistaken
for an untouched database. A second rollback fails because the restored state
no longer contains the Apply evidence.

```bash
blockwart-knowledge-apply rollback \
  --database-url sqlite:////protected/candidate.sqlite3 \
  --receipt /protected/backups/knowledge-before.sqlite3.receipt.json \
  --expected-receipt-digest "$RECEIPT_DIGEST" \
  --expected-plan-digest "$PLAN_DIGEST" \
  --expected-post-state-digest "$POST_STATE_DIGEST" \
  --expected-database-state-digest "$DATABASE_STATE_DIGEST" \
  --principal-id "$CATALOG_OWNER_ID"
```

Machine contracts are available without opening any database:

```bash
blockwart-knowledge-apply --print-schema apply-result
blockwart-knowledge-apply --print-schema backup-receipt
blockwart-knowledge-apply --print-schema rollback-result
```

This workflow does not change data routing, delete source files, deploy code,
contact a runtime, resolve credentials, or perform remote writes. Backup
retention and any later routing cutover remain separate reviewed operations.
