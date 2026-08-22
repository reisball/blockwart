# Atomic Container Release Workflow

`blockwart-release` is the packaged host-side release controller for one
containerized, SQLite-backed Blockwart service. It is host-neutral: the
operator supplies absolute host paths and a local Docker or Podman runtime in
a version-1 JSON specification. It does not provision a VM, network, TLS,
proxy, credentials, grants, schedules, or client/agent configuration.

Dry-run is the default. These commands are equivalent and make no filesystem,
database, image, container, or pointer change:

```bash
blockwart-release --spec /etc/blockwart/release-v1.json
blockwart-release plan --spec /etc/blockwart/release-v1.json
blockwart-release release --spec /etc/blockwart/release-v1.json
```

A real release requires both the mutation flag and an explicit compare-and-set
expectation for the managed current release:

```bash
blockwart-release release \
  --spec /etc/blockwart/release-v1.json \
  --apply \
  --expect-current none

blockwart-release release \
  --spec /etc/blockwart/release-v1.json \
  --apply \
  --expect-current aaaaaaaaaaaa-bbbbbbbbbbbb
```

Use `none` only for the first managed installation. A later mismatch is
`stale_current_pointer` and fails before image build, backup, or service
mutation. `status` is read-only:

```bash
blockwart-release status --spec /etc/blockwart/release-v1.json
```

JSON is the default output. `--format summary` is an explicit human-readable
alternative. Exit codes are stable: `0` planned/succeeded, `1` failed before a
completed rollback, `2` invalid CLI use, `3` release failed and verified
rollback succeeded, and `4` rollback itself failed closed. Version-1 JSON
Schemas are installed with the CLI:

```bash
blockwart-release --print-schema spec
blockwart-release --print-schema manifest
blockwart-release --print-schema report
blockwart-release --print-schema pointer
blockwart-release --print-schema status
blockwart-release --print-schema error
```

The complete generic example is
[`examples/release/spec-v1.json`](../examples/release/spec-v1.json). Unknown
fields and versions are rejected. The source commit is exactly 40 lowercase
hexadecimal characters; abbreviated SHAs, symbolic refs, ambiguous SHA-shaped
refs, missing objects, non-commit objects, and commits unreachable from every
ref are rejected. The repository must be at that exact `HEAD` with a clean
index and worktree. Source evidence is checked again after image resolution so
a concurrent ref or tree change cannot reach backup or cutover.
Build mode never passes the host checkout to Docker/Podman. It materializes a
temporary archive of the accepted commit, rejects archive links, devices, and
traversal, and builds with the container file from that tracked-tree context.
Ignored or untracked `.env`, SQLite, credential, and other private host files
therefore cannot enter an image even when `.dockerignore` does not name them.

## Host layout and trust boundary

The repository, release state root, backup root, and live data directory must
be absolute, disjoint, symlink-free paths. Existing state, backup, data, live
database, and optional environment files must be owned by the invoking user
and not group/world writable. The service is always published on explicit
IPv4 loopback using `127.0.0.1:HOST_PORT:CONTAINER_PORT`; TLS and the trusted
reverse proxy remain outside this tool.

When the configured backup root is absent, apply creates that single directory
as the invoking user with mode `0750`, durably records the parent update, and
validates it before creating an attempt directory. Missing parents, symlinks,
foreign ownership, and group/world-writable roots fail closed; caller umask
cannot make a newly created root more permissive.

The release state root contains only non-secret release evidence:

```text
STATE_ROOT/
  lock
  pointers.json
  history.jsonl
  releases/RELEASE_ID/
    manifest.json
    manifest.sha256
    artifacts/{build,contract,source}.json
  reports/
```

`pointers.json` holds `current` and `previous` together, so the pair is one
atomic, durable replacement rather than two independently updated links. Each
pointer binds the release id, generation, source SHA, image content digest,
manifest digest, packaged schema revision, and an opaque digest of the
persistent runtime layout. Before a new release, the controller verifies the
complete current bundle and every artifact digest, the exact local rollback
image and its embedded `BLOCKWART_BUILD_REVISION`, the running container image,
and daemon-reported runtime layout. The inspected bind mounts and read/write
mode, published address/ports, restart policy, network mode, and effective
environment are compared to the image plus configured service overrides. Only
an opaque digest is persisted; environment values and paths are never emitted.
A same-name, same-image container with different wiring fails before backup.
Missing evidence, a stopped/missing managed
service, or drift fails before backup or cutover.

Bundles are staged in the release store, fsynced, renamed atomically, and
replayed only when all immutable bytes match. Their canonical JSON uses sorted
keys, compact separators, UTF-8, and no non-finite numbers. A manifest binds
the exact source commit/tree, immutable image digest and build revision,
container build metadata, expected and packaged Alembic head, host-neutral
contract digest, and the SHA-256 of every artifact. Host paths, bind addresses,
environment-file locations/values, database content, endpoints, credentials,
and hook commands are not copied into the bundle or manifest.

The configured retention is bounded to `2..100`. Successful housekeeping
keeps the newest managed bundles/backups plus every bundle named by both the
committed and pre-transaction current/previous pairs until completion evidence
is durable. Thus a late report failure can restore two pointers that still
name complete bundles. Housekeeping also removes image tags associated with a
pruned bundle and never deletes the current invocation's backup. Unrelated content
in the backup root is never considered managed. A rollback failure does not
run retention, so its backup, failed database, bundle, and report remain for
diagnosis. Retention trouble is a recorded `retention_incomplete` diagnostic
and never invalidates an otherwise verified cutover.

## Backup and candidate gates

The live SQLite database is opened read-only and copied with Python SQLite's
online backup API to the separate backup root. The finalized backup is
read-only and has a canonical receipt binding release/source, filename,
SHA-256, size, creation time, and successful SQLite check. Before every use,
the workflow rechecks receipt digest and fields, backup digest, ownership and
permissions, `PRAGMA integrity_check`, and `PRAGMA foreign_key_check`.

Candidate migration never mounts the live data directory. It restores the
verified backup into a private candidate directory and runs the exact image
content digest with no published port and `--network none`. The ordered,
bounded gates are:

1. `blockwart-db upgrade` on the restored copy;
2. packaged Alembic head equals the specification;
3. `blockwart-db check`;
4. `blockwart-db integrity` for catalog/relationship integrity;
5. Blockwart's internal `/api/health/ready` contract; and
6. the OCI container healthcheck.

The daemon-reported candidate mount, environment, restart policy, network mode,
and absence of published ports are verified before readiness. Each migration,
schema, and database-check container has a deterministic release-scoped name;
after success, failure, or client timeout the controller force-removes that
exact name and never enumerates or cleans unrelated containers.

Readiness and container health are different gates. A readiness success can
arrive before Docker/Podman records its next health probe. A `healthy` value is
therefore accepted only when its newest probe ended strictly after readiness
was observed; a stale healthy result is polled until the health timeout and
then fails before cutover.

## Cutover and rollback

After candidate success, the current image is pinned under a release-specific
rollback tag. Cutover stops and removes only the configured managed container,
then takes and verifies a final SQLite snapshot. Its database digest must match
the snapshot proved by the candidate. A concurrent write between candidate
proof and service stop produces `stale_live_database`; rollback uses the final
snapshot, so that write is preserved, and the operator can retry in a quiet
window. Only an unchanged database proceeds to start the exact candidate
digest against the live persistent data directory,
and repeats readiness, fresh container health, schema, and relationship
integrity gates. Every command, poll, stop, start, cutover, rollback, and hook
has a finite configured timeout.

Stopping the managed service is the point of no return. Any timeout or failure
from that point through hooks or pointer/history commit automatically:

1. stops/removes the failed candidate container;
2. re-verifies the exact pre-release backup;
3. moves the failed live database and SQLite sidecars into preserved evidence;
4. restores the verified backup by durable replacement;
5. starts the exact previous image digest; and
6. verifies its daemon-reported runtime layout, rollback readiness, a fresh
   health probe, packaged schema, and
   relationship integrity before restoring the pointer pair.

Rollback never invokes Alembic downgrade. If no managed predecessor exists,
the database is restored and the service stays stopped rather than selecting
an image by guess. A rollback failure returns exit `4`, keeps all evidence,
and reports both the original and rollback errors. If the restored service
fails runtime-layout, readiness, health, schema, or integrity verification, its
exact managed container is stopped and force-removed so an unverified
published/restart-enabled service cannot remain running; containment status is
part of the rollback evidence.

## Reports and hooks

Plans, completion reports, and failure reports use canonical version-1 JSON.
They contain source/image/manifest/artifact digests, expected and packaged
schema, ordered gate results, pointer summaries, backup evidence, outcome,
rollback evidence, hook results, and stable redacted diagnostics. They never
contain command stdout/stderr, host paths, environment values, SQL/database
content, private endpoints, credentials, or exception text.

Hooks are optional and run only after the new service passes every cutover
gate. Each hook is an explicit absolute executable plus at most 31 literal
arguments and a bounded timeout; no shell is involved. Credential-shaped
arguments are rejected. In addition to a fixed non-secret `PATH`/locale, a
hook receives only:

- `BLOCKWART_RELEASE_ID`
- `BLOCKWART_RELEASE_SOURCE_COMMIT`
- `BLOCKWART_RELEASE_IMAGE_DIGEST`
- `BLOCKWART_RELEASE_MANIFEST_DIGEST`
- `BLOCKWART_RELEASE_SCHEMA_REVISION`
- `BLOCKWART_RELEASE_OUTCOME`

Hooks are verification/reporting contracts only. They must not deploy,
rewrite proxy/TLS/network policy, rotate credentials, mutate Blockwart grants
or catalog data, or rewrite an external client, Gateway, MCP, or agent
configuration. A timeout or nonzero exit triggers the same automatic rollback.
