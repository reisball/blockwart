# Safe operation custody and native audit

## Value-free write state

Migration `20261111_0033` adds only `safe_operations`. It does not copy,
rewrite or migrate credentials. Its columns are operation ID, actor, channel,
object ID, immutable object instance, action, CAS, source version, state and
result version. There are no field names, values, request bodies, value hashes,
tokens or replay responses. No scheduler or background reconciler is added.

A mutation commits value-free `intent` before backend work. Configuration,
restore-source reads and AppRole login precede a conditional `intent` →
`dispatched` update committed immediately before the KV mutation POST. Only one
concurrent caller may claim that transition; no DB transaction spans backend I/O.
KV-v2 writes include the operation ID alongside the internal credential envelope;
ordinary read responses omit it. CAS remains the backend concurrency boundary.

| Interruption | Next attempt |
| --- | --- |
| Intent commit fails | No backend call occurred; a later admitted attempt may write. |
| Intent committed, before dispatch | No mutation was admitted; a retry may claim intent and send. |
| Dispatch committed, before send | Same as an in-flight request: bounded exact-version reconciliation. |
| Backend wrote, response lost or response audit failed | Read only CAS+1 and compare its operation ID. |
| Final DB/audit commit fails | The durable intent remains; the same exact-version comparison repairs completion. |
| Policy revoked after backend write | Persist completion first; deny the response and record that denial. |
| Competing CAS writer | A different operation at CAS+1 records conflict, never success. |

Reconciliation does one exact-version read, not a history scan. Matching ID
records success and returns only the original version, even when later versions
exist. This response is a receipt for the original operation, not a statement
about the current credential value or deletion state. This also applies to
legacy callers: retrying an old delete may return its old success after a later
undelete. To change the current entry, obtain a fresh CAS through an authorized
read/history path and submit a new intent; do not infer current state from an
old-CAS success.
An absent version returns 409 pending: absence cannot prove that a previously
dispatched network request will never execute. No automatic cancellation,
cleanup, deletion of originals or blind retry is inferred from a timeout.
Unavailable/malformed backend responses keep ambiguous custody and return 503.

This is a limitation of separate DB and KV transactions, not exactly-once
distributed execution: a crash before send can leave pending custody indefinitely.
An operator/caller may initiate a *new* operation with an explicit new ID and the
same known CAS after assessing the pending operation. CAS still allows at most
one winner at that version; this is not automatic replay or proof that the old
request stopped.

The API/MCP add optional `operation_id` (64 lowercase hexadecimal characters)
and `action: reconcile` with that ID. The caller retains an ID before submitting
a new operation; mutation success remains the compatible `{"version": N}`.
Reconciliation and retries require current content-write permission and the
original actor, channel, object and instance. Reusing an ID for another action,
CAS or source version is rejected. Write retries compare fields and preset in
memory against the exact CAS+1 backend envelope, including already-completed
rows. Changed content returns 409, never a success for content not stored; neither
values nor value fingerprints are persisted locally. Explicit `reconcile` returns
status only and never accepts a replacement payload. Read/history use fresh
internal correlation IDs.

Legacy UI/API/MCP callers need no new argument: a value-free digest of instance,
actor, channel, action, CAS and source version binds their implicit intent.
Repeating a dispatched tuple reconciles, never resends. A definitive backend
400/404 rejection (locally conflict/failed) may be retried by legacy callers;
unsent intent is retryable, but ambiguous dispatched custody is never reset.
Caller-supplied IDs use a separate actor/channel/instance-scoped namespace and
cannot preclaim another actor’s derived legacy ID. UI POST also accepts explicit
operation IDs; existing forms retain their existing shape. All paths recheck
current authorization after I/O before returning status or values.

Do not downgrade to a writer that ignores custody. Schema downgrade refuses
while any operation rows exist. Prefer a forward fix. Preserve the DB, backend
and operation records together; do not delete intents to make a retry work.

## Native audit and correlation

OpenBao **v2.7.2** natively supports the declarative `audit "file" "blockwart"`
stanza and the audited-request-header allowlist. See upstream
[declarative audit](https://openbao.org/docs/configuration/audit/),
[file audit](https://openbao.org/docs/audit/file/) and
[request-header configuration](https://openbao.org/docs/api/system/config-auditing/).
The implementation was checked against tag v2.7.2, commit
`9e0a0d3c3504a0a00b45e61355afac5e35c78379`.

The sole sink is `/openbao/audit/audit.json` in the separate persistent
`credential-safe-audit` volume; directory mode 0700, log mode 0600.
`log_raw=false` and accessor HMAC remain enabled. Accepted secret field values
are strings and are HMAC-redacted by OpenBao, including multiline values.
Non-string field payloads are rejected by the broker before backend access;
structural CAS/version numbers and deletion booleans are not secret values.
Do not enable raw audit, non-HMAC secret keys, stdout audit or a second
always-writable sink that would mask failure of the protected sink.

The fixed `X-Blockwart-Operation` header is allowlisted with `hmac=false`.
Only an operation ID is sent, never principal credentials or field content.
Join Blockwart's actor/channel/operation records to native request headers, then
native `request.id` to request/response records. This joins failed, denied and
lost-response requests too, including AppRole login and revoke-self attempts.
Native identity is the **broker AppRole**, not the individual Blockwart user.
Denied catalog authorization is recorded locally without a backend request;
caller-supplied operation IDs are digested even on that path. Request audit
outcomes distinguish `payload_mismatch`, `claim_lost`, `unavailable`, `pending`
and malformed dispatched-response `uncertain` from durable custody states.
Already-completed retries record `reconciled`, not another backend completion.
A conditional completion update also prevents concurrent reconcilers from
auditing the same successful backend completion more than once.
Failed revoke-self emits only an operation-correlated fixed warning; token TTL
still bounds exposure and the next operation logs in anew.

The existing supervisor checks the file once per second. At 10 MiB it invokes
Debian's maintained logrotate, retains seven archives (delayed compression),
and signals native SIGHUP to reopen. Debian logrotate and libpopt are installed
at reviewed versions through apt/dpkg, including Debian’s required cron package;
package service startup is blocked and the Python entrypoint never runs cron.
Only the supervisor schedules rotation. Pins require reviewed security updates;
live apt repositories are not an immutable snapshot of transitive dependencies. Retention is count/size-triggered, not a guaranteed age; the active file
can overshoot between checks under load. Storage exhaustion makes native
operations fail closed. Rotation failure emits
`safe_backend_audit_rotation_failed` and stops the backend; ordinary Safe
503/uncertain audit outcomes expose sink failures without raw backend errors.
Catalog/login/metadatas do not depend on the sink. Protected audit-volume
capacity and failure markers must be included in the deployment's monitoring.

## Existing-instance configuration and rollback

Fresh bootstrap configures the fixed header and verifies a durable, narrowly
scoped maintenance AppRole before revoking its initial root. See
[recurring maintenance access](credential-safe.md#recurring-maintenance-access-fresh-setups).
Its short-lived login token suffices for this fixed-header helper.
An existing installation must first provision the same header against its
running internal backend using an explicitly authorized temporary administration
token with OpenBao ACL `create`, `update`, and `sudo` capabilities on
`sys/config/auditing/request-headers/x-blockwart-operation`, then persist
`/control/audit.json` with `{"version":1}`. Here `sudo` is an OpenBao ACL
capability, not operating-system sudo.
The new supervisor deliberately refuses runtime startup without this marker.

Run the helper `python /supervisor.py --configure-audit /protected/token.json`
from the candidate/new image, never by executing the old container’s supervisor.
The old binary does not implement this flag and may start a second backend.
The helper reads a protected JSON string token file, configures only that fixed
allowlist, and writes the marker. Give the new-image helper the existing backend’s
network namespace (for default loopback), or an explicit internal `SAFE_LOCAL_URL`,
and the existing protected control mount in the reviewed deployment procedure.
Do this before replacing the old running supervisor; its old backend can serve
this admin request. Malformed helper arguments exit before any backend startup. Revoke the temporary token and remove its protected file afterward.
Never replace broker auth or initialize a new backend to satisfy this gate.

Stage the audit-volume/config/header provisioning and additive DB migration
before admitting the new application writer. Existing secret envelopes remain
readable without rewriting them. An old envelope cannot attest a new operation
ID and is treated as a conflicting version during reconciliation.

Rollback must retain operation custody and native audit. Removing a declarative
stanza disables that native device on reload; do not remove it as an application
rollback shortcut. No live migration or configuration is performed by tests.

## Finite verification

`tests/test_safe_reconciliation.py` and `tests/test_safe_faults.py` cover
durability before send, intent/dispatch/final-commit failures, lost responses,
exact earlier versions, changed retry fields/preset, CAS competition, postwrite
revocation, and additive schema/no-drift/downgrade behavior.
`tests/test_safe_retry_binding.py` also covers retryable unsent intent,
definitive rejection recovery, actor-scoped namespaces, concurrent first
admission and fresh policy checks before pending status responses.
`tests/test_safe_postgresql.py` runs conditional-dispatch races, admission
conflicts, lost responses and terminal-rejection recovery against a disposable
PostgreSQL ledger.
`tests/test_safe_native_audit.py` accepts an explicit
`BLOCKWART_TEST_BAO_BINARY` pointing to a disposable v2.7.2 executable; it
checks expiry/relogin/revocation, real lost-response correlation, retry after
login/source-read failures, native sink failure and actual independent
catalog/password-login availability.
The existing `scripts/ci/credential_safe_smoke.py` additionally exercises the
digest-pinned static-seal bundle, persistent private audit, native denials,
redaction and sink-failure/recovery. Its root-container supervisor proof uses the
actual main loop for nine rotations/pruning and verifies Bao shutdown with fixed
markers after rotation failure. A separate existing-instance rehearsal invokes
`--configure-audit` against default loopback, proves `sudo` is required, and
checks unchanged broker auth/data and removal/revocation of the temporary token.
