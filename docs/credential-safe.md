# Integrated credential safe (V1)

The safe is opt-in. Existing deployments, credential references, locators and
stored catalog content are not migrated or changed automatically. Blockwart is
the only supported UI, REST and MCP interface. OpenBao is an internal backend,
not an additional user-facing service.

## Deployment bundle and trust boundary

Use the ordinary delivery image for Blockwart and the explicit
`compose.safe.yaml` overlay for the backend. The default `compose.yaml` and
`Dockerfile` remain unchanged. For a separately approved deployment:

1. Create a protected host directory for the static seal key, outside the
   repository, images, catalog database, control directory and OpenBao volume.
   Generate `unseal.key` once with 32 random **raw bytes**, not base64.
   Set directory permissions to 0700 and the file to 0600. Do not regenerate it
   on restart. The accepted trust boundary is the host and its administrators.
2. Create a separate protected host control directory (0700), initially empty except for an empty `runtime/` subdirectory
   (0700).
   It holds durable broker AppRole credentials, operator-only recovery material
   and temporary bootstrap state. Fresh setups also retain maintenance AppRole
   credentials in the operator-only `operator/` subdirectory (0700).
   Set `BLOCKWART_SAFE_KEY_DIR` and `BLOCKWART_SAFE_CONTROL_DIR` to these absolute
   directory paths. Both containers must have the intended file-read rights;
   do not make credentials world-readable. The shipped images run as root;
   deployments changing the runtime UID must arrange matching ownership.
3. Explicitly use
   `docker compose -f compose.yaml -f compose.safe.yaml up --build`.
   The seal-key directory is mounted read-only only into the backend; the
   Blockwart container receives **only the runtime subdirectory** read-only;
   temporary bootstrap/root material is never mounted into the application. Only the
   internal Docker network connects them. No backend port is published.
4. Check the backend's value-free `safe_backend_ready` status before use.
   Bootstrap initializes only uninitialized storage paired with empty control
   state. It mounts KV-v2 with mandatory CAS and a very high retention limit,
   writes a small synthetic sentinel, restarts the real server, and reads the
   persisted sentinel before issuing runtime credentials.
5. Preserve all three independent state inputs: the static key, OpenBao data
   and control credentials. This release does not implement backup or restore
   tooling. Losing a required input fails closed; it does not initialize
   replacement storage over an existing deployment.

An initialized backend without its matching control state fails closed.
A failed/interrupted first sentinel write is never retried against that mount:
this protects against the known upstream first-write salt-loss bug
[OpenBao #4331](https://github.com/openbao/openbao/issues/4331). Resolve an
incomplete bootstrap as an operator; do not delete existing storage or replace
a key to make an error disappear. Runtime credentials are published only after
the restart persistence check and initial root-token revocation. Temporary
root-token files are private (0600), are never runtime credentials, and are
removed after recoverable finalization. Initialization response loss cannot
be repaired by blindly reinitializing existing storage.

### Operator recovery material

Bootstrap durably saves the full initialization envelope to private `init.json`
before splitting it into `root.json`, `stage.json` and operator-only
`recovery.json`. An interruption between these file writes resumes from the
same envelope without reinitializing storage. Once split, the envelope is
removed; recovery shares remain in `recovery.json` (0600) in the protected
control directory, **outside** `runtime/`. The application mount contains only
`runtime/broker.json`; never mount the full control directory into Blockwart.
Recovery shares are not unseal keys: keep the original static seal key as well.
An initialization HTTP response lost before the envelope is durably saved still
requires operator recovery; the supervisor fails closed, never reinitializes.

### Recurring maintenance access (fresh setups)

Before revoking the initial root, fresh bootstrap provisions the fixed
`blockwart-maintenance` AppRole and policy. Its nonexpiring role/secret IDs are
saved in `operator/maintenance.json` (0600) under the protected control directory,
never under `runtime/` or in the application mount. The planned SecretID is saved
before OpenBao's supported `custom-secret-id` call; interrupted creation looks up
that same ID instead of allocating a new credential. Finalization revalidates the
accepted policy/role, proves fresh maintenance and broker logins, then revokes the
initial root. Bootstrap verification tokens are revoked too. Existing controls
are not automatically provisioned or migrated.

For authorized maintenance, POST this private JSON as the request body to the
internal `auth/approle/login` endpoint. Keep its returned token in a protected
0600 operator file only if needed; do not put credentials in argv, shell history,
application settings or logs. Tokens have a maximum lifetime of **900 seconds**,
including renewals. Revoke with `auth/token/revoke-self` after use; log in again
when needed. The long-lived IDs survive backend restarts. Protect and back up
them with the other control material. They grant only:

- Read/create/update of the fixed `x-blockwart-operation` audit-header setting.
- Read-only `sys/storage/raft/configuration`.
- The authenticated `sys/generate-root-token/*` recovery-share ceremony.
- Token lookup-self and revoke-self.

They cannot read/write secret KV, administer arbitrary policies/auth methods, or
create root tokens directly. Ordinary header maintenance can use the existing
`--configure-audit` helper with this short-lived token; no root is needed.

OpenBao 2.7.2 requires **both authenticated operator authority and recovery
shares** for [root generation](https://github.com/openbao/openbao/blob/v2.7.2/website/content/docs/api/system/generate-root-token.mdx).
Recovery shares alone are insufficient; the deprecated unauthenticated endpoints
are disabled by default. For separately authorized exceptional administration,
a maintenance token authenticates the attempt/update requests, while the retained
recovery shares satisfy the quorum. Keep the nonce, OTP and encoded response
private; decode the response using that attempt's OTP. Revoke any generated root
afterward, never use it as broker auth. Lost final responses require operator
reconciliation, not blind share replay or another root-generation attempt.
Existing installations without this AppRole require an independently established
administration route; this change does not retrofit one or enable legacy routes.

The supervisor emits readiness/unavailable and audit-rotation-failure markers.
Operational OpenBao stdout/stderr are discarded. Native HMAC-redacted audit is
retained separately in the protected persistent audit volume, with size-triggered
logrotate retention. See [operation custody and audit](credential-safe-operations.md)
for correlation, failure handling and the existing-instance configuration step.

OpenBao's native static seal performs auto-unseal. If the key is missing or
wrong, the backend stays unavailable and the container restart policy retries.
Restoring the original key permits automatic recovery on the next start;
no interactive unseal, new root token or reinitialization is required. The
read-only **directory** bind lets replacement of the key file become visible
without retaining a stale mounted inode.

The standalone settings are `BLOCKWART_SAFE_URL` (fixed operator-approved
internal URL) and `BLOCKWART_SAFE_AUTH_FILE` (protected broker JSON file).
Empty defaults disable safe operations, not catalog/login availability. The
broker performs AppRole login per operation, uses a short-lived 60-second
token, and revokes it afterward. Persistent role/secret IDs survive restart;
no root token reaches the application, browser, MCP configuration or database.
The scoped policy allows only KV data read/create/update and metadata reads.
Destroy, metadata deletion, policy administration and root operations are
excluded. Internal plaintext HTTP is confined to the accepted single-host
internal network; do not expose this listener or route it over an untrusted
network. Broker, supervisor and MCP HTTP clients reject redirects and ignore
environment proxies, including for loopback requests carrying secrets.

## Credential entries and operations

Explicitly select provider `safe` on a credential reference. Changing an
existing entry to/from this provider requires its existing content-write
capability as well as the ordinary metadata update rights. Keep
`data.reference` empty: safe values use a separate transport and are never
stored in catalog JSON. Creating a new reference uses the existing authorized
creation workflow and Owner assignment. The existing
`secret_value_stored: false` flag continues to describe the **catalog**.

The backend locator is computed only from the immutable server-generated
catalog instance identity, not from a submitted path, object label or locator
field. Renames preserve it; deleting/recreating a catalog identity cannot
attach a new object to an old secret. Keep the catalog entry to retain access
to its history; use the safe's soft-delete action, not catalog-object removal.

The UI provides explicit POST actions and local templates for login
(`username`, `password`), API token (`token`), multiline key (`key`,
optional `passphrase`) and other values. Fields are freely named strings:
at most 64, names up to 128 characters, individual values up to 65536
characters, aggregate JSON up to 256 KiB. No automatic value fetch occurs on
a detail GET or edit action. Reveal results are escaped, private and
`no-store`; browser POSTs require the existing CSRF token. Do not enable
request/response body logging on secret endpoints in reverse proxies.

REST clients POST to `/api/v1/objects/{id}/safe` using their existing bearer
token. MCP clients use `blockwart.credential_safe` with the same fields plus
`object_id`.

Safe MCP transport requires configured bearer credentials before network I/O.
Only trusted loopback may use HTTP; remote API targets require HTTPS. MCP clients,
agent/model providers and conversation tooling can retain intentional safe inputs
and results. Blockwart does not control that retention; catalog nonpersistence
and `no-store` are not a guarantee of transcript deletion. Use safe operations
only in approved receiving clients and conversations.

Supported actions:

- `action: read`: explicitly reveal current value, or a positive `version`.
- `action: history`: return version metadata, never values.
- `action: write`: send `fields`, optional `preset` and mandatory `cas`.
- `action: delete`: write a reversible tombstone with mandatory `cas`.
- `action: restore` or `undelete`: copy a non-deleted source `version`
  into a new current version with mandatory `cas`.

CAS is the current safe version (0 for the first write), independent of the
catalog ETag. A concurrent mutation wins once; stale CAS gets 409 and missing
CAS gets 428. Deletion uses a **CAS tombstone**, not OpenBao's non-conditional
delete endpoint, so it cannot accidentally delete a concurrent newer version.
An old version is still explicitly readable while the current version is
deleted. Restoring a saved password does **not** change the password on any
target system.

Current `read_reference_content` authorizes reveal and history, including old
values. Current `write_reference_content` authorizes mutations, but never
reveals values to a write-only client. Restore copies server-side and returns
only the new version number. Metadata read/write alone grants neither.
Existing effective Owner/catalog-owner permissions are unchanged; no parallel
safe roles are introduced. Two short command lock/refresh transactions check
current principal activity, grants, object instance and revision: before backend
I/O, then again before response. Backend completion is recorded before the
second check, even if that check denies the response. No catalog transaction or command
locks remain open during backend calls. Revocation, deactivation, replacement or
an intervening object edit prevents returning values. Already-authorized backend
work may have completed before that second check; it cannot be rolled back by
catalog authorization. Secret values
never enter catalog persistence, object history, search, exports, ordinary
audit events, or denial records. Audit records contain only fixed operation,
principal, channel, state and correlation metadata.

Sealed/down/timeouts return 503; there is no plaintext fallback.
Metadata/catalog/login remain independent. Backend mutation and catalog audit
are not one atomic transaction. A durable value-free intent precedes dispatch;
the operation ID is written inside the internal KV envelope. Retry of the same
intent only reconciles its exact expected version; it never repeats a backend
write. This also works for write-only callers without returning values. A missing
expected version remains explicitly pending, not falsely successful or failed:
an original dispatched request might still be in flight. See
[operation custody and audit](credential-safe-operations.md) for crash points,
compatibility and migration/rollback constraints.

There is no permanent-destroy operation. KV retention is explicitly set to
2147483647 versions rather than the upstream default of 10. The broker stops
writes before the configured limit instead of letting retention trim old
values. This is bounded retention, not unlimited history: metadata responses
also have a 1 MiB transport cap, so practical history retrieval can reach its
bound much earlier (503, without truncation). A write-only caller cannot discover
the current CAS through history; it must retain the version from a prior write
or obtain it from an authorized reader. Do not manually lower this limit or mutate the internal mount.

## Pinned artifact and reproducible proof

The optional bundle currently supports Linux amd64 and pins OpenBao **2.7.2**,
released 2026-10-26, source commit
`9e0a0d3c3504a0a00b45e61355afac5e35c78379`.

- Official image index:
  `quay.io/openbao/openbao@sha256:5046911075e137e154ce49ab051502f4ec7cf367d484ae4a4dce665d9b90561f`.
- Official Linux amd64 archive SHA-256:
  `582b1f3c2fdc5afd443b2d57a225ef654de75adea609fdb66731fd582a9cbc96`.
- Archive and image executable both:
  `9c5f36287c673f386e1533e9c044169a248e4ee50dd54810fa766e95bd41b788`.
  The optional Dockerfile checks this executable hash during build.
- The release checksums were verified against their GPG detached signature
  using primary key `66D15FDD87287219C8E15478D200CD702853E6D0`,
  signing subkey `E617DCD4065C2AFC0B2CF7A7BA8BC08C0F691F94`.
  The primary fingerprint is published in the
  [pinned official installation instructions](https://github.com/openbao/openbao/blob/v2.7.2/website/content/docs/install.mdx).
  This verifies a signed upstream binary, not an invented container attestation.
- [Release assets](https://github.com/openbao/openbao/releases/tag/v2.7.2)
  include signed checksum and SBOM artifacts.
  [Static-seal configuration](https://github.com/openbao/openbao/blob/v2.7.2/website/content/docs/configuration/seal/static.mdx)
  defines the native raw-key format.
- OpenBao is MPL-2.0. The optional image retains the unmodified upstream
  license at `/usr/share/licenses/openbao/LICENSE`, upstream README and signed
  SBOM (losslessly compressed) at `/usr/share/doc/openbao/`; its exact corresponding
  source is the pinned official release above. No modified OpenBao source or
  automatic upstream update is included.

Run the disposable proof using the locked development environment:

```bash
PYTHONPATH=src python scripts/ci/credential_safe_smoke.py
pytest -q tests/test_credential_safe.py tests/test_credential_safe_ui.py tests/test_safe_backend_bootstrap.py
# Optional fresh maintenance/restart/interruption proof using a pinned local executable:
BLOCKWART_TEST_BAO_BINARY=/protected/test/bao pytest -q tests/test_safe_maintenance.py
```

The smoke builds the actual optional image, initializes synthetic Raft storage,
checks real restart persistence, concurrent CAS, version reads, CAS tombstone
and recovery, denial of destructive backend calls, non-root broker auth,
missing-key failure and automatic recovery after restoring the same key. It
removes its own containers, image and synthetic state. Full CI runs it without
a live instance or repository secrets. This is development proof, not a
deployment or live acceptance.

Backup/restore implementation, a general upgrade program, rotation and target
provisioning, direct tool injection, HA, additional roles, reauthentication
and break-glass workflows remain outside V1.
