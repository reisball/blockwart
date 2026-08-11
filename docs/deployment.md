# Deployment Readiness

Blockwart is prepared for controlled deployment, but this repository does not deploy or register a
persistent service by itself.

## Approval Gate

Before a real deployment, decide and document:

- target host or container
- localhost bind port and reverse-proxy address
- backup location and retention
- HTTPS certificate source, HSTS policy, and exact trusted-proxy network
- fully covering Owner anchors already bootstrapped in the mounted database
- whether agents reach Blockwart through REST, MCP, or both
- credential reference name for runtime configuration

Do not bind Blockwart to LAN or public networks until those decisions are made.

## Local Package Run

Install the package:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
```

Initialize a database and import the pilot seed:

```bash
BLOCKWART_DATABASE_URL=sqlite:////tmp/blockwart.sqlite3 \
  blockwart-seed --create-schema --seed seeds/pilot_objects.yaml
```

Bootstrap one or more Owner anchors before the first start. Repeat `--object-id`
for every disconnected canonical component and supply the password through a TTY
or `--password-stdin`:

```bash
BLOCKWART_DATABASE_URL=sqlite:////tmp/blockwart.sqlite3 \
  blockwart-auth bootstrap-owner --login kai --display-name Kai \
  --object-id COMPONENT_ROOT_ID --scope subtree --catalog-owner
```

`bootstrap-owner` makes that protected first human a platform admin while
scoped catalog access still comes only from the listed Owner anchors.
`--catalog-owner` additionally assigns the independent global catalog-owner
role in the same transaction; without it, startup and readiness fail with
`catalog_owner_missing`. For an existing database upgraded from an earlier
release, explicitly run `blockwart-auth promote-admin --login kai` and
`blockwart-auth bootstrap-catalog-owner --login kai`; migrations `0012` and
`0015` never guess an admin or catalog-owner identity.

Then run the migration/readiness-gated launcher:

```bash
BLOCKWART_DATABASE_URL=sqlite:////tmp/blockwart.sqlite3 \
  blockwart-start
```

Direct HTTP remains useful for local health probes, but browsers will not send Blockwart's
unconditionally `Secure` identity cookies over it. Browser use therefore requires the HTTPS
reverse-proxy contract below.

## Container Example

The example compose file binds only to localhost:

```bash
BLOCKWART_BUILD_REVISION="$(git rev-parse HEAD)" \
  docker compose -f compose.example.yaml build
docker compose -f compose.example.yaml run --rm blockwart \
  blockwart-seed --create-schema --seed seeds/pilot_objects.yaml
docker compose -f compose.example.yaml run --rm blockwart \
  blockwart-auth bootstrap-owner --login kai --display-name Kai \
  --object-id COMPONENT_ROOT_ID --scope subtree --catalog-owner
docker compose -f compose.example.yaml up
```

This is an example only. It binds the published port to `127.0.0.1` and does not set up TLS,
backups, monitoring, or service registration.

The image command is `blockwart-start`. It runs the packaged Alembic upgrade against the effective
`BLOCKWART_DATABASE_URL`, verifies the packaged head, full active effective Owner coverage, and an
active global catalog owner, and only then replaces itself with Uvicorn with Uvicorn's implicit
proxy-header processing disabled. Migration errors use the redacted
`startup_error=database_migration_failed`; authorization-invariant failures use
`startup_error=owner_catalog_empty`, `startup_error=owner_coverage_incomplete`, or
`startup_error=catalog_owner_missing`. The last code means the catalog is fully owned but no
active global catalog owner has been selected yet; see `auth-rbac.md` for the explicit
`--catalog-owner` bootstrap choice and the `bootstrap-catalog-owner` recovery command. Nothing
promotes an existing principal automatically.

The image healthcheck calls `/api/health/ready`. An unhealthy result therefore means the process
may still be alive but must not receive normal traffic.

## Liveness And Readiness

The health endpoints have separate operational meanings:

- `GET /api/health` and `GET /api/health/live` return `200` when the application process can
  answer HTTP. They deliberately do not touch the database.
- `GET /api/health/ready` returns `200` only when `SELECT 1` succeeds, the current Alembic revision
  exactly matches the packaged head, SQLite has the expected connection settings, every object in
  a nonempty catalog has an active effective Owner, at least one active catalog owner exists, and a
  rolled-back write against the Alembic revision succeeds without changing data. The probe first
  acquires a write lock, changes the revision only inside that transaction, and rolls it back.

Readiness failures return `503` with a stable `error_code`, check statuses, package version, build
revision, and current schema revision where available. The public response never includes database
paths, SQL text, driver exceptions, or credentials. Expected codes are
`database_missing`, `database_unavailable`, `schema_revision_mismatch`,
`sqlite_configuration_invalid`, `database_not_writable`, `owner_catalog_empty`,
`owner_coverage_incomplete`, and `catalog_owner_missing`. Scoped Owner coverage is evaluated
before the catalog-owner gate, so a partially owned catalog still reports the precise
`owner_coverage_incomplete` cause.

Example:

```bash
curl -fsS http://127.0.0.1:8000/api/health/live
curl -fsS http://127.0.0.1:8000/api/health/ready
```

These endpoints provide probes, not a monitoring system. Alerting, dashboards, and external
service registration remain deployment concerns.

The default SQLite lock wait is five seconds. The image's HTTP probe waits seven seconds and
Docker allows eight seconds for the complete healthcheck, so readiness can return its stable
`200`/`503` result before either client deadline expires.

## HTTPS Reverse Proxy Contract

Production compose publishes Blockwart only on `127.0.0.1:8000`. The approved reverse proxy is
the sole network entry point: it terminates HTTPS with a validated certificate, forwards to that
loopback address, and adds an HSTS response such as
`Strict-Transport-Security: max-age=31536000; includeSubDomains` only after the HTTPS domain and
subdomains are verified. Blockwart identity, login-challenge, CSRF, and cookie-clearing responses
always carry `Secure`; there is no configuration downgrade for direct HTTP browser sessions.

Blockwart does not infer trust from `Forwarded`, `X-Forwarded-Proto`, or arbitrary
`X-Forwarded-*` headers. For service-token source limiting, `X-Forwarded-For` is used only when the
direct transport peer belongs to `BLOCKWART_AUTH_TRUSTED_PROXY_CIDRS`, and the header contains
exactly one valid IP address in exactly one header field. The trusted proxy must overwrite, never
append, `X-Forwarded-For`. Configure the smallest exact proxy IP/CIDR set; duplicate, malformed, or
chained values are ignored in favor of the direct peer. The packaged launcher disables Uvicorn's
own proxy-header rewriting so this explicit Blockwart allowlist is the sole source-attribution
policy.

## Authorization Rollout Checklist

Perform the authorization transition against a restored candidate before changing live traffic:

1. Inventory and remove the retired `BLOCKWART_ADMIN_TOKEN`,
   `BLOCKWART_ADMIN_SESSION_TTL_SECONDS`, `BLOCKWART_ADMIN_COOKIE_SECURE`, and
   `BLOCKWART_AUTH_COOKIE_SECURE` settings from the deployment environment and secret injection.
2. Upgrade the candidate, inventory every disconnected catalog component privately, and run one
   atomic `bootstrap-owner` invocation with all required anchors and the explicit `--catalog-owner`
   choice, or select the existing owner once with `bootstrap-catalog-owner`. Require readiness to
   report `authorization=ok` without exposing object identifiers.
3. Verify the public HTTPS certificate, HSTS response, localhost-only application bind, and
   `Secure`, `HttpOnly`, and `SameSite=Strict` attributes on identity responses.
4. Prove `/admin`, `/admin/unlock`, and `/admin/lock` are absent, schema HTTP POST is rejected, and
   a stale `blockwart_admin_session` cookie grants no access.
5. Run the approved anonymous, Viewer, Editor, and Owner role matrix through UI, API, and MCP;
   correlate the resulting safe responses, security events, and object audits by request ID.

Do not manufacture automatic grants to make a failed candidate ready. Correct the explicit anchor
set while the service is stopped, repeat the candidate proof, and preserve the failed copy for
diagnosis.

## Service-Token Limiter Incident And Recovery

Service-token failures return one uniform `401`; clients cannot use the response to distinguish a
missing, malformed, expired, revoked, unknown, or limited credential. The protected security-event
store emits at most one aggregate event for each global, source, or token-fingerprint bucket in a
window. Events contain only dimension, bounded count, channel, and correlation context. Bucket keys
are one-way digests, so neither the submitted token nor the raw network source is available there.
If the bounded bucket table must reclaim a still-active bucket, Blockwart saturates the global
window first. Authentication therefore fails closed until the next window instead of losing a
source or fingerprint threshold.

For an authentication-denial incident:

1. Preserve application/proxy logs and the database backup, then correlate only allowlisted request
   IDs and aggregate dimensions. Never add Authorization headers, cookies, token values, request
   bodies, SQL parameters, or exception tracebacks to diagnostics.
2. Confirm the direct peer and exact `BLOCKWART_AUTH_TRUSTED_PROXY_CIDRS` setting. A malformed,
   duplicate, chained, or untrusted forwarded address is intentionally ignored; the proxy must
   overwrite rather than append the field. Do not widen the allowlist to silence an event.
3. Check for expired/revoked credentials and expected client retry behavior. Rotate or revoke a
   suspected service token through `blockwart-auth`, update the protected runtime token file, and
   repeat the cross-channel authorization proof.
4. Let fixed-window buckets expire and bounded pruning remove them. Do not truncate the live table
   or raise thresholds during an active incident. Any deliberate threshold change is a reviewed
   configuration rollout followed by load and denial tests.
5. Treat sustained `503` responses or SQLite lock failures as an availability incident, not an
   authentication hint. Remove traffic, preserve evidence, verify database integrity and lock
   ownership, and use the matching verified backup/image recovery procedure below when needed.

## SQLite Migration And Rollback

Treat application code and its database revision as one release. Before updating the live image:

Revision `0013` deliberately keeps legacy Network rows without `data.network.category` readable
while rejecting every write to them. It does not classify or mutate those rows. Do not deploy that
transitional revision to production until the separately reviewed Network classification dry run,
mapping/apply plan, backup, and production acceptance are complete.

Revision `0014` creates the append-only object-comment timeline, migrates each
string `data.comment` losslessly as legacy plain text, and removes the old key.
Before rollout, inspect a restored candidate for invalid/non-string legacy
values, record object/comment/audit counts, and verify that object revisions
advance once while `updated_at` and audit counts remain unchanged. All existing
catalog rows also receive a unique internal instance ID; all existing service
tokens become `api` audience. Once any timeline row exists, downgrade
is intentionally refused; rollback requires the paired pre-`0014` backup and
matching image. See `object-comments.md`.

Revision `0016` is additive: it creates the normalized source snapshot, entry,
and many-to-many mapping tables and does not rewrite existing catalog objects,
provenance, relationships, grants, comments, or principals. After upgrading a
restored candidate, run the Markdown collector with `--record-coverage`, review
its digest and state counts, then query `/api/v1/source-coverage` using both an
ordinary service account and the explicit platform-admin `scope=all` view. The
collector is the only workspace filesystem trust boundary; application HTTP
and MCP workers need no OpenClaw workspace mount. The same `0015` -> `0016`
upgrade and `0016` -> `0015` downgrade contract applies to SQLite and
PostgreSQL: downgrade removes only the three source-coverage tables. The entry
and mapping integer keys retain native auto-increment/sequence behavior, while
the composite entry/snapshot foreign key prevents mappings from crossing
snapshot boundaries.

For a fresh Markdown import, bind the reviewed mapping directly to both the
dry-run and apply commands. The importer requires exact coverage of all Network
rows and rejects missing, unknown, or conflicting evidence before schema or
catalog writes:

```bash
blockwart-import-markdown \
  --tools /home/zoe/.openclaw/workspace/TOOLS.md \
  --references-root /home/zoe/.openclaw/workspace \
  --network-mapping seeds/pilot_network_mapping.yaml
```

Run the classification gate against a restored candidate database:

```bash
blockwart-db --database-url "$CANDIDATE_DATABASE_URL" \
  --mapping reviewed-network-mapping.yaml networks
```

The mapping is evidence, not an apply instruction. Review every JSON line and
require `blocked=0 diagnostics=0`. The command never writes; `--apply networks`
fails closed until the later reviewed import/apply slice implements the paired
transaction, owner-coverage proof, backup, and rollback evidence.

1. Record the current application commit and image ID.
2. Create a SQLite online backup outside `/opt/blockwart-data`.
3. Run `PRAGMA integrity_check` against the backup and record the catalog, relationship, and audit
   counts.
4. Keep the previous image under a release-specific rollback tag.
5. Start the new image and require `blockwart-db check`, `blockwart-db integrity`, and the normal
   application smoke tests.

For a service-interface data rollout, run `blockwart-db interfaces` against the
restored candidate first and review every diagnostic. `blockwart-db --apply
interfaces` is a separate explicit step; application startup never performs
that JSON normalization automatically. Re-run the dry run afterward and
require zero changes before switching live traffic.

Example host-side backup:

```bash
install -d -m 0750 /opt/blockwart-backups
sqlite3 /opt/blockwart-data/blockwart.sqlite3 \
  ".backup '/opt/blockwart-backups/blockwart-before-upgrade.sqlite3'"
sqlite3 /opt/blockwart-backups/blockwart-before-upgrade.sqlite3 \
  "PRAGMA integrity_check;"
```

Also run `blockwart-db upgrade` and `/api/health/ready` against a disposable restored copy before
depending on a backup. This proves that the backup is readable, migratable, and compatible with
the current image without mutating the live database.

For rollback, stop Blockwart first, preserve the failed database for diagnosis, restore the
verified pre-upgrade backup, select the matching previous image, and start the service again. Do
not run an automatic Alembic downgrade on live data. The `0011` downgrade drops only the transient
service-token failure-bucket table; the `0013` device/relationship foundation explicitly refuses a
downgrade because its two SQLite rebuilds require the matching pre-migration backup. Revision
`0014` likewise refuses downgrade while any comment exists, preventing silent timeline loss. Primary
recovery remains the matching verified pre-upgrade database plus pinned old image. Never supply a
retired global-bypass credential to an old image.

Downgrading `0016` drops only recorded coverage snapshots and mappings; it does
not change catalog objects or their `CatalogProvenance.source_ref`. Treat those
snapshots as reproducible audit inventory: export or re-collect them if their
history is needed after rollback.

An existing unversioned Blockwart database is adopted only if Alembic finds no model/schema
differences. The adopter stamps the known initial revision and then applies later revisions
normally. Unknown JSON fields are data and remain untouched. Missing tables, columns or indexes,
extra schema objects, an unknown revision, and unwritable targets all abort startup instead of
being guessed or repaired.

## Runtime Configuration

Required:

- `BLOCKWART_DATABASE_URL`

Optional:

- `BLOCKWART_ENV`
- `BLOCKWART_BUILD_REVISION` (default `unknown`; inject the deployed Git commit at image build)
- `BLOCKWART_SECRET_REFERENCE`
- `BLOCKWART_AUTH_SESSION_TTL_SECONDS` (default `3600`, allowed `300..86400`)
- `BLOCKWART_AUTH_LOGIN_CHALLENGE_TTL_SECONDS` (default `600`, allowed
  `60..3600`)
- `BLOCKWART_AUTH_LOGIN_RATE_WINDOW_SECONDS` (default `60`, allowed `10..3600`)
- `BLOCKWART_AUTH_LOGIN_SOURCE_ATTEMPT_LIMIT` (default `10`)
- `BLOCKWART_AUTH_LOGIN_ACCOUNT_ATTEMPT_LIMIT` (default `5`)
- `BLOCKWART_AUTH_LOGIN_GLOBAL_ATTEMPT_LIMIT` (default `60`)
- `BLOCKWART_AUTH_LOGIN_SOURCE_CHALLENGE_LIMIT` (default `30`)
- `BLOCKWART_AUTH_LOGIN_GLOBAL_CHALLENGE_LIMIT` (default `120`)
- `BLOCKWART_AUTH_PASSWORD_MAX_CONCURRENCY` (default `2`, allowed `1..16`)
- `BLOCKWART_AUTH_SECURITY_EVENT_RETENTION_DAYS` (default `90`)
- `BLOCKWART_AUTH_SECURITY_EVENT_MAX_ROWS` (default `100000`)
- `BLOCKWART_AUTH_SERVICE_TOKEN_RATE_WINDOW_SECONDS` (default `60`, allowed `10..3600`)
- `BLOCKWART_AUTH_SERVICE_TOKEN_GLOBAL_FAILURE_LIMIT` (default `300`)
- `BLOCKWART_AUTH_SERVICE_TOKEN_SOURCE_FAILURE_LIMIT` (default `30`)
- `BLOCKWART_AUTH_SERVICE_TOKEN_FINGERPRINT_FAILURE_LIMIT` (default `10`)
- `BLOCKWART_AUTH_SERVICE_TOKEN_FAILURE_BUCKET_MAX_ROWS` (default `10000`)
- `BLOCKWART_AUTH_SERVICE_TOKEN_FAILURE_BUCKET_PRUNE_INTERVAL_SECONDS` (default `60`)
- `BLOCKWART_AUTH_TRUSTED_PROXY_CIDRS` (default empty; comma-separated exact networks)
- `BLOCKWART_SQLITE_BUSY_TIMEOUT_MS` (default `5000`, allowed `100..60000`)
- `BLOCKWART_SQLITE_WAL_ENABLED` (default `true`)

Every SQLite connection enables foreign-key enforcement and applies the configured busy timeout.
The five-second default absorbs short UI/import lock contention while still failing a stuck writer
within a bounded interval. Persistent database files use WAL by default so readers can proceed
during a write transaction. In-memory SQLite retains its compatible `memory` journal mode.
Disabling WAL selects SQLite's `DELETE` journal for an explicitly incompatible filesystem, but
reduces concurrency and must be documented in the deployment configuration.

`BLOCKWART_SECRET_REFERENCE` is a reference label only. It must not contain a raw token, password,
private key, cookie, or `.env` body.

When `BLOCKWART_SCHEMA_OVERRIDES_PATH` is configured, Blockwart persists the versioned UI metadata
document through a temporary file in the same directory and atomically replaces the previous
document only after the written JSON and its complete structure validate. A malformed, unsupported,
or unreadable existing document fails diagnostically instead of silently falling back to defaults.
The configured directory must therefore be writable by the application process.

Catalog access now requires principals and object grants. `/auth` uses the
`BLOCKWART_AUTH_*` settings for browser sessions; service-account bearer
tokens authenticate and filter `/api/objects`, `/api/agent`, and `/api/v1`.
Production bootstrap, token injection, writable authorization, and deployment
rollout each require explicit approval. See `auth-rbac.md`.

## Agent Access

The stable object-authorized API lives under `/api/v1`; `/api/agent` remains a
read-only compatibility namespace. The local MCP wrapper uses v1 through
`BLOCKWART_API_BASE_URL` for both reads and writes. Deployment of the MCP
wrapper into OpenClaw/Gateway config is a separate approval step.

For an approved MCP deployment, inject a service-account token through the
protected `BLOCKWART_API_TOKEN_FILE`. `BLOCKWART_API_TOKEN` is an environment
fallback; configuring both sources is an error. The service account must have
the exact object grants needed by its tools. To enable comment writes, rotate
the exact named runtime token with `blockwart-auth rotate-token --audience mcp`
to a new protected output file, atomically replace the runtime secret file, and
verify `blockwart.list_comments` plus one explicitly approved idempotent
`blockwart.add_comment` smoke. Token rotation and runtime injection remain
separate deployment approvals; migration does not rotate live credentials.
