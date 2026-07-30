# Authentication and object authorization

Blockwart has a dormant authentication and object-authorization foundation. It
does not yet replace the legacy global UI admin gate, authorize catalog reads,
or expose catalog mutation APIs. Those integrations are delivered separately
so that a partially migrated deployment stays fail-closed.

## Principals and credentials

Two principal types are stored:

- `human`: local interactive identity with an Argon2id password and revocable
  opaque browser sessions
- `service_account`: non-interactive identity with named, revocable opaque
  bearer tokens

Passwords, browser session values, login challenges, CSRF values, and service
tokens are never stored in plaintext. Service tokens are returned once, and
the CLI writes them only to a newly created mode `0600` file. Rotating a
password revokes all browser sessions for that principal. Deactivating a
principal revokes all of its active sessions and service tokens.

The identity endpoint is:

```text
GET /api/v1/auth/me
Authorization: Bearer <service-account token>
```

It returns only the authenticated principal's stable identity fields. It does
not grant access to existing catalog endpoints yet.

The browser identity page is available at `/auth`. Login uses a one-time,
server-stored pre-authentication challenge. Authenticated browser sessions are
opaque, revocable, time-limited, `HttpOnly`, and `SameSite=Strict`; state
changes require the session-bound CSRF value.

Password work is bounded before Argon2 verification by configurable global,
per-source, and per-account-fingerprint limits plus a per-process concurrency
cap. Challenge issuance has separate global and per-source limits so anonymous
GET requests cannot grow the challenge table without bound. The deployment
uses one application process by default; multi-process deployments must size
the documented limits per worker or add an external shared limiter.

## Roles and scope

An object grant assigns one role to one principal at one object with either
`self` or `subtree` scope:

| Role | Permissions |
|---|---|
| `discoverer` | `discover` |
| `viewer` | `discover`, `read` |
| `editor` | `discover`, `read`, `write` |
| `creator` | `discover`, `read`, `create_child` |
| `access_manager` | `discover`, `read`, `manage_access` |
| `owner` | all permissions, including `delete` |

`discover` exposes only a future safe stub projection. `read` permits the
future full object projection. Grants are additive, do not imply access to
parents or siblings, and never live inside `data_json`.

`subtree` follows only the canonical placement graph:

- `host -> system`
- `host -> service`
- `system -> service`

Other relationship types do not propagate grants. Effective authorization is
calculated from the current graph in one recursive database query, so
reparenting changes access without a stale application cache.

Every object has a positive monotone `revision`. Object and relationship
mutations advance the affected revision. Grant creation and revocation advance
the anchor object's revision and append an object audit event. A last active
subtree owner cannot be removed accidentally. The same effective-owner guard
applies when a principal is deactivated or a placement edge is removed, so an
existing object or descendant cannot be orphaned through a lifecycle shortcut.

## Bootstrap and credential operations

Run the schema upgrade before any auth command:

```bash
blockwart-db upgrade
```

Create the first human and its Owner grant atomically:

```bash
blockwart-auth bootstrap-owner \
  --login kai \
  --display-name Kai \
  --object-id fabrik \
  --scope subtree
```

The command prompts on a TTY. Automation may use `--password-stdin`; never put
a password in command-line arguments. Bootstrap is idempotent only when the
complete requested principal, password credential, and Owner grant already
exist. Any partial or conflicting identity state fails closed.

Service-account tokens use a protected output file:

```bash
blockwart-auth create-service-account \
  --login inventory-agent \
  --display-name "Inventory Agent"

blockwart-auth issue-token \
  --login inventory-agent \
  --name primary \
  --output-file /protected/runtime/blockwart-api-token
```

The output path must not already exist. The token is never written to stdout.
Use `rotate-token`, `revoke-token`, `set-password`, and
`deactivate-principal` for their corresponding lifecycle operations.

## Audit boundaries

Interactive login success/failure, authentication denials, credential
rotation/revocation, and principal deactivation go to the append-only
security-event stream. Successful service-token use updates only its
`last_used_at` timestamp instead of creating one event per API call. Events
contain stable event codes, channel, principal where known, request ID, and
redacted structured details. User-supplied login names, passwords, tokens,
cookies, and hashes are not recorded.

Security events are immutable while retained. Periodic login-path maintenance
removes events older than the configured retention and caps the remaining row
count; repeated throttle denials are aggregated to at most one event per
limiter bucket and window.

Object and grant mutations use the existing object audit stream and record the
actor principal, channel, request ID, old/new revision, and structured
change. Authorization denials belong to the security stream once the
read/write integrations are enabled.

## Transition contract

The legacy `BLOCKWART_ADMIN_TOKEN` mechanism remains the only gate for current
UI catalog mutations until the migration rollout is completed. New identities
and grants do not enable those routes. Existing REST and MCP catalog
operations also remain read-only and are not yet filtered by object grants.
Do not bootstrap production identities or inject tokens before the dedicated
authorization integration and rollout have been reviewed and approved.
