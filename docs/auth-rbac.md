# Authentication and object authorization

Blockwart authenticates every catalog read and authorizes it against current
object grants. Catalog and grant mutations use the same object-scoped command
and policy layer across the browser UI, API v1, and MCP. The legacy global UI
admin gate remains only as an isolated compatibility surface.

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

It returns only the authenticated principal's stable identity fields. The same
bearer credential is required by `/api/objects`, `/api/agent`, and `/api/v1`.

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

`discover` exposes only the safe stub projection. `read` permits the full
object projection. Grants are additive, do not imply access to parents or
siblings, and never live inside `data_json`.

`subtree` follows only the canonical placement graph:

- `host -> system`
- `host -> service`
- `system -> service`

Other relationship types do not propagate grants. Effective authorization is
calculated from the current graph in one recursive database query, so
reparenting changes access without a stale application cache.

## Grant management

An actor needs effective `manage_access` on the anchor object to list, create,
update, or revoke its direct grants. Owner grants have an additional invariant:
only an actor with effective `owner` on that object may create, change, or
revoke them. Role names are not accepted as proof; both checks resolve the
actor's current grants from the database inside the command transaction.

The object UI's **Access control** panel, API v1, and MCP expose one shared
application service:

- direct grants are shown separately from effective permissions;
- effective entries group all additive direct and inherited grant sources by
  principal;
- principal search accepts 2..100 characters, returns at most 20 active
  identities, and exposes only ID, login, display name, type, and active state;
- subtree preview follows only canonical placement and returns the safe object
  ID, kind, label, and whether the anchor is direct;
- create, update, and revoke require the current strong object `ETag` through
  `If-Match` (or the equivalent hidden UI field).

Every actual grant change atomically advances the anchor revision and appends
one immutable object audit event with actor, target principal, channel,
request ID, old/new revision, and structured before/after grant state. An exact
duplicate create or unchanged update is a revision-preserving no-op and emits
no extra audit event.

Owner coverage is evaluated over the affected canonical placement set. A
revoke, role downgrade, scope shrink, principal deactivation, placement
change, or delete that would leave any existing affected object without an
active effective Owner fails closed. A principal also cannot use a grant
change to remove its own effective `manage_access` on the anchor; another
authorized Owner can perform a deliberate transfer. Successful revocation is
visible to the next request because policy decisions are rebuilt from current
database state and no authorization cache is used.

ACL-shaped keys such as `acl`, `access_grants`, or `permissions` are rejected
recursively from catalog write and import data. Object grants can be changed
only through the dedicated grant-management commands and never through
`data_json`.

## Authorized read projection

Human UI reads require a valid browser identity session. Machine reads under
`/api/objects`, `/api/agent`, and `/api/v1` require a valid service-account
bearer token. UI, REST, Agent API, and MCP apply the same effective policy:

- no `discover`: omit the object from lists, search, topology,
  relationships, counts, and MCP; direct access returns the same `404` as a
  missing object;
- `discover` without `read`: return only `visibility`, stable ID, kind,
  display label, released placement path/state, and the principal's own
  capabilities;
- `read`: return the existing detail projection and the object's released
  audit history.

Placement `hosts` edges are visible only when both endpoints are discoverable.
Other relationship types require `read` on both endpoints. Detail filters such
as lifecycle, health, IP, endpoint, provenance, or freshness never evaluate
discover-only stubs; text search on a stub is restricted to ID, kind, and
label. Counts and pagination are computed after authorization. Kind counts
include discoverable stubs because kind is part of the released stub
projection; detail-derived counts such as health include readable objects
only. Opaque cursors are bound to both the principal and the exact effective
policy, so they cannot be reused after a grant change or by another identity.

Released placement paths stop at the first ancestor without `discover`.
Inherited IP addresses and hostnames are stricter: inheritance requires
`read` on every traversed ancestor and stops at the first unreadable one.

Principal-scoped UI and API responses use `Cache-Control: private, no-store`,
`Pragma: no-cache`, and `Vary: Authorization, Cookie`. Health/readiness,
static assets, OpenAPI documentation, `/auth`, and the separately protected
legacy `/admin` flow remain outside catalog-read authorization.

Every object has a positive monotone `revision`. Object, relationship, and
grant mutations advance the affected revision. The same effective-owner guard
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
actor principal, channel, request ID, old/new revision, and structured change.
Invalid authentication is recorded in the security stream. Concealed object
denials intentionally use stable not-found responses and do not include object
details.

## Transition contract

The legacy `BLOCKWART_ADMIN_TOKEN` mechanism remains a compatibility bypass
for schema settings and unplaced root creation until a dedicated migration
removes it. It never authorizes grant management. Identity sessions do not by
themselves enable writes: UI, REST, and MCP commands also require the matching
object permission. Production identity bootstrap, token injection, and runtime
rollout still require their dedicated approval.
