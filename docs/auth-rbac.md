# Authentication and object authorization

Blockwart authenticates every catalog read and authorizes it against current
object grants. Catalog and grant mutations use the same object-scoped command
and policy layer across the browser UI, API v1, and MCP. There is no global
browser write bypass.

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

Every service token has a server-stored audience, `api` or `mcp`.
It is selected only by protected issuance/rotation operations and is included in
credential metadata, never inferred from a client header. Existing tokens
migrate to `api`. The audience currently provides trusted provenance for
comment appends: API comments require `api`, MCP comments require `mcp`; it
does not add object permissions or bypass the bearer-token policy.

The identity endpoint is:

```text
GET /api/v1/auth/me
Authorization: Bearer <service-account token>
```

It returns only the authenticated principal's stable identity fields. The same
bearer credential is required by `/api/objects`, `/api/agent`, and `/api/v1`.

The browser identity page is available at `/auth`. Login uses a one-time,
server-stored pre-authentication challenge. Authenticated browser sessions are
opaque, revocable, time-limited, `Secure`, `HttpOnly`, and `SameSite=Strict`; state
changes require the session-bound CSRF value.

## Role axes

Blockwart stores three independent authorization axes on a principal:

| Axis | Stored as | Meaning |
|---|---|---|
| identity administration | `platform_role = admin` | identity and credential administration |
| global catalog authority | `catalog_role = catalog_owner` | all six permissions on every object |
| scoped catalog access | `object_grants` rows | one role at one object, `self` or `subtree` |

The axes never imply each other. A platform admin has no catalog permission
unless it also holds grants or the catalog-owner role, and a catalog owner
cannot administer identities or credentials. Both role columns are nullable and
constrained to their single allowed value, and both are guarded by SQLite
triggers plus service checks that refuse to remove the last active holder.

## Platform administration

Identity administration is a separate authorization axis. A principal may
have the optional platform role `admin`, which permits user, service-account,
credential-metadata, and lifecycle administration. It never grants catalog
`discover`, `read`, `write`, `manage_access`, or `delete`; those permissions
still come only from explicit object grants or the global catalog-owner role.

The admin-only browser UI lives at `/admin/principals`. It provides principal
search, lifecycle changes, direct and effective assignment views, password
reset, and service-token lifecycle. Reverse assignment rows are limited to
objects on which the acting admin currently has `manage_access`; hidden object
IDs, labels, and counts are not released. Owner-grant changes still require an
effective Owner grant and use the shared object ETag, last-owner, and
self-lockout checks.

Principal search uses opaque, filter-bound keyset cursors and exposes no total
count. The browser keeps the active filters while following the exhaustive
next-page link; REST and the read-only MCP wrapper forward the same cursor.

Principal changes use their own positive revision and strong ETag. A service
guard plus SQLite triggers prevents demotion, deactivation, or deletion of the
last active platform admin, including concurrent writers. Credential-creating
browser actions require the current human admin password. REST may use an
explicit admin service-account bearer credential as the equivalent protected
machine authorization. New tokens are returned once with `no-store`; MCP has
no password or token-value operation.

Protected CLI password, token, and lifecycle mutations advance the same
principal revision as UI and REST mutations, so previously issued principal
ETags become stale across channels.

Password work is bounded before Argon2 verification by configurable global,
per-source, and per-account-fingerprint limits plus a per-process concurrency
cap. Challenge issuance has separate global and per-source limits so anonymous
GET requests cannot grow the challenge table without bound. Failed service-token
authentication is separately bounded in shared SQLite fixed-window buckets so API
and MCP processes observe the same global, source, and token-fingerprint limits.

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

## Global catalog owner

An active principal with `catalog_role = catalog_owner` holds `discover`,
`read`, `write`, `create_child`, `manage_access`, and `delete` on every object
that currently exists, including objects created after the role was assigned.

This is computed centrally in the policy service on every request. No wildcard
grant, per-object grant, sentinel grant ID, or negative grant ID is ever
materialized: the effective policy snapshot carries the authority as typed
global provenance, while `grants_for()` keeps meaning real object grants only.
Scoped grants stay additive and their direct and effective projections are
unchanged. The provenance is part of the policy fingerprint, so assigning or
removing the role immediately invalidates existing cursors and principal-scoped
read state. An inactive catalog owner receives nothing.

Owner-coverage computation treats any active catalog owner as covering every
current object without creating a grant. Exclusion-based coverage checks used
for deactivation and deletion ignore the excluded principal and then fall back
to the remaining active catalog owners and scoped Owner grants.

Normal catalog-role assignment and removal are performed through one dedicated
application command and its REST/UI surfaces, described below. The role is never
part of the generic principal create or update mutation. Disconnected-root
creation is a separate catalog write available to already-authorized active
catalog owners, described below; it never assigns or removes any role. Until a
catalog owner exists, the protected local commands below remain the only
first-owner and recovery path.

## Catalog-owner administration

The dedicated catalog-role command assigns or removes `catalog_owner` on an
existing principal. It is separate from generic principal create/update, which
never touches `catalog_role`.

Authorization requires the actor to be simultaneously active and both a platform
admin and a catalog owner; neither axis alone is sufficient. Human actors must
reauthenticate with their current password, using the same safe failure-audit
pattern as platform-admin reauthentication. Service-account actors are always
denied this human control-plane action, including over REST where bearer
credentials authenticate service accounts.

The command requires the current principal ETag through `If-Match` (or the
hidden UI field); a missing or stale precondition uses the established 428/412
behavior. An unchanged requested role is an idempotent no-op: no revision bump
and no success audit event. A real change advances the target principal revision
exactly once and writes a redacted structured `catalog_owner_role_changed`
security event with actor, target, before/after role, channel, request ID, and
resulting revision. Passwords, tokens, raw request bodies, and secrets are never
recorded.

Removing or deactivating the last active catalog owner remains impossible at both
service and SQLite-trigger levels, including concurrent writers. The command
cannot bypass the strict zero-owner bootstrap contract: if no active catalog
owner exists, normal REST/UI administration cannot mint the first one, because
the dual-role gate cannot be satisfied.

The role is never assigned to an inactive principal, because such a principal
could later be activated through the generic principal update and gain global
catalog permissions without the dual-role gate or its audit event. Assigning
`catalog_owner` to an inactive target is rejected with the stable principal
conflict, and — for legacy rows or raw writes that already hold that state —
generic principal update refuses to activate a principal that currently carries
`catalog_owner`. The safe sequence is to remove the role through catalog-role
administration first, activate the principal, and reassign the role under the
dual-role gate. Generic principal update still never accepts a password or a
catalog-role field; its `principal_updated` security event now also records the
target's non-secret `catalog_role` so the relevant state is visible in the audit
trail.

A dual-role authorization denial on either the REST or the UI path returns `403`
and writes exactly one redacted `catalog_owner_admin_authorization` denial event
carrying the actor, the channel, the request ID and a single stable reason. It
mirrors the failed platform-admin reauthentication evidence and never names the
target, the missing role axis, or any credential, so a requester cannot learn
which of the two required roles was absent.

REST exposes the action at `POST /api/v1/admin/principals/{principal_id}/catalog-role`
with the `CatalogRoleMutationIn` body and the same `If-Match` header and stable
error envelopes as principal administration. Unlike the other `/api/v1/admin`
routes, which use service-account bearer tokens, this one dedicated JSON
mutation authenticates an active human browser identity through the opaque
`blockwart_identity_session` cookie and requires a bounded double-submit
`X-CSRF-Token` header matched against the secure `blockwart_identity_csrf` cookie
and verified against the browser session. A missing or invalid browser session
returns a JSON `401`; a missing or mismatched CSRF header returns a JSON `403`
with a redacted `browser_write_csrf` denial event. Bearer authentication is never
accepted as a fallback, so service-account and MCP actors cannot mutate the
catalog role. Every other `/api/v1/admin` read and write route keeps its existing
bearer-token contract. The browser UI adds a dedicated **Catalog role** panel on
the principal detail page, separate from the generic principal edit form, and
shows the current catalog role in the principal list and detail views without
implying platform-admin equivalence. The canonical principal, admin summary, and
API schemas carry the nullable `catalog_role`, and the admin principal detail
exposes the typed `global_authorities` effective-permission explanation for an
active catalog owner.

MCP may only read/display the catalog role and its effective authority through the
existing read-only `list_admin_principals` and `get_admin_principal` projections.
No MCP tool, argument, route, or generic update field assigns or removes the
catalog role.

### Credential administration of a catalog owner

Issuing or rotating a service token for a catalog-owner principal, or resetting a
human catalog owner's password, takes over that principal's global catalog
authority, so those operations are gated exactly like catalog-role
administration: the actor must be at that moment both an active platform admin
and an active catalog owner, and must pass the human-only reauthentication path.
The generic platform-admin service-account exemption on the API channel never
applies to such a target, so a platform-admin-only service account can neither
mint nor rotate an API or MCP token for a catalog-owner service principal nor
reset a human catalog owner's password. Because the `/api/v1/admin` credential
routes are bearer-only, catalog-owner credential administration is reachable
through the browser UI, where a human dual-role administrator reauthenticates.

The target's catalog role is read from current database state — never from the
request body or the actor's access projection — and covers active and inactive
targets and every token audience. Denial happens before the idempotency
reservation, the revision claim, any token issuance or rotation, any password
mutation, session revocation, and any success audit evidence, so a denied attempt
leaves credentials, revisions, idempotency records, sessions, and the audit trail
untouched apart from the denial event. Targets without the catalog-owner role
keep the established platform-admin contract, including one-time secret
disclosure, ETag preconditions, idempotent replay, and stable error envelopes.

## Catalog-owner root creation

An active catalog owner may create a new disconnected top-level catalog root
through the dedicated `create_root` application command, exposed on REST
(`POST /api/v1/roots`), the browser UI (typed **Create root** form), and MCP
(`blockwart.create_root`). This is a catalog write, not a role mutation, and it
is the only creation path that does not require a placement parent.

Authorization is resolved from current database state inside the command
transaction: the actor must be active and hold `catalog_owner`. Platform-admin
alone is denied, and the catalog owner needs no platform-admin role for this
operation. The trusted channel must also match the credential: browser UI actors
use their browser session, REST writes require an `api`-audience service token,
and MCP writes require an `mcp`-audience service token.

The command reuses the canonical object schema, reference, provenance,
ACL-shaped-key rejection, secret scanning, normalization, idempotency, and
revision semantics of object creation. It atomically creates the root and
exactly one real direct `Owner/self` grant for the creating principal in the
same transaction; a failed object, grant, or audit write rolls the whole
transaction back, and idempotent replay never duplicates either. The root has
no canonical placement parent and no synthetic relationship. Global authority
is still never represented by a wildcard, sentinel, or subtree grant. The
generic object create/update/import paths expose no root-creation bypass.

Every creation emits the normal immutable `create_root` audit event with the
trusted actor, channel, request ID, and revisions, and never includes secrets
or raw credentials.

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

Owner coverage is evaluated over the affected canonical placement set, plus the
whole catalog when the affected principal is an active catalog owner. A
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
static assets, OpenAPI documentation, and `/auth` remain outside catalog-read
authorization.

Every object has a positive monotone `revision`. Object, relationship, and
grant mutations advance the affected revision. The same effective-owner guard
applies when a principal is deactivated or a placement edge is removed, so an
existing object or descendant cannot be orphaned through a lifecycle shortcut.

Object comments follow the same policy boundary: `read` reveals the timeline
and the five-entry `recent_comments` projection, while `write` permits an
append. Appends do not use optimistic `If-Match`, because they cannot overwrite
another entry, but they are idempotent and advance the object revision.
Discover-only stubs never release comments. See `object-comments.md`.

The focused Project overview and chronology apply this same boundary before
filtering, counting, ordering, or reading activity. A Project with only
`discover` is a strict stub only on direct generic reads; it does not appear in
the focused overview and reveals no chronology, last-activity timestamp,
relationship, or filter match. `write` authorizes both focused canonical-field
edits and chronology appends. UI sessions and `api`/`mcp` audience tokens retain
their existing trusted-channel requirements.

## Bootstrap and credential operations

Run the schema upgrade before any auth command:

```bash
blockwart-db upgrade
```

Create the first human platform admin, its explicit Owner grant, and the global
catalog owner atomically:

```bash
blockwart-auth bootstrap-owner \
  --login kai \
  --display-name Kai \
  --object-id fabrik \
  --scope subtree \
  --catalog-owner
```

The command prompts on a TTY. Automation may use `--password-stdin`; never put
a password in command-line arguments. Bootstrap is idempotent only when the
complete requested principal, password credential, catalog-role choice, and
Owner grant already exist. Any partial or conflicting identity state fails
closed.

`--catalog-owner` is an explicit choice, never an implicit migration
promotion. Omitting it produces a valid catalog whose readiness and startup
checks fail with `catalog_owner_missing` until a catalog owner is selected.

Repeat `--object-id` for each disconnected canonical component. Creation of the
principal, password credential, and all requested Owner grants is one transaction;
the command rolls everything back unless the complete catalog satisfies the same
Owner-coverage invariant used by startup and readiness.

An existing installation is never promoted implicitly by a migration. Promote
the exact existing human explicitly through the protected CLI before enabling
the admin UI:

```bash
blockwart-auth promote-admin --login kai
```

The operation is idempotent and writes a redacted security event.

The same rule applies to the global catalog owner. An upgraded installation
reaches `catalog_owner_missing` until one existing active human or service
principal is selected locally:

```bash
blockwart-auth bootstrap-catalog-owner --login kai
```

The command is a bootstrap and recovery path, not a routine way to add owners:
it succeeds only while there is no active catalog owner, is idempotent for the
principal that already holds the role, takes no secret in arguments, prints and
logs no secret, advances the principal revision on change, writes a redacted
`catalog_owner_selected` security event with a protected-CLI actor, and leaves
every existing object grant untouched.

Neither bootstrap path can remove the last active catalog owner afterwards:
demotion, deactivation, and deletion fail with the repository's normal safe
conflict, and concurrent writers hit the same invariant in SQLite triggers.

Alembic revision `20260806_0015` only adds the nullable, indexed
`principals.catalog_role` column, its value constraint, and the two guard
triggers. It promotes nobody and creates no grant. Because SQLite requires a
batch table rebuild for the new constraint, the migration also recreates the
existing last-platform-admin triggers verbatim. Downgrading past it drops the
column and therefore every catalog-owner assignment while leaving principals,
credentials, and object grants intact; reselect an owner after upgrading again.

Service-account tokens use a protected output file:

```bash
blockwart-auth create-service-account \
  --login inventory-agent \
  --display-name "Inventory Agent"

blockwart-auth issue-token \
  --login inventory-agent \
  --name primary \
  --audience api \
  --output-file /protected/runtime/blockwart-api-token
```

The output path must not already exist. The token is never written to stdout.
Use `rotate-token`, `revoke-token`, `set-password`, and
`deactivate-principal` for their corresponding lifecycle operations.
Use `--audience mcp` only for the token installed into an approved MCP runtime.
Rotation can explicitly change the audience of an existing named token; if an
API or CLI rotation omits the audience, the current value is preserved.

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
Comment creation is intentionally narrower: it records the immutable comment
ID, actor, trusted channel, request ID, and new revision, but never copies the
comment body or a before/after document into audit or idempotency storage.
Invalid authentication is recorded in the security stream. Concealed object
denials intentionally use stable not-found responses and do not include object
details.

## Control-plane boundary

Identity sessions do not by themselves enable writes: UI, REST, and MCP commands
also require the matching object permission. Schema settings are read-only over
HTTP, and normal object creation requires an authorized placement parent through
the shared `create_child` command. New top-level roots are created either as an
explicit seed or import control-plane operation or by an active catalog owner
through the dedicated `create_root` command described above. Production
identity bootstrap, token injection, and runtime rollout still require their
dedicated approval.
