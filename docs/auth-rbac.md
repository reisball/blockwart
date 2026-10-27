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
migrate to `api`. Channel-sensitive commands require the matching audience:
REST uses `api`, MCP uses `mcp`, and the UI uses its authenticated browser
session. This includes disconnected-root creation, ownerless adoption,
comment/Project-chronology appends and Project-workspace writes/actions.
The audience supplies trusted origin, not object permissions; it never bypasses
current authorization. Read access alone does not prove write eligibility.

The identity endpoint is:

```text
GET /api/v1/auth/me
Authorization: Bearer <service-account token>
```

It returns only the authenticated principal's stable identity fields. The same
bearer credential is required by `/api/objects`, `/api/agent`, and `/api/v1`.

### Own direct-grant inventory

```text
GET /api/v1/auth/me/direct-grants?role=owner&limit=100&cursor=<opaque>
Authorization: Bearer <service-account token>
```

Any authenticated, active principal may list its **own** direct grants; no platform
role or catalog role is required and none is added. The principal comes only from the
credential — the route has no principal parameter and rejects a `principal_id` query
value. Unauthenticated, revoked, expired, or inactive callers receive the uniform
`401`. The existing admin principal endpoints and their RBAC are unchanged.

Each item is `{target_kind, target_id, role, scope}`: `target_kind` is `project` when the
granted object is a top-level `project`, otherwise `catalog_object`; `role` and `scope`
(`self` or `subtree`) are the grant's own values. Only direct grants are returned, never
inherited or effective access, and nothing about other principals, labels, or object
contents. Different roles or scopes on one target are separate items.

- `role` (optional) filters to exactly that role, so `role=owner` excludes viewer
  grants and every other role.
- `limit` is `1..200` (default `100`); out-of-range values are rejected.
- `cursor` is the opaque `next_cursor` of the previous page and is bound to the
  authenticated principal and `role` filter; malformed, oversized, or mismatched
  cursors return `400`.
- Order is `(target_id, role, scope)` ascending. On an unchanged grant set, following
  `next_cursor` until it is `null` returns every matching grant exactly once.
- Consistency under mutation: pages are keyset-based, not snapshots. A grant that exists
  for the whole traversal is never skipped or repeated; a grant created or revoked during
  it may or may not appear depending on whether its position is after the current cursor.
  Re-run the traversal to confirm a changed inventory.

The endpoint does not change grants or catalog data. Normal authentication
bookkeeping still applies. MCP exposes it as
`blockwart.list_own_direct_grants` (`role`, `limit`, `cursor`; no principal argument) with
identical semantics.

The browser identity page is available at `/auth`. Login uses a one-time,
server-stored pre-authentication challenge. Authenticated browser sessions are
opaque, revocable, time-limited, `Secure`, `HttpOnly`, `SameSite=Strict`, and
limited to `Path=/`; state changes require the session-bound CSRF value. Login
responses and the identity page remain `Cache-Control: no-store`.

Interactive human login offers the localized **Keep me signed in** / **Angemeldet
bleiben** checkbox. It is unchecked by default and affects no bearer-token,
service-account, REST, or MCP authentication. When unchecked, the server-side
session has the configured absolute lifetime of `300..3600` seconds (one hour
maximum), while both the identity and CSRF cookies are browser-session cookies
without `Max-Age` or `Expires`. When checked, the server chooses the dedicated
`BLOCKWART_AUTH_REMEMBER_SESSION_TTL_SECONDS` lifetime (30 days by default,
bounded to `86400..7776000` seconds) for the server-side session and the matching
`Max-Age` on both cookies. The browser never supplies a TTL or expiry. Missing,
unknown, manipulated, or duplicated checkbox values select the standard mode;
extra form fields cannot change persistence or cookie flags.

Both lifetimes are absolute and non-sliding. Authentication, CSRF verification,
and ordinary use do not change `expires_at` or reissue either cookie. Logout,
password rotation, principal deactivation, explicit revocation, and absolute
expiry invalidate standard and remembered sessions identically. A later visit
to `/auth` clears stale identity and CSRF cookies with the same security flags.

## Role axes

Blockwart stores independent authorization axes on a principal:

| Axis | Stored as | Meaning |
|---|---|---|
| identity administration | `platform_role = admin` | identity and credential administration |
| global catalog authority | `catalog_role = catalog_owner` | all permissions on every object |
| global catalog read-only | `catalog_role = catalog_viewer` | exactly `discover` and `read` on every object |
| global root-project creation | `project_creator = true` | create a top-level root of `kind = project` and nothing else, additively to the catalog role |
| legacy root-project creation | `catalog_role = project_creator` | still recognized for existing principals; use the independent capability for new assignments |
| scoped catalog access | `object_grants` rows | one role at one object, `self` or `subtree` |

The axes never imply each other. A platform admin has no catalog permission
unless it also holds grants or a catalog role, and a catalog owner, viewer, or
project creator cannot administer identities or credentials. Both role columns
are nullable and constrained to their closed allowed values, and `catalog_role`
holds exactly one of the three values or none. `project_creator` is a separate
boolean capability, so a viewer can also create its own Projects without losing
read access. The last-active-holder service
and database guards remain specific to platform admins and catalog owners;
viewers and project creators are freely revocable through their protected
admin commands.

## Platform administration

Identity administration is a separate authorization axis. A principal may
have the optional platform role `admin`, which permits user, service-account,
credential-metadata, and lifecycle administration. It never grants catalog
`discover`, `read`, `write`, `rename`, `manage_access`, or `delete`; those
permissions still come only from explicit object grants or an explicit global
catalog role.

The admin-only browser UI lives at `/admin/principals`. It provides principal
search, lifecycle changes, direct and effective assignment views, password
reset, and service-token lifecycle. Reverse assignment rows are limited to
objects on which the acting admin currently has `manage_access`; hidden object
IDs, labels, and counts are not released. Owner-grant changes still require an
effective Owner grant or Global Catalog Owner authority and use the shared object ETag, last-owner, and
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
| `renamer` | `discover`, `read`, `rename` |
| `editor` | `discover`, `read`, `write`, `rename` |
| `creator` | `discover`, `read`, `create_child` |
| `credential_reference_creator` | `discover`, `read`, `create_credential_reference` |
| `reference_content_reader` | `discover`, `read`, `read_reference_content` |
| `reference_content_editor` | `discover`, `read`, `write_reference_content` |
| `access_manager` | `discover`, `read`, `manage_access` |
| `owner` | all permissions, including `rename`, `create_credential_reference`, and `delete` |

`discover` exposes only the safe stub projection. `read` permits the
metadata projection; protected credential-reference content requires its own
capability as described below. Grants are additive, do not imply access to parents or
siblings, and never live inside `data_json`.

`rename` is a capability of its own rather than a part of `write`. It permits
exactly one change — the common top-level `label` — through the narrow rename
contract of [API v1](api-v1.md) and [MCP](mcp.md), and it permits nothing else:
it never allows a full-object update, a create, a delete, or a grant change.
`renamer` is the narrow role that delegates only that, while `editor`, `owner`,
and `catalog_owner` carry it alongside their existing authority. `viewer`,
`creator`, and `access_manager` deliberately do not receive it. Renaming
changes no other stored field, so it can never move an object in the placement
tree or widen anyone's access.

`create_credential_reference` is likewise a capability of its own. On a
service it permits exactly one command — creating a new `credential_reference`
object bound to one access method of that service, described in
[Service-bound credential-reference creation](#service-bound-credential-reference-creation)
— and nothing else: no update, rename, delete, relationship, or grant change of
the service, and no placement-child or root creation. `credential_reference_creator`
is the narrow role that delegates only that, while `owner` and `catalog_owner`
carry it through their existing all-permission sets. `editor`, `creator`,
`renamer`, `viewer`, `access_manager`, and `catalog_viewer` deliberately do not
receive it, so no existing assignment is widened.

### Credential-reference metadata and protected content

For `credential_reference`, the complete `data.reference` object, including
`reference.name`, `reference.path`, `reference.key`, and `reference.item_hint`,
is protected content. Provider, scope, usage associations, and handling rules
remain metadata governed by ordinary object access. Discovery remains a minimal
safe entry, without protected content. Reading a linked service/system or
following its credential-reference link grants no authority on the reference.

| Authority on the reference | Discover | Metadata read | Metadata write | Content read | Content write | Manage access |
|---|---|---|---|---|---|---|
| `discoverer` | yes | no | no | no | no | no |
| `viewer`, `catalog_viewer` | yes | yes | no | no | no | no |
| `editor` | yes | yes | yes | no | no | no |
| `reference_content_reader` | yes | yes | no | yes | no | no |
| `reference_content_editor` | yes | yes | no | no | yes | no |
| `access_manager` | yes | yes | no | no | no | yes |
| `owner`, `catalog_owner` | yes | yes | yes | yes | yes | yes |
| Platform admin without catalog authority | no | no | no | no | no | no |

The content roles are valid only on a `credential_reference` with `self` scope.
Creation, update, and role-aware scope preview reject another kind or `subtree`
with `invalid_reference_content_grant`. They are ordinary, independently
assignable additive object grants: assign both for content read **and** write,
and add `editor` separately if metadata write is also required. The content
editor deliberately does **not** imply content read, metadata write, rename,
creation, deletion, or access management. Other narrow roles (`renamer`,
`creator`, `credential_reference_creator`) keep their existing permissions and
receive neither content capability. An access manager may delegate/revoke these
non-Owner roles using the usual current-object ETag and audit path; changing an
Owner grant still follows the existing Owner restrictions. Revocation removes
only that grant's contribution: another grant or catalog-owner authority can
still supply the capability. Access inspection reports the effective content
permissions alongside their ordinary grant/global sources. A role-aware grant
preview reports that role's permissions and validated scope; it is not a write
or an access grant.

Metadata updates preserve protected content when omitted and reject unauthorized
content changes. Content-only editors can update protected fields without
metadata-write authority; all mutation responses, previews, and historical
payloads still obey the separate content-read requirement. In particular,
writing content does not authorize echoing its current or previous values.
An explicit blind replacement always advances the revision, even if its bytes
match; its preview always reports one opaque redacted replacement and the same
next-revision prediction. Hidden equality, branch presence, and locator shape
cannot affect its diff or digest. The command records blind replacement intent;
history and activity show one opaque content change even for equal values, not
actual leaf counts or equality. Authorized content readers retain canonical
snapshots and actual differences. Omitting content retains ordinary no-op
semantics. Content-only writers must preserve metadata with type-sensitive JSON
equality (`true`, `1`, and `1.0` are distinct).
Kind conversion into or out of a credential reference additionally requires
content-write authority as well as ordinary metadata write. When converting
away, omit `data.reference`; retaining a locator under another kind is rejected.
Historical reference snapshots remain content-protected after conversion.
Unclassified legacy events also remain protected when immutable object history
shows a former reference kind; activity resolves this for page candidates only.
Untyped snapshots, whole-object/data changes and dotted/JSON-pointer reference
paths obey the same boundary; aggregate values never reopen the protected branch.
Global Catalog Owner content authority applies even to nonmaterialized activity
policy snapshots. Typed-reference preservation is location-specific: unrelated
edits may retain an unchanged inaccessible target at its exact stored key/index,
but newly introduced or relocated values require target read authority. Explicit
blind content proposals always authorize their typed targets independently of
hidden stored values; omitted copied content does not reauthorize its targets.

**Compatibility:** migration `20261026_0031` expands only the database role
constraint and preserves every existing grant (IDs, roles, scopes, creators,
and timestamps), principal, and object. It assigns no new role. Existing
viewers, editors, and catalog viewers retain metadata access, but their former
implicit content visibility/update behavior becomes narrower: neither ordinary
`read` nor `write` carries a content capability. Explicitly delegate the new
roles for callers that still need content access. Existing Owners and catalog
owners retain full control through their all-permission mappings; catalog
owners do not become per-object Owner sources. No other existing role is widened.
Downgrade refuses if **either** new-role grant still exists, including grants
to inactive principals. Explicitly revoke them first (or restore the paired
pre-migration backup); downgrade never deletes grants or maps them to a broader
role automatically.

`subtree` follows only the canonical placement graph:

- `host -> system`
- `host -> service`
- `system -> service`

Other relationship types do not propagate grants. Effective authorization is
calculated from the current graph in one recursive database query, so
reparenting changes access without a stale application cache.

## Global catalog roles

An active principal with `catalog_role = catalog_owner` holds `discover`,
`read`, `write`, `rename`, `create_child`, `create_credential_reference`,
`read_reference_content`, `write_reference_content`, `manage_access`, and `delete` on
every object that currently exists, including objects created after the role
was assigned.

This is computed centrally in the policy service on every request. No wildcard
grant, per-object grant, sentinel grant ID, or negative grant ID is ever
materialized: the effective policy snapshot carries the authority as typed
global provenance, while `grants_for()` keeps meaning real object grants only.
Scoped grants stay additive and their direct and effective projections are
unchanged. The provenance is part of the policy fingerprint, so assigning or
removing the role immediately invalidates existing cursors and principal-scoped
read state. An inactive catalog owner receives nothing.

An active human or service-account principal with
`catalog_role = catalog_viewer` holds exactly `discover` and `read` on the same
complete current catalog and every object created later, including a new
disconnected root. It never implies `write`, `rename`, `create_child`,
`create_credential_reference`, `read_reference_content`, `write_reference_content`,
`manage_access`, `delete`, platform
administration, credential administration,
or token
administration. Login, a valid browser session or token, and platform admin
alone likewise never imply catalog viewing. The viewer is a distinct typed
global policy source; it is not an object grant and is never materialized into
per-object rows.

An active human or service-account principal with
`catalog_role = project_creator` holds **no** catalog-wide object permission at
all: not `discover`, `read`, `write`, `rename`, `create_child`,
`create_credential_reference`, `manage_access`, or `delete`, on any object,
current or future. Its entire authority is the
right to create one kind of disconnected top-level root — `kind = project` —
through the `create_root` command described below.

That authority is now independently assignable because a top-level root has no
placement parent, so no object grant, including `creator/subtree`, can delegate
its creation. The earlier exclusive catalog-role value remains accepted for
backward compatibility, but new assignments use the separate boolean capability. Delegating root-project creation through `catalog_owner` instead
would hand out catalog-wide write, delete, and access-management authority for
an agent that only needs to open its own projects.

The role is deliberately narrow in every direction:

- it authorizes `create_root` only, and only for `kind = project`; `host`,
  `system`, `network`, `device`, `service`, `credential_reference`, `runbook`,
  and `decision` roots stay denied with the same indistinguishable `403` as no
  catalog role at all;
- it is consulted by no other command, so it grants nothing on the generic
  object create, update, rename, delete, relationship, grant-management,
  comment, import, or reviewed-Knowledge-apply paths, which continue to require
  their existing object permissions or `catalog_owner`;
- it never implies platform administration, credential administration, token
  administration, or catalog reading; and
- it is assigned and revoked independently of `catalog_owner`, through the same
  protected catalog-role command, and carries no last-active-holder invariant.

Each root it creates receives the same atomic direct `Owner/self` grant for the
creating principal as a catalog owner's, so the creator can then read and manage
exactly the projects it opened — and nothing else — through ordinary object
grants. A project creator that is later revoked keeps those object grants,
because they are real, independently revocable grants; it simply cannot open new
roots.

Object grants remain additive. A catalog viewer with an explicit `owner/subtree`
grant has the normal Owner permissions only within that canonical subtree and
remains globally read-only everywhere else. All UI, REST v1, Agent API, MCP,
search, count, relationship, comment, audit, and coverage reads consume this
same policy snapshot, preserving their existing concealment and field-redaction
rules. Policy is rebuilt from current database state on every request without a
long-lived authorization cache; role assignment or revocation changes the
policy fingerprint, so bound cursors fail closed.

Owner coverage counts active local or inherited object Owner grants only.
Global `catalog_owner` authority does not satisfy this invariant. Exclusion-based
checks for deactivation/deletion exclude that principal's grants and require
remaining active object Owner coverage; global administration cannot mask a gap.

Normal catalog-role assignment and removal are performed through one dedicated
application command and its REST/UI surfaces, described below. The role is never
part of the generic principal create or update mutation. Disconnected-root
creation is a separate catalog write available to already-authorized active
catalog owners, described below; it never assigns or removes any role. Until a
catalog owner exists, the protected local commands below remain the only
first-owner and recovery path.

## Catalog-role administration

The dedicated catalog-role command assigns, replaces, or removes
`catalog_owner`, `catalog_viewer`, and `project_creator` on an existing active
principal. It is separate from generic principal create/update, which never
touches `catalog_role`; migration, upgrade, startup, and bootstrap never assign
a viewer or a project creator.

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
exactly once and writes a redacted structured `catalog_role_changed`
security event with actor, target, before/after role, channel, request ID, and
resulting revision. Passwords, tokens, raw request bodies, and secrets are never
recorded.

Removing, replacing, or deactivating the last active catalog owner remains impossible at both
service and SQLite-trigger levels, including concurrent writers. The command
cannot bypass the strict zero-owner bootstrap contract: if no active catalog
owner exists, normal REST/UI administration cannot mint the first one, because
the dual-role gate cannot be satisfied.

No catalog role is assigned to an inactive principal, because such a principal
could later be activated through the generic principal update and gain global
catalog permissions without the dual-role gate or its audit event. Assigning
either role to an inactive target is rejected with the stable principal
conflict, and — for legacy rows or raw writes that already hold that state —
generic principal update refuses to activate a principal that currently carries
any catalog role. The safe sequence is to remove the role through catalog-role
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
active catalog owner, viewer, or project creator. Because creating a root is not
an object permission — a root has no object to hold one — each authority also
reports its creatable `root_kinds`, so a project creator is explained as no
permission plus exactly `["project"]`, and a viewer as read permissions plus no
root kind. REST schemas and the EN/DE UI represent `catalog_owner`,
`catalog_viewer`, `project_creator`, and no role as four distinct states.

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
That includes catalog-viewer and project-creator targets: neither role adds
credential or token administration authority, and neither broadens the
established platform-admin credential workflow. Taking over a project creator's
token yields exactly that principal's root-project creation, never catalog-wide
authority, so it stays on the ordinary platform-admin contract.

## Catalog-role root creation

An active principal holding a catalog role that covers the requested kind may
create a new disconnected top-level catalog root through the dedicated
`create_root` application command, exposed on REST (`POST /api/v1/roots`), the
browser UI (typed **Create root** form), and MCP (`blockwart.create_root`). This
is a catalog write, not a role mutation, and it is the only creation path that
does not require a placement parent.

| Catalog role | Creatable root kinds |
|---|---|
| `catalog_owner` | every kind the object schema accepts |
| `project_creator` | `project` only |
| `catalog_viewer` | none unless `project_creator = true` |
| no catalog role | none unless `project_creator = true` |

Authorization is resolved from current database state inside the command
transaction: the actor must be active and hold either a catalog role whose
creatable kinds contain the requested `kind`, or the independent creator
capability for `kind = project`. Platform-admin alone is denied, and neither
catalog role needs a platform-admin role for this operation. Every missing
property — inactive principal, absent role, uncovered kind, or wrong channel —
raises one indistinguishable denial, so a caller cannot probe which one it
lacks. The trusted channel must also match the credential: browser UI actors use
their browser session, REST writes require an `api`-audience service token,
and MCP writes require an `mcp`-audience service token.

The browser **Create root** form narrows its own kind control to the kinds the
acting principal may create, so a project creator sees a project-only form
rather than a control that fails on submit, and the entry point disappears for
a principal that may create no root at all. That projection is a convenience;
the command re-resolves the same rule from current database state and remains
the authoritative gate.

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
trusted actor, channel, request ID, revisions, and the `catalog_authority` that
was actually used (`catalog_owner` or `project_creator`), so the audit trail
distinguishes a narrow delegated creation from a global one. It never includes
secrets or raw credentials.

## Service-bound credential-reference creation

A credential reference is catalog metadata that names where a credential is
kept — provider, protected path, key, item hint, scope, and handling rules. It
never holds a value, it is never a placement child of the service that uses it,
and a service links it through `data.access_methods[].credential_references`.
Recording one for one service used to need three unrelated authorities:
`creator` cannot place a `credential_reference` below a service, `create_root`
for a `credential_reference` requires `catalog_owner`, and the link needs
`write`, that is unrestricted editing, on the service. Creating a placement
child, a disconnected root, and a service-bound reference are therefore three
separately published creation paths; `blockwart.describe_schema` names each
one and the permission or catalog authority it requires.

### Supported delegation path

1. An Owner of the service, or an `access_manager` on it, grants the agent
   `credential_reference_creator` on that service with `self` scope, or on a
   host or system with `subtree` scope to cover the services placed below it.
   The normal grant commands apply: REST
   `POST /api/v1/objects/{object_id}/access/grants`, MCP `blockwart.create_grant`,
   or the UI **Access control** panel. No catalog role and no platform role is
   assigned.
2. The agent reads the service through REST `GET /api/v1/objects/{service_id}`
   or MCP `blockwart.get_object_context`, confirms that its `capabilities`
   contain `create_credential_reference`, picks the target entry of
   `data.access_methods`, and keeps the strong `etag`.
3. The agent calls REST `POST /api/v1/objects/{service_id}/credential-references`
   or MCP `blockwart.create_service_credential_reference` with that ETag, the
   zero-based `access_method_index`, an `Idempotency-Key`, and the new
   credential-reference object. See [API v1](api-v1.md) and [MCP](mcp.md).

### Command contract

One shared application command runs in one transaction. It:

- authorizes `create_credential_reference` on the service from the request
  policy and again from current database state after it has locked the caller's
  principal row and claimed the service row at the exact `If-Match` revision. A
  concealed or missing service is the same `404`. A discoverable service without
  the capability is `403` with the stable code
  `create_credential_reference_required` and one redacted
  `object_command_authorization` denial event;
- accepts only `kind = credential_reference` and applies the canonical object
  schema, secret-shaped key and value rejection, the credential-reference
  raw-value rule, ACL-shaped-key rejection, and normalization of object creation;
- requires `read` on every typed reference inside the new object's data, so a
  concealed, a missing, and a kind-mismatched target are the same `404`;
- refuses an ID that already names an object or is already held by any stored
  typed reference or relationship with `409 credential_reference_id_unavailable`.
  An existing reference, readable or not, is never reused, re-owned, or linked,
  and a dangling legacy reference is never silently captured;
- creates the reference as a disconnected object with no placement parent and
  no relationship, and writes exactly one direct `Owner/self` grant for the
  caller through the shared ownership primitive;
- appends exactly one `credential_reference:<id>` to
  `data.access_methods[access_method_index].credential_references` and advances
  the service revision once. The applied statement writes only the service's
  data document and optimistic concurrency columns, and the document differs
  from the stored one in that single list: every other field, the other access
  methods, the service-level `credential_references`, relationships, and grants
  are unchanged. The result must still satisfy the full canonical service
  contract; a stored record that does not is refused with
  `409 service_record_invalid` instead of being repaired; and
- records `create_service_credential_reference` on the new object and
  `credential_reference_link` on the service, each with actor, channel, request
  ID, old and new revision, and the exact link path, and stores the idempotency
  result.

Any failure rolls the whole transaction back: no reference, grant, link, audit
event, or idempotency reservation survives. Missing `If-Match` is `428`; a
malformed, weak, or stale value is `412`, and concurrent callers holding the
same base ETag have exactly one winner. The same key and request perform no
second link mutation even after the service revision moves on. Replay requires
current readability of the same created reference instance and returns its
current authorized representation/ETag; stored link-operation metadata remains
original. Re-read the service before another conditional write. The same key
with another service, index, ETag, or object is `409`. An index outside
`data.access_methods` is `409 access_method_not_found`, and a target that is not
a service is `409 credential_reference_requires_service`.

### Ownership and maintenance

The caller becomes the explicit Owner of the new reference. It can then read,
update, rename, and manage access to that reference, and to nothing else of the
service: it can neither edit nor unlink the access method, and a linked
reference cannot be deleted while the service still references it. The
service's Owners and editors keep full control of their service, including
removing the link through an ordinary ETag-bound update. They see the typed
reference in the service data but read the reference object itself only through
their own grants or a global catalog role; its Owner grants further access
explicitly through the normal grant commands.

The command stores metadata only. It never stores or reveals a secret value, and
it grants no access to a secret store or to the target system.

### Owner-mediated workaround

Where nobody holds or may be given `credential_reference_creator`, the same
result still needs three separately authorized steps, and the agent still needs
no broad role:

1. an existing catalog owner creates the disconnected reference with
   `create_root` and becomes its Owner;
2. a principal with `write` on the service — its Owner or an editor — links it
   through an ETag-bound full-object update, which also requires `read` on the
   new reference; and
3. the reference's Owner grants the agent explicitly scoped access to that
   reference, for example `editor/self`, for later maintenance.

The delegation path replaces these steps with one atomic, idempotent,
service-scoped call. It never assigns `catalog_owner` or `write` on the service.

## Grant management

An actor needs effective `manage_access` on the anchor object to list, create,
update, or revoke its direct grants. Owner grants have an additional invariant:
an actor needs a current local/inherited Owner source **or** global
`catalog_owner` authority to create, change, or revoke them. Both paths enforce
local Owner coverage and current revision checks inside the command transaction.
An ownerless object requires the dedicated adoption flow, not an ordinary grant
mutation. Platform admin alone grants neither path.

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

An actor that has `manage_access` but neither an effective Owner grant nor
Global Catalog Owner authority is refused an Owner-grant change with one of two stable reasons, published identically as
the REST and MCP error `code` and as a localized UI message:
`owner_required_to_manage_owner_grants` when the object has an active Owner,
and `object_has_no_owner_use_adoption_flow` when it has none. Both are still
denials and write the normal redacted denial security event with the reason.

## Ownership invariant and ownerless recovery

Every catalog object must be reached by at least one active object Owner grant,
directly or through a canonical subtree grant. A global `catalog_owner`
administers every object but is deliberately not an object Owner source: it
neither satisfies nor masks this per-object invariant. It **can** add, change,
or remove existing-object Owner grants without a local grant, subject to the
same local coverage and revision constraints. The first Owner of a legacy
ownerless object still uses the dedicated audited adoption flow.

One shared primitive (`blockwart.services.ownership.assign_initial_owner`)
writes the first direct `Owner/self` grant inside every creation transaction:

| Creation path | First Owner |
|---|---|
| REST `POST /api/v1/roots`, `/children`, `/attached-devices`, `/credential-references`; MCP `create_root`, `create_child`, `create_attached_device`, `create_service_credential_reference`; browser create forms | the authenticated creator |
| `blockwart-seed` | the explicit `--owner-login` principal |
| `blockwart-import-markdown --apply` | the explicit `--owner-login` principal |
| reviewed Knowledge apply | the applying catalog-owner principal |

The owner must be an existing active principal. A missing or inactive owner is
rejected before commit (`owner_principal_required` or
`owner_principal_inactive`), and any failure while writing the grant rolls back
the object with it. Seeds and imports also prove, before commit, that every
object they created carries its direct Owner. Nothing ever guesses an owner
from other effective permissions, and a seed's descriptive `owner` field is
provenance only. Alembic migrations create no catalog objects.

Objects created before this invariant can still be ownerless. They are detected
read-only by:

- `blockwart-db owners`, which prints one JSON line per ownerless object (ref,
  label, revision and ETag, top-level or placed, active direct/inherited and
  inactive direct Owner counts, provenance source type and path, and whether
  adoption is currently possible) and exits `1` while any exist;
- `blockwart-db integrity`, which additionally warns with
  `owner_integrity_warning code=access_owner_missing` without failing;
- the needs-attention view (`access_owner_missing` in category `access`), shown
  only to principals that may manage the object's access;
- `owner_coverage` on the object access resource and in the UI access panel.

Online, the only repair is the audited adoption command (REST `POST
/api/v1/objects/{object_id}/access/adoption`, MCP
`blockwart.adopt_ownerless_object`, and the **Adopt ownerless object** form in
the UI access panel). It requires an active catalog owner on a trusted channel
and the current strong ETag, assigns exactly one direct `Owner/self` grant to
one active principal, and refuses as soon as any active direct or inherited
Owner grant exists. Its compare-and-set revision claim gives concurrent
adoptions exactly one winner. See `api-v1.md` for the full contract.

An upgraded legacy catalog that still contains ownerless objects cannot become
ready, so it cannot reach that command. For this state, the protected pre-start
form is `blockwart-db adopt-owners` against the stopped database. The trusted
operator running that protected CLI is the administrative authority. It requires
an explicit existing active target principal, which needs no catalog role, and
an audit reason, previews the exact
set with a plan digest, and applies only that reviewed set in one transaction.
It fails closed on drift, reruns as a no-op, and leaves the same `owner_adopt`
audit evidence (channel `cli`, actor `protected_cli`). It never changes
readiness. See `deployment.md` for the full upgrade sequence.

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

The object-update preview is the one authenticated catalog operation that
requires effective `write` while deliberately issuing database reads only. A
valid credential is checked against the same current token and policy state,
but a successful or object-denied preview does not update token `last_used_at`
or append a denial security event. Invalid credentials never reach planning
and retain the normal shared failure buckets and bounded security evidence.

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

On a fresh, still-empty catalog, bootstrap first and seed afterwards. With
`--catalog-owner`, `--object-id` may then be omitted: the command creates only
the first identity, and the following `blockwart-seed --owner-login kai` gives
that principal a direct `Owner/self` grant on every object it creates. An
anchor-free bootstrap is refused on a non-empty catalog or without
`--catalog-owner`, and startup still reports `owner_catalog_empty` until the
catalog has objects.

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

Alembic revision `20260822_0019` expands only the existing catalog-role check
constraint to accept `catalog_viewer`. It changes no existing role, principal,
credential, grant, or owner counter and assigns nobody. PostgreSQL replaces the
constraint in place; SQLite rebuilds `principals` and recreates the established
platform-admin and catalog-owner guard/counter triggers verbatim. Downgrade to
`20260818_0018` is data-preserving when no viewer remains and fails closed while
any principal still carries `catalog_viewer`; operators must explicitly remove
those roles through the protected lifecycle before retrying. No grant is ever
removed or rewritten.

Alembic revision `20260909_0023` expands the same catalog-role check constraint
once more, to accept `project_creator`. It changes no existing role, principal,
credential, grant, or owner counter and assigns nobody. Because the role carries
no last-active-holder invariant, it adds no counter row and no trigger; SQLite
rebuilds `principals` and recreates the established platform-admin and
catalog-owner guard/counter triggers verbatim, while PostgreSQL replaces the
constraint in place. Downgrade to `20260909_0022` is data-preserving when no
project creator remains and fails closed while any principal still carries
`project_creator`.

Alembic revision `20260925_0024` adds the independent non-null boolean
`principals.project_creator`, defaulting to false. Existing principals whose
exclusive catalog role was `project_creator` are backfilled to true; owner and
viewer roles, principal revisions, and all object grants are unchanged. A
viewer can then receive the independent capability without surrendering global
read access. Downgrade fails closed while any independent capability cannot be
represented by the legacy exclusive role.

Alembic revision `20260926_0025` expands only the object-grant role check
constraint, to accept `credential_reference_creator`. It writes no grant and
rewrites no existing row: `owner` and `catalog_owner` gain
`create_credential_reference` from the role or catalog role they already store,
and no other stored role gains it. PostgreSQL replaces the constraint in place;
SQLite rebuilds `object_grants`, which carries no trigger. Downgrade to
`20260925_0024` is data-preserving when no such grant remains and fails closed
while any grant still carries `credential_reference_creator`; revoke those
grants through the normal grant commands before retrying.

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

Browser-session issuance records `browser_session_issued` with only the
server-selected `session_mode` and bounded `lifetime_seconds`. Single and bulk
revocation evidence (`browser_session_revoked` and `browser_sessions_revoked`)
records only the mode or per-mode counts and a stable server-selected reason;
`browser_logout` also carries the mode. Cookie values, session values, CSRF
values, password material, and hashes are never included. These events reuse
the request correlation ID and transaction of the triggering operation.

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
through the dedicated `create_root` command described above. A credential
reference bound to one service access method is created only through the
service-scoped `create_credential_reference` capability described above. Production
identity bootstrap, token injection, and runtime rollout still require their
dedicated approval.


## Consolidated role contract (#297)

The product labels **Global Catalog Owner** and **Global Catalog Reader** map
to the existing stored values `catalog_owner` and `catalog_viewer`. There is no
new reader role, schema revision or automatic assignment. New human and
service accounts default to no platform role, no catalog role, no project
creation capability and no object grants. Existing explicit assignments survive
unchanged. Authentication is not authorization.

| Object role | Discover | Read | Rename | Write/comments/PM/sync | New children | New credential reference | Manage non-Owner grants | Manage Ownership | Delete |
|---|---|---|---|---|---|---|---|---|---|
| discoverer | yes | — | — | — | — | — | — | — | — |
| viewer | yes | yes | — | — | — | — | — | — | — |
| renamer | yes | yes | yes | — | — | — | — | — | — |
| editor | yes | yes | yes | yes | — | — | — | — | — |
| creator | yes | yes | — | — | yes | — | — | — | — |
| credential_reference_creator | yes | yes | — | — | — | yes | — | — | — |
| access_manager | yes | yes | — | — | — | — | yes | — | — |
| owner | yes | yes | yes | yes | yes | yes | yes | yes | yes |

The credential-reference capability creates new metadata through its narrow
service command; a Project workspace reference creation additionally needs
Project write authority. No role gives a secret value or external access.
The last local Owner cannot be removed without replacement, even by a global
Owner. Global Owner controls all present/future roots and objects, independent
of local Owners, but is not an identity administrator. Ownerless repair remains
explicit and audited rather than bypassing coverage checks.

Global Reader supplies only discover/read everywhere. Other grants are additive:
Reader + Editor on Project A can comment, maintain records and synchronize on A,
but not elsewhere. Reader alone creates no root, child, comment, record or
synchronization. `project_creator` remains independent: Reader + Project Creator
can read everything and create its own Projects, not edit other Projects. A
creator receives Owner/self atomically only on genuinely new objects; it may
not capture an existing foreign object. Revocation removes that source only.

`self` is anchor-only. `subtree` propagates only down canonical `hosts` edges
Host -> System, Host -> Service and System -> Service. No inheritance follows
Project links, network links, attached devices, references, assignees, authors,
`managed_by` or repository ownership. Direct grants do not override inherited
or global rights; effective rights are their union.

### Existing-object placement is an access-boundary mutation

A placement create/delete requires effective Owner on the existing child or
Global Catalog Owner, evaluated **before** changing the graph. Attaching also
requires `create_child` on the destination parent; detaching requires `write` on
the current parent. A denied child-Owner check has stable code
`owner_required_to_change_placement`. The normal anchor-write, visibility, kind,
ETag and relationship/coverage invariants still apply. An editor may continue
ordinary content edits and non-inheriting relationships; it cannot change
placement merely to acquire inherited permissions. Placement is changed only
by the authorized relationship commands, not by an arbitrary object document
or Project-record import. Protected offline imports remain a separate operator
trust boundary and do not expose a weaker online mutation route.

### Revocation and running commands

Online mutations lock and reload authorization in the existing shared order:
principals in ID order, active Owner grants, canonical placements, then
authority/anchor grants. These are held until transaction end. Comments and
chronology then lock the current object instance before any idempotency
reservation, append, revision bump or successful replay. Object, relationship,
new-object, Project-record/action/sync and legacy-import commands use the same
current-context gate. Read-only previews remain lock-free and give no later
write guarantee. SQLite serializes writers; PostgreSQL row locks establish the
order with concurrent grant revocation, catalog-role changes and deactivation.
A writer authorized first may commit before revocation; once revocation wins,
a stale snapshot cannot write or return a successful replay. A Project synchronization denied at its initial current-authority gate must
not resolve credentials or call GitHub. External acquisition uses short
preflight and completion transactions, never long-lived authorization locks.
The preflight validates CAS, references and idempotency without record/event/key
mutation. Immutable project/record snapshots bind acquisition; source changes
fail completion CAS. Current authority and credential readability are checked
again before each further GitHub GET and before storing a result. Revocation
while an already-authorized GET is in flight prevents further GETs and durable
observations; it cannot undo the already-started request. Successful cached
replays perform no acquisition. Completion revalidates credential readability
for **all** acquired references, including earlier successes when a later GET
outlives revocation. An unreadable credential produces only the reference,
`ok: false` and `credential_not_accessible`; protected repository names, URLs,
state and metadata are not persisted in the event or idempotency response.

### Rights explanation and rollout

Object access and principal-assignment responses carry real grant `sources`
separately from additive `global_authorities` (source, permissions, root kinds).
The REST fields are preserved by MCP and rendered with the same EN/DE global
role labels in the UI. `owner_coverage.actor_has_owner_source` still describes
a real local/inherited source; `actor_has_global_authority` separately reports
Global Owner authority. Global authority is never fabricated as a grant and
never counted as local coverage. Active explicit global principals are included
even with no ObjectGrant rows; candidate selection uses an IN-subquery instead
of DISTINCT, preserving deterministic case-insensitive ordering on PostgreSQL.

This change needs no data migration or mass grant creation. The release version,
DB schema, current identities/role assignments and existing grants are unchanged.
Verify explicit Reader assignment/revocation, role combinations, global Owner
create/update/revoke, valid/denied placement and concurrent revocation before
rollout. Rollback changes code only; no new role value needs conversion. A
rollback would restore the old security gaps and is not a security remediation.

The separate identity-admin trust decision is deliberately unchanged: a
platform admin can still take over non-global-Owner identities through the
existing protected credential contract. Global-Owner targets retain the
existing human dual-role/password protection. This issue does not silently
extend that restriction to every locally authorized identity.


Review follow-up strengthens three equivalent boundaries: manually triggered
release checks in UI/REST use short authorization/lease transactions before
provider acquisition and fresh authorization plus instance/revision validation
before observation persistence. No database transaction spans the provider
request. Revoked completion releases its own lease without storing an
observation (scheduled workers keep short lease transactions); identity-role/capability and credential mutations
lock actor/target/coverage before password reauthentication can insert its FK
audit event; creation replays re-check the created object's current readability
and re-project current fields/capabilities, not historical Owner authority.
Fresh creation records bind an immutable object instance; legacy records bind
the recorded creation timestamp. Hidden or replaced results are refused even
when the caller retains creation rights on the old parent. Replay performs no
second mutation, but its returned representation/ETag reflects current access
and state; unchanged-state replay remains equal apart from `replayed`.
