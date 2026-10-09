# Access Requests And Temporary Grants

Issue #100 adds a governed way for authenticated principals to request missing
read access instead of arranging it outside Blockwart. The same request,
decision, policy and audit contract backs the UI (`/access-requests`), the REST
API and MCP; MCP tools proxy the identical REST endpoints.

## Workflow

1. A principal that currently holds `discover` on an object may apply for
   exactly **Viewer on `self`**, temporary or permanent, with an optional
   bounded purpose text (untrusted input: length-capped at 500 characters,
   control characters stripped). A principal that can already `read` the object
   gets `409`.
2. Principals that currently hold `manage_access` on the object see the open
   request in the UI, `GET /api/v1/access-requests` and
   `blockwart.list_pending_access_requests`, and approve or deny it.
3. Approval atomically creates exactly one Viewer grant plus audit events
   (`grant_create`, `access_request_approve`). Denial and cancellation create no
   grant. Approvers may shorten but never extend a temporary window; a
   permanent request may be shortened to temporary. An approval is refused
   (`409`) if the requester is no longer active, can no longer `discover` the
   object, or already holds `read`; a denial is always possible.
4. Everything is re-evaluated against current state on every call: nothing the
   caller held when authenticating, or when the request was created, is trusted.

## Request States

Stored statuses: `pending`, `approved`, `denied`, `cancelled`, `expired`,
`revoked`. The API always reports the **effective** state at the time of the
call:

| Effective state | When |
| --- | --- |
| `pending` | not decided, and (if temporary) its requested window has not elapsed |
| `expired` | a pending temporary request whose requested window elapsed (it can no longer be approved), **or** an approved request whose grant window elapsed |
| `revoked` | an approved request whose grant was removed |
| `approved` / `denied` / `cancelled` | as decided |

**Reads never write.** `GET /api/v1/me/access-requests`,
`GET /api/v1/access-requests`, their read-only MCP tools and the UI page project
the effective state from the stored row, the grant it created and the clock.
They flush nothing, append no audit event and do not even update a token's
`last_used_at`; the regression tests compare *every row of every table* before
and after, across the expiry and revocation boundaries.

**Writes persist the end.** The stored status moves to `expired` / `revoked`
only inside a write lifecycle that already owns a transaction, each with exactly
one audit event (`access_request_expire`, `access_request_revoke`) and a
guarded `UPDATE ... WHERE status = <expected>` so parallel lifecycles cannot
double-apply:

- creating a request for the same requester and object;
- revoking or replacing the grant (`DELETE .../access/grants/{id}` and the
  grant-create path), which ends the approval at the moment of revocation;
- deciding or cancelling.

The original decision columns (`decided_by`, `decided_at`,
`approved_expires_at`, `reason`) are never rewritten; `ended_at` records when an
approval or pending window stopped counting.

## Replacement After Expiry Or Revocation

Only `pending` requests occupy the open-request slot (a partial unique index on
requester, object, role and scope, identical on SQLite and PostgreSQL — the
ORM model carries the same `postgresql_where`, so `create_all` and migrations
agree). An approved request therefore never blocks a replacement:

- after a temporary grant expires, or after a grant is revoked, the requester
  can simply ask again; no unrelated read has to run first;
- approving the replacement removes the expired grant row (audited as
  `grant_expire`) and creates a fresh grant; an administrator creating the same
  Viewer assignment over an expired temporary grant does the same instead of
  being answered with the dead row;
- a *true retry* while a request is still pending returns that same request
  with `changed: false` and leaves the original row, its reason and its audit
  history untouched (retry parameters never overwrite it).

## Concealment

- Without `discover`, creating is indistinguishable from an unknown object
  (`404`).
- The requester's list, status and cancellation re-check the active identity
  and the **current** `discover` on every call. After visibility is lost the
  list omits the request entirely (no object id, request id, status or grant
  id) and cancel returns the same `404` as an unknown request id. An inactive
  principal gets the same uniform `404` on every requester path.
- Approvers need current `manage_access` *and* an active identity; policy lost
  between listing and deciding yields `403` and changes nothing.

## Durations And Expiry

- Conservative defaults (module constants in
  `blockwart.services.access_requests`, changed only by shipping code):
  temporary TTL between **5 minutes and 30 days**; at most **10 open requests
  per requester**; list responses are capped at 200 items.
- Temporary grants carry `expires_at`. Policy computation, "my direct grants"
  and the principal grant views ignore expired grants, so access ends at the
  timestamp without a restart and without a cache to invalidate; the policy
  fingerprint (and therefore ETags/cursors bound to it) changes with it.
- Permanent grants behave like every other grant and end only through the
  normal revocation lifecycle.

## Approver Hints (Notifications)

A hint tells one currently authorized approver, through one
administrator-approved agent route, that a request is waiting. It is a pointer,
never a decision.

- **Honest states.** Nothing is "delivered" because a no-op ran. When hints are
  not enabled the request's creation audit event records
  `notification: "disabled"`; when no approved route belongs to a principal that
  can decide the request it records `"no_route"`; otherwise `"queued"`. Only the
  outbox can establish `delivered`, and only after the transport confirmed
  acceptance (or a receiver confirmed the same `delivery_id` as a duplicate).
  The requester's responses never reveal routing.
- **Recipients.** Active agent delivery targets (registered by a platform admin
  via [Agent notices](agent-notices.md)) of active **service accounts with a live
  token that hold `manage_access` on the object right now**, excluding the
  requester. At most 10 recipients per request. Registering a target is the
  administrator's approval of that route; no new route or URL is created by
  access requests.
- **Durable and bounded.** One `access_request_notices` row per
  `(request, target)` is written in the request's own transaction. Retries use
  exponential backoff (30 s base, 1 h cap), an attempt budget of 5 and a 24 h
  TTL; exhausting either is the dead-letter state (`failed` / `expired`). At
  most 20 pending notices per target (`storm_suppressed`). A claim commits a
  fenced lease **before** any network I/O, no transaction or lock is held while
  the transport runs, and the result is written by an update conditional on the
  lease token, so a crashed or slow worker can neither duplicate nor overwrite.
- **Attempt-time authorization.** Before every attempt the target, the
  principal, a live token, the request (still effectively pending, requester
  active) and the recipient's current `manage_access` are re-checked. A lost
  authorization suppresses the notice (`target_inactive`, `principal_inactive`,
  `manage_access_lost`, `request_not_pending`) and nothing leaves Blockwart.
  Deciding or cancelling a request also suppresses its unclaimed notices.
- **Minimal payload.** A closed schema: `schema_version`, `event_type`
  (`access_request_pending`), `request_id`, `object_ref`, a fixed message and a
  *relative* `blockwart_reference` (`/api/v1/access-requests`). It never carries
  the reason, requester identity, object label, token or any URL. Following it
  requires the recipient's own Blockwart credentials; the hint approves nothing.
- **Independent of the request.** Notices only read request state. A failing,
  expired or dead-lettered notice cannot change a request or a grant; planning
  a notice runs in the same transaction as the request, so they commit or roll
  back together.
- **Transport.** The only transport is the isolated loopback
  OpenClaw test gateway of the agent notice channel (`openclaw_test_gateway`).
  There is no configurable callback URL, and the former unrestricted
  `WebhookNotifier` is gone. Delivery ids are `access-request-notice-<uuid>`,
  globally unique, so a receiver can never confuse two different notices.
- **Redacted diagnostics.** Attempts store a coarse outcome and a safe error
  code only (no payload, route, token or URL).

### Enabling hints (deployment decision, off by default)

Hints are queued and delivered only when **all three** hold:
`BLOCKWART_ACCESS_REQUEST_NOTICES_ENABLED=true`,
`BLOCKWART_NOTICE_DELIVERY_POLLER_ENABLED=true` and a loopback
`BLOCKWART_NOTICE_DELIVERY_ENDPOINT_URL` (see [Configuration](config.md)). A
refused (non-loopback) endpoint logs
`access_request_notice_poller_error code=transport_refused` and ends only this
poller. Without them requests record `notification: "disabled"` and no notice
exists. Shipping this code changes no deployment configuration.

## Fail-Closed Properties

- Duplicate retries and races map onto the single pending slot (partial unique
  index); parallel create / decide / cancel have exactly one winner, the other
  callers conflict (`409`) or receive the winner's request unchanged.
- A failure while creating the grant rolls back the whole decision: no
  half-decided request, no orphan grant, no approval audit event.
- Audit entries contain ids and timestamps, no secrets and no reason text
  (only its length).

## Audit And Recovery

Audit actions: `access_request_create` (with the routing state),
`access_request_approve`, `access_request_deny`, `access_request_cancel`,
`access_request_expire`, `access_request_revoke`, plus the existing
`grant_create`, `grant_revoke` and `grant_expire` for the grant.

Manual recovery: revoke the generated grant through the normal grant management
surface (`DELETE /api/v1/objects/{id}/access/grants/{grant_id}`); the request
becomes `revoked` in the same transaction. Completed request rows are
historical evidence and need no cleanup.

## Migration And Rollback

Revision `20261009_0028` follows PR221's `20261009_0027` (which follows main's
`20260926_0026`), so the combined history has exactly one Alembic head. It is
purely additive: one nullable column `object_grants.expires_at` (existing
grants stay permanent), `access_requests`, `access_request_notices` and
`access_request_notice_attempts`. Upgrades from a populated database keep every
principal, object, grant and notice row byte-for-byte, on SQLite and
PostgreSQL.

The downgrade **fails closed while any grant carries an expiry** (expired or
not): dropping the column would silently turn those temporary Viewer grants
into permanent ones, so revoke them first. It then drops exactly the structures
this revision created; access-request history and hint notices are removed
(export the audit trail first, and for a live rollback restore the verified
pre-upgrade database per the deployment recovery contract).

## Verification

```bash
export NO_PROXY=127.0.0.1,localhost,::1 no_proxy=127.0.0.1,localhost,::1
pytest tests/test_access_requests.py tests/test_access_request_hardening.py \
  tests/test_access_request_notices.py tests/test_access_request_ui.py \
  tests/test_migrations.py tests/test_postgresql_compat_regressions.py -rs
```

Set `BLOCKWART_TEST_PG_URL` to a disposable PostgreSQL to run every case on both
backends; without it the PostgreSQL cases skip (visible with `-rs`).
