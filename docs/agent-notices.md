# Agent Notices: Delivering Blockwart Events To Agents (Issue #106)

Blockwart can surface information to humans in UI, REST, and MCP, but agents
learn about relevant events only by polling. Agent notices add a narrow,
auditable push channel for selected events. The first supported event is the
release-monitoring signal `release_update_available` — deliberately reusing
the shipped attention vocabulary from #105 instead of the issue draft's
`service_release_update_available`, so events, attention reasons, and notices
speak one language.

## Status And Boundary

This is a **delivery foundation proven against a fake/loopback test gateway**.
It is not a production OpenClaw rollout:

- The only shipped real transport, `OpenClawTestGatewayTransport`, refuses
  every non-loopback destination at construction, ignores environment HTTP
  proxies, and refuses redirects. There is no live gateway, Telegram/e-mail
  delivery, callback URL, credential, infrastructure, or deployment setting.
- A productive transport, its credential handling, and its network path need a
  separate design and approval round.
- Delivery is **at-least-once on the wire with a receiver-enforced idempotency
  key**. Blockwart never claims exactly-once or at-most-once *transport*. What
  it guarantees is: no repeat of a *confirmed* delivery, and a receiver that
  honors `delivery_id` shows one visible notice per logical event and target
  even when responses are lost, workers race, or a worker crashes. A gateway
  that ignores `delivery_id` can show duplicates after a lost response; that is
  a receiver property Blockwart cannot repair.
- A delivered or acknowledged notice proves receipt only. It grants no access,
  extends no grant, and triggers no update or deployment.

## Model

- **Event** (`agent_notice_events`): one deduplicated logical occurrence with
  a stable public id and a `dedupe_key`. Repeated emission of the same logical
  occurrence (retry, process restart, concurrent emitters) is a no-op.
- **Target** (`agent_delivery_targets`): one approved destination bound to one
  active service-account principal by a non-secret `route` (lower-case
  `[a-z0-9._:-]`). Targets carry no credential material. **One logical route
  can be registered by at most one active target** (any principal): a partial
  unique index on `(transport, route) WHERE active` enforces it identically on
  SQLite and PostgreSQL, the service validates first for a clear error
  (`route_already_registered`, REST `409`), and a revoked route can be approved
  again later.
- **Subscription** (`agent_notice_subscriptions`): an explicit, revocable
  routing rule between event/object scope and a target. Only platform
  administrators create them; both ends are validated (active service-account
  principal, active target owned by that principal, existing object). The same
  rule cannot be active twice (`subscription_already_registered`, `409`;
  partial unique indexes for object and catalog scope).
- **Job** (`agent_delivery_jobs`): exactly one per `(event, target)` pair,
  enforced by a unique constraint. States: `pending`, `delivered`, `failed`
  (dead-letter), `suppressed`, `expired`, `acknowledged`.
- **Attempts** (`agent_delivery_attempts`): redacted audit with coarse
  outcomes only — `success`, `confirmed_duplicate`, `timeout`, `unavailable`,
  `rate_limited`, `lease_expired` (a crashed or abandoned attempt). No payload,
  prompt, token, session, or URL content.
- Administrative changes (target/subscription create and revoke) are recorded
  as security events (`agent_notice_*`) with actor, channel, and ids only.

## Delivery Pipeline: Lease, Recheck, Send, Record

`deliver_due_agent_notices` processes one job at a time, so no phase holds a
database write lock while another waits on the network:

1. **Claim (committed).** A single-row conditional UPDATE takes a *lease* on a
   due `pending` job: it sets a fresh random `lease_token` (the fencing token),
   a bounded `lease_expires_at` (`lease_seconds`, default 60, must exceed the
   transport timeout), and consumes one attempt of the budget. It commits
   immediately. The UPDATE compares against the lease state it observed, so
   two workers cannot both win a row on either backend. Reclaiming an expired
   lease records the abandoned attempt as `lease_expired`.
2. **Recheck.** In a fresh read (identity map expired), the job is judged from
   current state only: TTL, attempt budget, target active, principal active and
   a service account, an unrevoked unexpired service token, the subscription
   still active and matching the event, and current `read` on the object via
   the normal policy snapshot. Any miss — or any unexpected error — fails
   closed: the job becomes `suppressed`/`failed` with a safe code, the attempt
   is handed back, and nothing leaves Blockwart. Transient DB read failures
   instead consume the bounded attempt budget and retry with `delivery_error`,
   backoff and TTL; they never send on an uncertain authorization read.
3. **Send.** The read transaction is ended; the transport runs with **no
   database transaction open**. The payload is closed and fixed (below).
4. **Record (fenced).** The outcome is written by an UPDATE conditional on the
   `lease_token` and `status = 'pending'`, together with the attempt row, in one
   transaction. The lease must also remain unexpired. A worker whose lease
   expired or was reclaimed changes nothing (`lease_lost` in the pass statistics).

Database invariants back this: a lease token and expiry exist together, and
only a `pending` job may hold a lease. The production poller uses fresh database
time for claims, expiry and retries, avoiding worker wall-clock skew; callers
using the inline delivery API must supply a shared clock (fixed `now` is for tests).
The loopback adapter enforces a total wall-clock deadline through headers and
body, closing the socket on expiry. Invalid/refused endpoints are logged only
as `transport_invalid`; startup and shutdown remain safe. The admin UI shows
poller and endpoint state without displaying URLs or tokens.

### Response loss and replay

Every send carries `agent-notice-job-<event UUID>-<target UUID>`. The UUID pair
is globally unique across new databases/instances and stable for the same logical
job on retry or restore; local integer primary keys are never receiver keys.
A gateway that accepted old integer keys before this repair cannot correlate
them with the new UUID keys: drain pending retries before adopting this repair
in such a test environment, or reconcile receiver receipts explicitly.
If the response is lost after the receiver accepted the notice, the retry
reaches a receiver that already holds that key. The receiver contract:

- `2xx` accepts the delivery.
- A repeated `delivery_id` is answered with the **duplicate confirmation**:
  HTTP `409` (or `2xx`) with the JSON body
  `{"status": "duplicate", "delivery_id": "<the same id>"}`.

Blockwart records a confirmed duplicate as the prior success: the job becomes
`delivered` (attempt outcome `confirmed_duplicate`), not `failed`. A `409`
without that exact body, or naming another id, is an ordinary failure. Once a
job is `delivered` it is never sent again.

### Crash, reclaim, and bounds

- A worker that dies after the claim leaves a lease that expires; any worker
  may then reclaim it under a new token. The late original worker is fenced out.
- The claim consumes an attempt, so a crash loop cannot exceed `max_attempts`
  (default 5): the next claim past the budget ends the job as `failed` with
  `attempt_limit_reached` without sending.
- Failures back off exponentially (base 30 s, cap 1 h). Past TTL (default 24 h)
  the job is `expired`; after the attempt limit it is `failed`. Both are
  terminal and diagnosable.
- Known race, deliberately fail-safe: authorization is rechecked directly
  before each send, but a revocation that lands *after* the recheck and before
  the receiver accepts cannot recall that single in-flight notice. The next
  attempt is suppressed. Likewise, if a lease expires while its (slow) worker
  is still sending, a reclaiming worker's duplicate send is collapsed by the
  receiver, and the fenced slow worker records nothing.

## Payload And Prompt Boundary

The payload schema is closed:
`{schema_version, event_type, event_id, object_ref, message,
blockwart_reference}`. The message comes from one fixed template built only
from the visible object label and the already URL-safe validated tag. Release
notes, titles, HTML/Markdown bodies, upstream URLs, error strings, secrets, and
hidden object details never enter payloads, prompts, or audit. The envelope on
the wire is `{delivery_id, target, notice}`; `target` is the non-secret route.

## Surfaces

**REST — agent scoped** (bearer service-token auth, own state only):

- `GET /api/v1/notices?status=&limit=` — own notices plus delivery state,
  newest first, fail-closed on current `read`; several routes of one agent for
  the same event collapse to one notice with the furthest-progressed state.
- `POST /api/v1/notices/{event_id}/acknowledge` — receipt confirmation.
  Idempotent; only the owning principal, only while it can read the object
  (otherwise `404`, no hint); only a `delivered` notice can be acknowledged.

**REST — platform-admin scoped:**

- `POST /api/v1/admin/notices/targets`, `GET /api/v1/admin/notices/targets`,
  `DELETE /api/v1/admin/notices/targets/{id}`.
- `GET /api/v1/admin/notices` (subscriptions),
  `POST /api/v1/admin/notices/subscriptions`,
  `DELETE /api/v1/admin/notices/{subscription_id}`.
- `GET /api/v1/admin/notices/jobs?status=&limit=` — redacted diagnostics over
  all six states: no payload, endpoint, lease, or token data.

Validation failures return `422`, uniqueness conflicts `409`, both with the
stable reason in `error.code`; non-admins get `403`.

**UI — `/admin/notices` (platform admin, linked from Settings):** delivery
state counts for all six states, a status-filtered delivery table (safe error
codes, attempts, last attempt outcome), approved targets with revoke, routing
rules with revoke, and CSRF-protected forms to approve a target and create a
rule. It never renders an endpoint, bearer token, lease, session, or message
body.

**MCP (dedicated, agent-scoped, no principal argument):**

- `blockwart.list_own_notices` — read-only; forwards to `GET /api/v1/notices`.
- `blockwart.acknowledge_notice` — idempotent receipt write; forwards to the
  acknowledge route. It is not an approval and starts no action.

The receiving agent decides under its own rules, grants, and approvals whether
to ignore the notice, investigate, or propose a separate approval-gated
workflow. Delivery never widens its tools or access.

## Configuration

Delivery is off by default. The poller runs in the FastAPI lifespan only when
`BLOCKWART_NOTICE_DELIVERY_POLLER_ENABLED=true` **and** a loopback
`BLOCKWART_NOTICE_DELIVERY_ENDPOINT_URL` is set
(`BLOCKWART_NOTICE_DELIVERY_POLL_INTERVAL_SECONDS`, default 30, min 5;
`BLOCKWART_NOTICE_DELIVERY_MAX_PER_RUN`, default 50). The optional bearer token
for the test gateway is read from `BLOCKWART_NOTICE_DELIVERY_TOKEN` at start,
never stored, logged, audited, or placed in a payload. Retry, TTL, lease, and
storm limits are `NoticeDeliveryPolicy` code defaults; exposing them as
settings is a follow-up. Fan-out refuses more than 20 pending jobs per target
(`storm_suppressed`), and a pass processes at most 50 jobs.

## Operational Runbook

- **Enable (test environment only):** as platform admin approve a target for an
  active service account and create a subscription (UI or REST); the next
  fresh observation with `update_available` fans out, including the first
  observation of an outstanding update. Current, unknown and backwards releases
  do not notify. A persisted highest-observed version prevents repeated checks
  of a withdrawn release from later notifying, even after a fan-out failure. Repeated checks (including 304) dedupe by instance/provider/version.
  A fan-out failure rolls back all notice changes, logs `fanout_failed`, and
  preserves the observation; a later equal-version check may retry emission.
  Enable the poller and configure a valid loopback test endpoint to deliver jobs.
- **Rotate/revoke:** revoke the principal's service tokens (the activity check
  suppresses deliveries on the next attempt), revoke the target, or revoke the
  subscription; each suppresses pending work fail-closed.
- **Diagnose:** `/admin/notices` or `GET /api/v1/admin/notices/jobs`. A job
  showing `lease_expired` attempts indicates crashed or stalled workers.
- **Dead-letter recovery:** inspect `failed` rows and their safe
  `last_error_code`; fix the cause, then emit a fresh logical event (a new
  version observation) — failed jobs are terminal by design and never replay
  silently.
- **Full channel shutdown:** unset the poller flag and/or revoke every target;
  disabling the poller pauses existing pending jobs without changing their
  state. Revoked targets receive no new jobs; existing pending jobs suppress
  only when a delivery pass runs. Only storm protection creates suppressed jobs
  during fan-out.
- **Rollback:** migration `20261009_0027` is additive (five new tables); its
  downgrade drops them and the nullable notice high-water field. Stop Blockwart and restore the verified pre-upgrade
  database per the deployment recovery contract before any live rollback.

## Verification

Focused, runnable without any live gateway (loopback only; export `NO_PROXY`
for hosts with an HTTP proxy; set `BLOCKWART_TEST_PG_URL` to also run the
PostgreSQL parity cases):

```bash
export NO_PROXY=127.0.0.1,localhost,::1 no_proxy=127.0.0.1,localhost,::1
pytest tests/test_agent_notice_delivery.py tests/test_agent_notice_hardening.py \
  tests/test_agent_notice_surfaces.py tests/test_migrations.py \
  tests/test_postgresql_compat_regressions.py tests/test_openapi_contract.py \
  tests/test_mcp_manifest_contract.py -rs
```

## Deliberate Scope Boundaries And Follow-Ups

- No Telegram/e-mail delivery to humans (per issue out-of-scope).
- No productive gateway, credential, or network path (separate approval).
- Retry/TTL/lease knobs as environment settings.
- Sharing the outbox contract with access requests (#100) stays decoupled.

Migration reconciliation for Issue #100: historical 0025/0026 remain unchanged.
The single unmerged 0027 after 0026 now also adds nullable
`service_release_observations.notice_highest_version` (String(64)), backfilled
from `latest_version`, and removes it on downgrade. Issue #100’s 0028 must
retain this revised 0027 predecessor and matching release-observation model.
A test DB already stamped with the old unmerged 0027 must be rebuilt or
rolled back to 0026 and upgraded with this revised migration; merely running
upgrade on an already stamped DB does not add the column. Reconcile the shared
adapter/deadline tests with
`bfc5e80783e5dca99dcc32c81cc518fec68770df`; no access-request changes belong here.
