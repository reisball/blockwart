# Agent Notices: Delivering Blockwart Events To Agents (Issue #106)

Blockwart can surface information to humans in UI, REST, and MCP, but agents
learn about relevant events only by polling. Agent notices add a narrow,
auditable push channel for selected events. The first supported event is the
release-monitoring signal `release_update_available` — deliberately reusing
the shipped attention vocabulary from #105 instead of the issue draft's
`service_release_update_available`, so events, attention reasons, and notices
speak one language.

## Model

- **Event** (`agent_notice_events`): one deduplicated logical occurrence with
  a stable public id and a `dedupe_key`. Repeated emission of the same logical
  occurrence (retry, process restart) is a no-op.
- **Target** (`agent_delivery_targets`): one approved destination bound to one
  active service-account principal. Targets carry no credential material.
- **Subscription** (`agent_notice_subscriptions`): an explicit, revocable
  routing rule between event/object scope and a target. Only platform
  administrators create them; both ends are validated (active service-account
  principal, active target owned by that principal).
- **Job** (`agent_delivery_jobs`): exactly one per `(event, target)` pair,
  enforced by a unique constraint. States: `pending`, `delivered`, `failed`
  (dead-letter), `suppressed`, `expired`, `acknowledged`.
- **Attempts** (`agent_delivery_attempts`): redacted audit with coarse
  outcomes only — no payload, prompt, token, session, or URL content.

## Delivery Safety Contract

1. **Re-authorization before every attempt.** Directly before each delivery,
   Blockwart re-checks: target active, principal active and of type service
   account, at least one non-revoked non-expired service token (activity),
   subscription still active, object exists, and current `read` permission on
   the object via the normal policy snapshot. Any miss fails closed: the job
   becomes `suppressed` with a safe code (`target_inactive`,
   `principal_inactive`, `subscription_revoked`, `read_permission_lost`) and
   nothing leaves Blockwart — not even an existence hint.
2. **At-most-once visible semantics.** Only `pending` rows are retried;
   delivered rows are never re-pinged regardless of retry idempotence
   upstream. Retries of the same job reuse its stable payload.
3. **Bounded retries, TTL, dead-letter.** Failures schedule exponential
   backoff (base 30 s, cap 1 h, max 5 attempts by default). Past TTL the job
   becomes `expired`; after the attempt limit it becomes `failed`. Both are
   terminal and diagnosable through admin reads.
4. **Storm protection.** Fan-out refuses more than 20 pending jobs per target:
   excess jobs are created directly as `suppressed` with code
   `storm_suppressed` instead of queueing an unbounded burst. A delivery pass
   also processes at most 50 jobs per run.
5. **Data minimization.** The payload schema is closed:
   `{schema_version, event_type, event_id, object_ref, message,
   blockwart_reference}`. The message comes from one fixed template built
   only from the visible object label and the already URL-safe validated tag.
   Release notes, titles, HTML/Markdown bodies, upstream URLs, error strings,
   secrets, and hidden object details never enter payloads, prompts, or audit.
6. **Acknowledge ≠ business action.** Only the owning agent principal can
   acknowledge a `delivered` notice. Acknowledgement records receipt only; it
   grants no approval, extends no grants, and triggers no update or deploy.
7. **Fail-closed reads.** `/api/v1/notices` hides notices for objects on
   which the caller currently lacks `read` permission.

## Transport Adapter Contract

A transport receives one data-minimized payload per job and answers with a
coarse outcome (`ok`, or `transport_timeout` / `transport_unavailable` /
`rate_limited`). There are no freely configurable callback URLs:

- `FakeNoticeTransport`: deterministic in-memory transport for tests.
- `OpenClawTestGatewayTransport`: the first OpenClaw route, hard-bound at
  construction time to a loopback HTTP test endpoint (non-loopback targets
  raise `TransportConfigError`). It proves the full pipeline against an
  isolated fake gateway; CI requires no productive gateway, agent turn,
  network path, or credential. Productive transports need their own design
  and approval round.

Delivery is driven by a built-in application poller. When
`BLOCKWART_NOTICE_DELIVERY_POLLER_ENABLED=true` and a loopback
`BLOCKWART_NOTICE_DELIVERY_ENDPOINT_URL` are configured, the FastAPI lifespan
runs `run_notice_delivery_poller()` on a bounded interval
(`BLOCKWART_NOTICE_DELIVERY_POLL_INTERVAL_SECONDS`, default 30, minimum 5) and
delivers at most `BLOCKWART_NOTICE_DELIVERY_MAX_PER_RUN` due jobs per pass. Each
pass atomically claims due jobs with a bounded lease (`lease_seconds`, default
60): only the lease holder delivers a job, an expired lease makes the job
claimable again (crashed-worker recovery), and every payload carries the
stable `delivery_id` idempotency key plus the non-secret `target` route that
lets one gateway address separate agent destinations. Operators may still call
`deliver_due_agent_notices(session, transport, now=...)` manually with the
same claim semantics.

## REST Surface

Agent-scoped (bearer service-token auth):

- `GET /api/v1/notices` — own notices plus delivery state, fail-closed.
- `POST /api/v1/notices/{event_id}/acknowledge` — receipt confirmation.

Platform-admin scoped:

- `POST /api/v1/admin/notices/targets` — approve a destination.
- `DELETE /api/v1/admin/notices/targets/{id}` — revoke a destination.
- `GET /api/v1/admin/notices` — list subscriptions.
- `POST /api/v1/admin/notices/subscriptions` — create routing rule.
- `DELETE /api/v1/admin/notices/subscriptions/{id}` — revoke routing.
- `GET /api/v1/admin/notices/jobs?status=` — redacted diagnostics over all
  six states without any transport details.

## Operational Runbook

- **Enable:** create target + subscription as platform admin (above); the
  next matching release observation fans out automatically.
- **Rotate/revoke:** revoke the principal's service tokens (activity check
  suppresses deliveries immediately), deactivate the target, or revoke the
  subscription; all three suppress pending work fail-closed.
- **Dead-letter recovery:** inspect `GET /api/v1/admin/notices/jobs` for
  `failed` rows and their safe `last_error_code`; fix the cause, then emit a
  fresh logical event (a new version observation) — failed jobs are terminal
  by design and never replay silently.
- **Full channel shutdown:** deactivate every target; pending jobs suppress
  on their next due pass, fan-out creates suppressed-only jobs.

## Deliberate Scope Boundaries And Follow-Ups

- No Telegram/e-mail delivery to humans (per issue out-of-scope).
- Retry/TTL/storm knobs live in `NoticeDeliveryPolicy` code defaults;
  exposing them as environment settings is a follow-up.
- A management/diagnostics UI page and a dedicated MCP read tool are
  follow-ups; the authorized machine read exists as REST today.
