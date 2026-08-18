# Service Monitoring

Blockwart supports opt-in per-service health observations. Monitoring is a
catalog read-model input, not a replacement for manual lifecycle management or
an infrastructure discovery system.

## Configuration and compatibility

A service may store this closed document below `data`:

```json
{
  "monitoring": {
    "enabled": true,
    "provider": "builtin_http",
    "interval_seconds": 300
  }
}
```

`enabled` is required once the document exists. `provider` defaults to
`builtin_http`; `interval_seconds` is optional and may be 60 through 86400.
When the override is absent, the current server-wide default applies (300
seconds by default). An absent document is exactly `enabled=false`. Migration
`20260818_0017` does not rewrite catalog JSON, so every existing service stays
byte-for-byte unchanged and disabled after upgrade.

All writes use the ordinary parent service command. UI writes require browser
CSRF, `write`, and the current ETag. REST and MCP use their existing `write`,
ETag/CAS, schema, secret-rejection, audit, and channel rules. Polling never
updates the catalog row, its revision, business `updated_at`, or object audit
timeline.

## Effective target

Target resolution is pure and deterministic; it never performs DNS, discovery,
port scanning, or path scanning.

1. Exactly one canonical endpoint `health_url` wins.
2. Otherwise `/health` is derived only when exactly one canonical HTTP(S)
   endpoint supplies a complete origin and port.
3. Invalid, incomplete, or ambiguous endpoints produce a stable visible
   configuration diagnostic and no acquisition adapter is called.

The service detail and the read-only `blockwart-db monitoring` plan show the
effective URL and source, or the diagnostic, before the service is enabled.
Only an unauthenticated HTTP(S) `GET` is supported. Redirects are not followed.

## Provider-neutral observations

The canonical observation is independent of acquisition. It contains the
provider identity, observed state, optional HTTP status and latency, stable
redacted error code, last check, last success, and next due time. Storage is
keyed by service object ID, immutable object-instance ID, and provider. A
deleted and recreated object ID cannot inherit an earlier instance's result;
out-of-order observations cannot replace a newer one.

`record_service_observation` is the internal ingestion seam for later adapters.
Its caller supplies both the catalog ID and the concrete immutable object-
instance ID; a delayed delivery for a deleted instance is rejected rather than
attached to a replacement row. A future push receiver such as Gatus converts
its authorized input into the same domain observation and calls that seam. It
must not add vendor payloads to the catalog or public read models. This release
implements no Gatus HTTP/API receiver; that remains issue #177.

States are normalized as follows:

- 2xx: `healthy`;
- 5xx, timeout, connection failure, DNS failure, or TLS validation failure:
  `down`;
- redirect, 4xx, invalid target, policy denial, or other bounded probe problem:
  `check_error`;
- before the first observation, or after `next_due_at`: effective `unknown`.

The last observed state stays available when stale. Manual catalog
`maintenance` always wins in the effective health display, without deleting or
hiding the observation. A diagnostic check error does not assert that the
service is down.

Readable services receive this same provider-neutral projection in the catalog
state/detail UI, REST v1, Agent context, and MCP. Discover-only stubs never
receive the configuration, target, observation, freshness, timestamps, count,
or an indication that a row exists. Concealed and absent objects retain the
existing indistinguishable behavior.

## Outbound security boundary

The target allowlist is empty by default. A check is possible only when the
deployment explicitly enables the poller and allows the concrete destination
network and port. HTTP and HTTPS are the only schemes.

Every DNS answer is checked. If any returned address is denied, the complete
target is denied. One validated address is selected deterministically and used
directly for the socket; the original hostname remains the HTTP `Host` value
and HTTPS SNI/certificate-validation identity. The client never resolves the
hostname again between validation and connection.

Loopback, link-local, private, reserved, multicast, unspecified, documentation,
benchmark, carrier-grade, unique-local, and metadata ranges stay blocked under
a broad allow such as `0.0.0.0/0`. An operator must explicitly name the
special-purpose range or a narrower subnet. Use the smallest required CIDR and
port set.

The adapter attaches no authorization, credential, cookie, or caller header;
uses no environment proxy; sends `Connection: close`; enforces bounded connect
and total deadlines plus response-header/count limits; reads no response body;
and stores no header, body, resolver text, socket text, TLS text, exception
text, or upstream error string. Public and operator results use only controlled
codes.

## Scheduling and operations

When `BLOCKWART_MONITORING_POLLER_ENABLED=true`, each web process runs a small
due-check loop. A database lease keyed by service instance permits one effective
check even with multiple web processes. Lease acquisition uses a conditional
write on both SQLite and PostgreSQL. A process performs at most the configured
checks per pass and uses bounded local worker concurrency. It commits the
catalog/lease read before network I/O. A process never claims more checks than
its worker slots, and renews each still-live lease immediately before
acquisition, so local queueing cannot let a claim expire behind another check.

New or newly selected polling configurations receive a jittered first due time.
The schedule and observations survive process restarts, so startup does not make
every enabled service immediately due. Expired leases are recoverable after a
worker failure. Configuration is re-read after claim; a disabled service,
changed provider, deleted instance, or invalid target cannot use a stale claim
to discover another target.

Inspect without writes or network traffic:

```bash
blockwart-db monitoring
```

Run one bounded due pass under the same opt-in configuration:

```bash
blockwart-db --apply monitoring
```

The apply command does not enable the poller, widen the allowlist, change a
service configuration, or force a not-yet-due check. Use it only as an
operations diagnostic while normal web polling is stopped or understood.

For an incident, first set `BLOCKWART_MONITORING_POLLER_ENABLED=false` and
restart only the affected Blockwart processes. Preserve the database and stable
logs, inspect `blockwart-db monitoring`, then correct the exact service target
or deployment allowlist. Do not widen networks to silence `policy_denied`.
Expired leases recover automatically; deleting lease or observation rows is not
a normal recovery step.

Revision `0017` adds only `service_observations` and
`service_check_leases`. Its downgrade removes only those two tables. Before a
live rollback, stop Blockwart and restore the verified pre-upgrade database with
the matching previous image according to the deployment recovery contract.
