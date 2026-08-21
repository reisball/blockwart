# Gatus Webhook Receiver

The Gatus webhook receiver is a push-based monitoring provider that ingests
[Gatus](https://github.com/TwiN/gatus) custom alert payloads into Blockwart's
canonical service observation model.

> **Scope note:** This receiver is an *optional, low-latency* push signal. It
> does **not** by itself satisfy the Gatus adapter feature request (#177),
> which additionally requires a pull adapter that polls Gatus status data as
> the preferred source. This webhook-only receiver must not close #177.

## Endpoint

```
POST /api/v1/webhooks/gatus
Authorization: Bearer <service-token>
Content-Type: application/json
```

## Payload

| Field          | Type     | Required | Description                                      |
|----------------|----------|----------|--------------------------------------------------|
| `endpoint`     | string   | yes      | Gatus endpoint name (matches `data.gatus.endpoint`) |
| `group`        | string   | no       | Gatus group label (matches `data.gatus.group`)     |
| `source`       | string   | no       | Gatus source label (matches `data.gatus.source`)   |
| `alert`        | enum     | yes      | `TRIGGERED` or `RESOLVED`                           |
| `timestamp`    | string   | no       | Optional RFC 3339 check-result timestamp            |
| `http_status`  | integer  | no       | HTTP status code from the check (100–599)           |
| `latency_ms`   | integer  | no       | Response latency in milliseconds (≥ 0)              |

`timestamp` is **optional**. Stock Gatus custom alerts expose **no
event-timestamp placeholder**, so a Gatus-configured webhook cannot send one.
When `timestamp` is absent the receiver uses the server receive time as the
observation's `checked_at`.

## Configuring Gatus

To wire a Gatus custom alert to this receiver, configure the **Custom**
alerting provider with the actual Gatus placeholders. Stock Gatus supports
these placeholders in the custom provider's body and URL:

- `[ENDPOINT_NAME]` — the endpoint name (maps to `data.gatus.endpoint`)
- `[ENDPOINT_GROUP]` — the endpoint group (maps to `data.gatus.group`)
- `[ALERT_TRIGGERED_OR_RESOLVED]` — `TRIGGERED` or `RESOLVED` (maps to `alert`)
- `[ENDPOINT_URL]`, `[RESULT_ERRORS]`, `[RESULT_CONDITIONS]`, `[ALERT_DESCRIPTION]`

There is **no `[SOURCE]`** and **no `[TIMESTAMP]`** placeholder. If you need a
`source` value, send it as a fixed header (e.g. `X-Gatus-Source: prod`) — or
omit it and rely on `endpoint` + `group` alone.

Example Gatus endpoint alert configuration:

```yaml
alerting:
  custom:
    url: "https://blockwart.example.com/api/v1/webhooks/gatus"
    method: POST
    body: |
      {"endpoint":"[ENDPOINT_NAME]","group":"[ENDPOINT_GROUP]","alert":"[ALERT_TRIGGERED_OR_RESOLVED]"}
    headers:
      Authorization: "Bearer <service-token>"
```

Because Gatus cannot send a timestamp, the receiver stamps the observation
with its own receive time. Two alerts for the same endpoint within one receive
moment therefore arrive with the same `checked_at`; the second is treated as a
duplicate and reports `ingested=false`.

## Service Mapping

Each service that should receive Gatus observations declares a `data.gatus`
mapping document in its catalog record:

```json
{
  "gatus": {
    "endpoint": "api-gateway",
    "group": "core",
    "source": "prod"
  }
}
```

- `endpoint` is **required** and must match the Gatus payload exactly.
- `source` and `group` are optional. When declared, they must match the
  payload. When absent, any payload value for that field is accepted.
- The mapping is **case-sensitive** and **exact**.

If zero **authorized** services match → **404** (fail-closed, no write).
If more than one authorized service matches → **409** (ambiguous mapping, no
write). Ambiguity is measured only over services the caller can *see*; a
concealed second mapping never leaks its existence or cardinality.

## Observation State Mapping

| Gatus alert  | Blockwart state |
|--------------|-----------------|
| `TRIGGERED`  | `down`          |
| `RESOLVED`   | `healthy`       |

## Idempotency and Replay Handling

The receiver derives `checked_at` from the payload `timestamp` when present,
otherwise from the server receive time. The ingestion seam
(`record_service_observation`) has an `on_conflict_do_update` guard that
rejects observations with an older `checked_at` than the stored value.

- **Duplicate payloads** (same `checked_at`) do not overwrite and report
  `ingested=false`.
- **Stale replays** (older `checked_at` after a newer one) are rejected and
  report `ingested=false`.
- **Out-of-order deliveries** are handled by the same guard.

A delivery reports `ingested=true` **only** when it actually inserted or
advanced a row. A duplicate or stale replay that the guard rejected reports
`ingested=false` even though an observation row exists for the service.

A timestamp that lies more than 300 seconds ahead of the receiver's receive
time is rejected with **422** — a single far-future event must not pin the
provider row and starve later legitimate observations.

## What Is NOT Persisted

The receiver deliberately does not persist:

- Alert descriptions or error text
- Response bodies
- Gatus internal metadata

Only the canonical observation fields are stored: `state`, `http_status`,
`latency_ms`, and `checked_at`.

### Gatus Reports Binary State Only

Gatus custom alerts produce only two states: `TRIGGERED` (down) and
`RESOLVED` (healthy). Gatus does not transmit error details, DNS failures,
or timeout reasons through the webhook — those are internal to Gatus and
not part of the alert payload.

Consequence: every Gatus failure (DNS error, connection refused, timeout,
TLS error, etc.) collapses to `state=down`. The `check_error` and
`error_code` observation fields are **never set** by the Gatus adapter.
If detailed error information is needed, inspect the Gatus dashboard or
logs directly.

## Authorization and Concealment

The webhook uses the standard Blockwart service-token authentication
(`require_api_read_access`). The token must have at least `DISCOVER`
permission on the target service.

Concealment: target resolution runs against the caller's read access, so an
unauthenticated token, a token that names an unknown endpoint, and a token
without authorization over a matching service all receive the **same 404**.
No response distinguishes a hidden mapping from a missing one, so the
endpoint cannot be used as an existence oracle.

## Maintenance Precedence

The webhook writes observations only — it never touches
`catalog_objects.health`. An operator's manual `maintenance` health
setting is therefore preserved. The observation state is still recorded
and visible in the monitoring view, but the effective health remains
`maintenance` until the operator clears it.

## Relationship to the #135 Observation Model

The Gatus receiver is the first push-based provider on the #135 contract:

- **Provider identity:** `provider="gatus"`, `polling=False`
- **Ingestion seam:** `record_service_observation()` — the same function
  the built-in HTTP poller uses
- **No catalog mutation:** observations are stored in
  `service_observations`, not in `catalog_objects`
- **No comments:** no audit events, no comment spam
- **Provider-neutral read model:** the monitoring projection surfaces
  Gatus observations through the same `monitoring_view()` as every other
  provider
