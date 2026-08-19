# Gatus Webhook Receiver

The Gatus webhook receiver is a push-based monitoring provider that ingests
[Gatus](https://github.com/TwiN/gatus) custom alert payloads into Blockwart's
canonical service observation model.

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
| `timestamp`    | string   | yes      | RFC 3339 timestamp of the check result              |
| `http_status`  | integer  | no       | HTTP status code from the check (100–599)           |
| `latency_ms`   | integer  | no       | Response latency in milliseconds (≥ 0)              |

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

If zero services match → **404** (fail-closed, no write).
If more than one service matches → **409** (ambiguous mapping, no write).

## Observation State Mapping

| Gatus alert  | Blockwart state |
|--------------|-----------------|
| `TRIGGERED`  | `down`          |
| `RESOLVED`   | `healthy`       |

## Idempotency

The receiver uses the Gatus `timestamp` as the observation's `checked_at`,
not the server's `now()`. The ingestion seam
(`record_service_observation`) has an `on_conflict_do_update` guard that
rejects observations with an older `checked_at` than the stored value.

This means:
- **Duplicate payloads** (same timestamp) do not overwrite.
- **Replays** (older timestamp after newer) are rejected.
- **Out-of-order deliveries** are handled correctly.

## What Is NOT Persisted

The receiver deliberately does not persist:
- Alert descriptions or error text
- Response bodies
- Gatus internal metadata

Only the canonical observation fields are stored: `state`, `http_status`,
`latency_ms`, and `checked_at`.

## Authorization

The webhook uses the standard Blockwart service-token authentication
(`require_api_read_access`). The token must have at least `DISCOVER`
permission on the target service. Missing or unauthorized tokens result in
401 and 403 respectively.

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