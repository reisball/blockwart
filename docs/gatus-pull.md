# Gatus Pull Adapter (provider="gatus")

The Gatus pull adapter is the **preferred source** of the #177 feature: it
reads the **current Gatus status data** from the Gatus status API instead of
waiting for push webhooks. The optional push webhook (see
[`gatus-webhook.md`](gatus-webhook.md)) is a low-latency signal on top of this
polling source.

## How It Works

A service configured with `provider="gatus"` is driven by the built-in
database-backed scheduler, exactly like `provider="builtin_http"`. On each due
check the adapter:

1. resolves the Gatus status API URL (`data.monitoring.gatus.source_url`);
2. validates the resolved address against the deny-by-default outbound policy
   (the same SSRF controls as the built-in probe);
3. sends a bounded, authenticated `GET` to the Gatus status API;
4. finds the endpoint whose `name`/`group` match the service's Gatus mapping;
5. reads the **latest** result's `success` flag and stores a canonical
   observation (`healthy` or `down`).

## Configuration

Each service that should pull from Gatus declares its monitoring document with
a `gatus` sub-document:

```json
{
  "monitoring": {
    "enabled": true,
    "provider": "gatus",
    "interval_seconds": 300,
    "gatus": {
      "source_url": "https://gatus.example.com/api/v1/endpoints/statuses",
      "endpoint": "api-gateway",
      "group": "core"
    }
  }
}
```

- `source_url` (**required**) is the Gatus **status API** URL. It must be an
  `http(s)` URL that the outbound allowlist permits. A missing or malformed
  URL yields the `missing_gatus_source` / `invalid_gatus_source_url`
  diagnostic and no probe.
- `endpoint` (**required**) and `group` (optional) identify which Gatus
  endpoint this service maps to. They must match the `name` and `group` in the
  Gatus statuses payload.

The API token is **not** stored in catalog data. It is read from the process
environment variable `BLOCKWART_GATUS_TOKEN` and sent as a `Bearer` header.
Without a token the adapter still attempts an unauthenticated request; Gatus
endpoints behind the protected API routes will reject it (the adapter reports
`check_error`).

## Result Semantics

| Gatus latest result `success` | Blockwart observation state |
|-------------------------------|-----------------------------|
| `true`                        | `healthy`                   |
| `false`                       | `down`                      |
| endpoint not found / malformed payload | `check_error` (`invalid_target`) |
| Gatus API non-2xx             | `check_error` (`http_client_error` / `http_server_error`) |
| network / DNS / timeout       | `down` (redacted code)      |

## Security

- The target is resolved and pinned by the domain before any connection; this
  adapter never scans a URL, port, or path and never follows a redirect.
- Every resolved address is validated against the deny-by-default allowlist.
- Connect and total time, response size, and header count are bounded; the
  JSON body is read once up to a fixed cap and discarded after parsing.
- The API token never appears in catalog data, logs, or the OpenAPI contract.

## Relationship to the #135 Observation Model

The pull adapter writes through the same `record_service_observation()` seam as
the built-in probe and the push webhook, so it inherits freshness, maintenance
precedence, and the shared read model without duplicating them.
