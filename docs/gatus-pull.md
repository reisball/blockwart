# Gatus pull adapter (`provider="gatus"`)

The Gatus adapter reads current endpoint evidence from a deployment-bound
Gatus status API. It uses the same provider-neutral observation, freshness,
maintenance, REST, Agent, MCP, UI, attention, revision, and audit contracts as
the built-in HTTP provider.

## Service identity

Catalog data contains only a closed, bounded identity:

```json
{
  "monitoring": {
    "enabled": true,
    "provider": "gatus",
    "interval_seconds": 300,
    "gatus": {
      "source": "prod",
      "group": "core",
      "endpoint": "api-gateway"
    }
  }
}
```

`source` is a stable lowercase deployment identity, not a URL. `group` is
required and may be empty to select an ungrouped Gatus endpoint. `endpoint` is
the exact Gatus endpoint name. Extra, partial, URL-shaped, credential-shaped,
or over-bound fields are rejected. The service UI edits and round-trips all
three fields, including while another provider is selected.

## Runtime source registration

An operator binds each source identity to one immutable, validated status URL:

```dotenv
BLOCKWART_MONITORING_GATUS_SOURCES=prod=https://gatus.example.invalid/api/v1/endpoints/statuses
BLOCKWART_MONITORING_GATUS_CREDENTIAL_FILES=prod=/protected/runtime/gatus-prod-token
```

The registry accepts at most eight exact `name=value` bindings. Source names
must be unique; credential-file names must match a declared source; paths must
be absolute; and every URL must pass the bounded HTTP(S) admission rule.
Malformed, duplicate, or cross-source declarations stop startup. A catalog
service cannot provide or override a URL, and there is no default or fallback
source.

The credential-file setting contains a path, never a credential. Its bounded
value is read at acquisition time, attached only to that source's request, and
never stored, projected, logged, placed in an exception, or included in
OpenAPI. A declared but missing, unreadable, empty, oversized, or invalid
credential file fails closed without sending an anonymous request. Omit the
credential-file binding only for a deliberately unauthenticated source.

## Selection and time semantics

On each ordinary due check the adapter reads the bound status API and selects
exactly one entry by `group` plus endpoint `name`. Zero matches are missing;
multiple matches are ambiguous. Inside that entry it chooses the latest valid
result by its aware RFC 3339 `timestamp`, independent of list order. Results
that disagree at the same latest timestamp are ambiguous.

A matched `success=true` maps to `healthy`; `success=false` maps to `down`.
Only canonical bounded HTTP status and latency values are retained. Upstream
payload fields never enter a public projection.

The result timestamp is `last_checked_at`: the instant the evidence is about.
`last_received_at` is the separate server acquisition instant. Re-reading an
unchanged or older snapshot advances acquisition cadence but cannot replace
evidence, refresh freshness, change state/latency/status, or move last success.
This keeps old evidence stale without creating a tight polling loop. Invalid,
naive, or materially future-skewed timestamps are rejected.

## Failure and network semantics

DNS, connect, TLS, timeout, HTTP, framing, size, parse, and mapping failures are
source-acquisition `check_error` results. They project effective `unknown` and
never claim that the monitored service is down. Only a valid matched Gatus
result can produce `healthy` or `down`.

The deployment allowlist is still deny-by-default. Every DNS answer is policy
checked, one permitted address is pinned for the socket, and the original host
remains the HTTP Host and TLS SNI/certificate identity. The client follows no
redirect, uses no proxy, closes every connection, and bounds DNS, connect,
total time, response headers, body bytes, endpoint results, and credential
bytes. Errors are stable redacted codes.

See [Service monitoring](service-monitoring.md) for the shared observation and
scheduling contract.
