# Config

Blockwart configuration uses environment variables prefixed with `BLOCKWART_`.

Current local keys:

- `BLOCKWART_ENV`
- `BLOCKWART_BUILD_REVISION` (non-secret build evidence exposed by health and MCP contract metadata)
- `BLOCKWART_DATABASE_URL`
- `BLOCKWART_SECRET_REFERENCE`
- `BLOCKWART_AUTH_SESSION_TTL_SECONDS` (default `3600`, allowed `300..3600`;
  absolute lifetime for standard human browser login)
- `BLOCKWART_AUTH_REMEMBER_SESSION_TTL_SECONDS` (default `2592000` / 30 days,
  allowed `86400..7776000`; absolute lifetime for the default-off **Keep me
  signed in** choice)
- `BLOCKWART_IDEMPOTENCY_TTL_SECONDS` (default `86400`, allowed
  `300..604800`)
- `BLOCKWART_AUTH_SERVICE_TOKEN_RATE_WINDOW_SECONDS`
- `BLOCKWART_AUTH_SERVICE_TOKEN_GLOBAL_FAILURE_LIMIT`
- `BLOCKWART_AUTH_SERVICE_TOKEN_SOURCE_FAILURE_LIMIT`
- `BLOCKWART_AUTH_SERVICE_TOKEN_FINGERPRINT_FAILURE_LIMIT`
- `BLOCKWART_AUTH_SERVICE_TOKEN_FAILURE_BUCKET_MAX_ROWS`
- `BLOCKWART_AUTH_SERVICE_TOKEN_FAILURE_BUCKET_PRUNE_INTERVAL_SECONDS`
- `BLOCKWART_AUTH_TRUSTED_PROXY_CIDRS`
- `BLOCKWART_MONITORING_POLLER_ENABLED` (default `false`)
- `BLOCKWART_MONITORING_DEFAULT_INTERVAL_SECONDS` (default `300`, allowed
  `60..86400`)
- `BLOCKWART_MONITORING_ALLOWED_TARGET_NETWORKS` (default empty; comma-separated
  explicit CIDRs, so every target is denied)
- `BLOCKWART_MONITORING_ALLOWED_TARGET_PORTS` (default `80,443`)
- `BLOCKWART_MONITORING_CONNECT_TIMEOUT_MS` (default `2000`, allowed
  `100..15000`)
- `BLOCKWART_MONITORING_TOTAL_TIMEOUT_MS` (default `5000`, allowed
  `200..30000`)
- `BLOCKWART_MONITORING_MAX_RESPONSE_BYTES` (default `65536`, allowed
  `1024..1048576`; response bodies are not read or stored)
- `BLOCKWART_MONITORING_MAX_CHECKS_PER_RUN` (default `20`, allowed `1..1000`)
- `BLOCKWART_MONITORING_MAX_CONCURRENT_CHECKS` (default `4`, allowed `1..32`)
- `BLOCKWART_MONITORING_LEASE_SECONDS` (default `60`, allowed `10..3600` and
  strictly longer than the total probe timeout)
- `BLOCKWART_MONITORING_JITTER_SECONDS` (default `30`, allowed `0..3600`)
- `BLOCKWART_MONITORING_POLL_INTERVAL_SECONDS` (default `5`, allowed `1..60`)

`BLOCKWART_SECRET_REFERENCE` is a reference label only. It must never contain a raw secret value.

Browser-session settings apply only to interactive human login under `/auth`.
The standard setting controls only the server-side absolute expiry; its
identity and CSRF cookies remain browser-session cookies. The remembered
setting controls the server-side absolute expiry and the matching persistent
`Max-Age` of both cookies. Neither mode slides or accepts lifetime, expiry, or
cookie-security input from the login form. Values outside the declared bounds
fail settings validation and stop startup rather than falling back.

Monitoring configuration is deny-by-default at both levels: the process poller
must be enabled and the concrete target must fall within the explicit network
and port allowlists. A service's optional interval overrides only the server
default; it never changes timeout, concurrency, or target policy. See
[Service monitoring](service-monitoring.md).

Service-token audience is credential metadata, not environment configuration.
`blockwart-auth issue-token --audience api|mcp` and the equivalent protected
admin operations select it server-side. Existing tokens migrate as `api`; an
approved MCP comment writer needs a deliberately rotated `mcp` token. The MCP
wrapper still receives only that opaque value through its protected token file.

## Example Seed Import

The example catalog seed lives at `seeds/pilot_objects.yaml`. Its hostnames,
addresses, identities, and credential references are fictional. Use the
packaged CLI for local or deployment-prep initialization:

```bash
blockwart-seed --create-schema --seed seeds/pilot_objects.yaml
```

The CLI uses `BLOCKWART_DATABASE_URL` unless `--database-url` is supplied. `--create-schema` runs
the packaged Alembic migrations through `upgrade head`; it does not bypass migrations with
`create_all()`. It can also print a database summary without importing:

```bash
blockwart-seed --summary-only
```

The same lifecycle is directly available for deployment checks:

```bash
blockwart-db upgrade
blockwart-db check
```

`check` exits non-zero unless the configured database is at the exact revision expected by the
installed application.

The seed stores credential references only; it must not contain raw passwords, tokens, private keys,
cookies, or `.env` file bodies.
