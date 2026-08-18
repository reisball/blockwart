# Config

Blockwart configuration uses environment variables prefixed with `BLOCKWART_`.

Current local keys:

- `BLOCKWART_ENV`
- `BLOCKWART_BUILD_REVISION` (non-secret build evidence exposed by health and MCP contract metadata)
- `BLOCKWART_DATABASE_URL`
- `BLOCKWART_SECRET_REFERENCE`
- `BLOCKWART_IDEMPOTENCY_TTL_SECONDS` (default `86400`, allowed
  `300..604800`)
- `BLOCKWART_AUTH_SERVICE_TOKEN_RATE_WINDOW_SECONDS`
- `BLOCKWART_AUTH_SERVICE_TOKEN_GLOBAL_FAILURE_LIMIT`
- `BLOCKWART_AUTH_SERVICE_TOKEN_SOURCE_FAILURE_LIMIT`
- `BLOCKWART_AUTH_SERVICE_TOKEN_FINGERPRINT_FAILURE_LIMIT`
- `BLOCKWART_AUTH_SERVICE_TOKEN_FAILURE_BUCKET_MAX_ROWS`
- `BLOCKWART_AUTH_SERVICE_TOKEN_FAILURE_BUCKET_PRUNE_INTERVAL_SECONDS`
- `BLOCKWART_AUTH_TRUSTED_PROXY_CIDRS`

`BLOCKWART_SECRET_REFERENCE` is a reference label only. It must never contain a raw secret value.

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
