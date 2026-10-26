# Config

Blockwart configuration uses environment variables prefixed with `BLOCKWART_`.

## Server settings

This is the environment-variable reference for `blockwart.config.Settings`.
Defaults apply when unset; numeric bounds are inclusive (`ge`/`le`), and
`min_length`/`max_length` bound string length. Set the database URL explicitly
for a deployment. For units, use the variable suffix (`_MS`, `_SECONDS`, `_BYTES`).
The MCP wrapper has separate [client settings](mcp.md#configuration).

| Environment variable | Default | Bounds | Purpose |
| --- | --- | --- | --- |
| `BLOCKWART_ENV` | `"dev"` | — | Environment label. |
| `BLOCKWART_BUILD_REVISION` | `"unknown"` | min_length=1, max_length=128 | Build or Git revision exposed by health endpoints. |
| `BLOCKWART_DATABASE_URL` | `"sqlite:///./blockwart.sqlite3"` | — | SQLAlchemy database URL; explicitly set this for an instance. |
| `BLOCKWART_SQLITE_BUSY_TIMEOUT_MS` | `5000` | ge=100, le=60000 | Maximum SQLite lock wait in milliseconds. |
| `BLOCKWART_SQLITE_WAL_ENABLED` | `true` | — | Enable WAL journal mode for persistent SQLite databases. |
| `BLOCKWART_SECRET_REFERENCE` | `"local-dev-placeholder"` | — | Reference label only; never a secret value. |
| `BLOCKWART_SCHEMA_OVERRIDES_PATH` | `""` | — | Optional JSON file for UI schema metadata overrides. |
| `BLOCKWART_AUTH_SESSION_TTL_SECONDS` | `3600` | ge=300, le=3600 | Absolute lifetime of an authenticated browser session. |
| `BLOCKWART_AUTH_REMEMBER_SESSION_TTL_SECONDS` | `2592000` | ge=86400, le=7776000 | Absolute lifetime of a browser session issued with the opt-in 'keep me signed in' choice. Server-selected and never sliding. |
| `BLOCKWART_AUTH_LOGIN_CHALLENGE_TTL_SECONDS` | `600` | ge=60, le=3600 | Lifetime of a one-time pre-authentication CSRF challenge. |
| `BLOCKWART_AUTH_LOGIN_RATE_WINDOW_SECONDS` | `60` | ge=10, le=3600 | Fixed window for per-process login and challenge throttles. |
| `BLOCKWART_AUTH_LOGIN_SOURCE_ATTEMPT_LIMIT` | `10` | ge=1, le=1000 | Password attempts accepted per source and rate window. |
| `BLOCKWART_AUTH_LOGIN_ACCOUNT_ATTEMPT_LIMIT` | `5` | ge=1, le=1000 | Password attempts accepted per account fingerprint and rate window. |
| `BLOCKWART_AUTH_LOGIN_GLOBAL_ATTEMPT_LIMIT` | `60` | ge=1, le=10000 | Password attempts accepted by one app process and rate window. |
| `BLOCKWART_AUTH_LOGIN_SOURCE_CHALLENGE_LIMIT` | `30` | ge=1, le=10000 | Login challenges issued per source and rate window. |
| `BLOCKWART_AUTH_LOGIN_GLOBAL_CHALLENGE_LIMIT` | `120` | ge=1, le=100000 | Login challenges issued by one app process and rate window. |
| `BLOCKWART_AUTH_PASSWORD_MAX_CONCURRENCY` | `2` | ge=1, le=16 | Maximum concurrent Argon2 password checks per app process. |
| `BLOCKWART_AUTH_SECURITY_EVENT_RETENTION_DAYS` | `90` | ge=1, le=3650 | Maximum age of retained security events. |
| `BLOCKWART_AUTH_SECURITY_EVENT_MAX_ROWS` | `100000` | ge=1000, le=10000000 | Maximum retained security-event rows after periodic pruning. |
| `BLOCKWART_AUTH_SERVICE_TOKEN_RATE_WINDOW_SECONDS` | `60` | ge=10, le=3600 | Shared fixed window for failed service-token authentication. |
| `BLOCKWART_AUTH_SERVICE_TOKEN_GLOBAL_FAILURE_LIMIT` | `300` | ge=1, le=100000 | Failed service-token attempts accepted globally per window. |
| `BLOCKWART_AUTH_SERVICE_TOKEN_SOURCE_FAILURE_LIMIT` | `30` | ge=1, le=10000 | Failed service-token attempts accepted per source per window. |
| `BLOCKWART_AUTH_SERVICE_TOKEN_FINGERPRINT_FAILURE_LIMIT` | `10` | ge=1, le=1000 | Failed attempts accepted per opaque-token fingerprint per window. |
| `BLOCKWART_AUTH_SERVICE_TOKEN_FAILURE_BUCKET_MAX_ROWS` | `10000` | ge=100, le=1000000 | Maximum retained shared service-token failure buckets. |
| `BLOCKWART_AUTH_SERVICE_TOKEN_FAILURE_BUCKET_PRUNE_INTERVAL_SECONDS` | `60` | ge=10, le=3600 | Amortized request-path interval for pruning failure buckets. |
| `BLOCKWART_AUTH_TRUSTED_PROXY_CIDRS` | `""` | max_length=4096 | Comma-separated proxy IP networks trusted to supply one forwarded source. |
| `BLOCKWART_IDEMPOTENCY_TTL_SECONDS` | `86400` | ge=300, le=604800 | Retention and replay window for create-command idempotency keys. |
| `BLOCKWART_PROJECT_GITHUB_SYNC_ENABLED` | `false` | — | Allow explicit opt-in GET-only project GitHub observations. |
| `BLOCKWART_PROJECT_GITHUB_CREDENTIAL_FILES` | `{}` | — | Operator-approved project-instance/repository-record/GitHub-id/credential-reference to protected token-file mapping. |
| `BLOCKWART_MONITORING_POLLER_ENABLED` | `false` | — | Whether this deployment may run built-in service health checks. |
| `BLOCKWART_MONITORING_DEFAULT_INTERVAL_SECONDS` | `300` | ge=60, le=86400 | Server-wide check interval for services without an override. |
| `BLOCKWART_MONITORING_ALLOWED_TARGET_NETWORKS` | `""` | max_length=4096 | Comma-separated IP networks a health check may connect to. Empty denies every target. |
| `BLOCKWART_MONITORING_ALLOWED_TARGET_PORTS` | `"80,443"` | max_length=1024 | Comma-separated ports a health check may connect to. |
| `BLOCKWART_MONITORING_CONNECT_TIMEOUT_MS` | `2000` | ge=100, le=15000 | Maximum time one health check may spend connecting. |
| `BLOCKWART_MONITORING_TOTAL_TIMEOUT_MS` | `5000` | ge=200, le=30000 | Maximum total time one health check may take. |
| `BLOCKWART_MONITORING_MAX_RESPONSE_BYTES` | `65536` | ge=1024, le=1048576 | Response size bound: builtin_http reads no body; Gatus may parse a bounded body but never stores the raw response. |
| `BLOCKWART_MONITORING_MAX_CHECKS_PER_RUN` | `20` | ge=1, le=1000 | Maximum due checks one scheduler run may claim. |
| `BLOCKWART_MONITORING_MAX_CONCURRENT_CHECKS` | `4` | ge=1, le=32 | Maximum health checks executed in parallel by one process. |
| `BLOCKWART_MONITORING_LEASE_SECONDS` | `60` | ge=10, le=3600 | Lifetime of one database-backed check lease. |
| `BLOCKWART_MONITORING_JITTER_SECONDS` | `30` | ge=0, le=3600 | Maximum deterministic scheduling jitter. |
| `BLOCKWART_MONITORING_POLL_INTERVAL_SECONDS` | `5` | ge=1, le=60 | How often each web process looks for due database leases. |
| `BLOCKWART_MONITORING_GATUS_SOURCES` | `""` | max_length=4096 | Comma-separated name=status-url bindings for Gatus pull sources. Catalog data may only name one of these identities; it can never choose a URL. Empty denies every Gatus check. |
| `BLOCKWART_MONITORING_GATUS_CREDENTIAL_FILES` | `""` | max_length=4096 | Comma-separated name=file bindings. The file holds one API token for exactly that Gatus source and is read at check time; the value is never stored, projected, or logged. Never a token value. |
| `BLOCKWART_RELEASE_MONITORING_ENABLED` | `false` | — | Master switch for outbound public GitHub release checks, including authorized manual checks. Disabled by default. |
| `BLOCKWART_RELEASE_MONITORING_POLLER_ENABLED` | `false` | — | Whether this deployment schedules periodic release checks. |
| `BLOCKWART_RELEASE_MONITORING_DEFAULT_INTERVAL_SECONDS` | `86400` | ge=3600, le=604800 | Daily-by-default release check interval without a service override. |
| `BLOCKWART_RELEASE_MONITORING_CONNECT_TIMEOUT_MS` | `2000` | ge=100, le=15000 | Maximum connection time for a release request. |
| `BLOCKWART_RELEASE_MONITORING_TOTAL_TIMEOUT_MS` | `5000` | ge=200, le=30000 | Maximum total release-request deadline. |
| `BLOCKWART_RELEASE_MONITORING_MAX_RESPONSE_BYTES` | `524288` | ge=1024, le=524288 | Maximum GitHub latest-release response body accepted. |
| `BLOCKWART_RELEASE_MONITORING_MAX_CHECKS_PER_RUN` | `10` | ge=1, le=100 | Maximum release checks claimed in one run. |
| `BLOCKWART_RELEASE_MONITORING_LEASE_SECONDS` | `60` | ge=10, le=3600 | Database-backed release lease; includes the timeout safety margin below. |
| `BLOCKWART_RELEASE_MONITORING_JITTER_SECONDS` | `3600` | ge=0, le=21600 | Maximum deterministic release scheduling jitter. |
| `BLOCKWART_RELEASE_MONITORING_POLL_INTERVAL_SECONDS` | `30` | ge=5, le=300 | Interval between due-release scheduling passes. |

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
and port allowlists. Gatus additionally requires an exact runtime source
binding; a missing, duplicate, malformed, or unmatched binding fails closed.
Credential values are not settings values and must never be placed in `.env`.
A service's optional interval overrides only the server
default; it never changes timeout, concurrency, or target policy. See
[Service monitoring](service-monitoring.md).

Release monitoring has separate disabled-by-default runtime switches and a
fixed public GitHub target; it does not reuse the health target allowlist or
health observations. See [Public GitHub release monitoring](release-monitoring.md).

Service-token audience is credential metadata, not environment configuration.
`blockwart-auth issue-token --audience api|mcp` and the equivalent protected
admin operations select it server-side. Existing tokens migrate as `api`; a
writer using channel-sensitive MCP commands needs an `mcp`-audience token;
see the [audience contract](auth-rbac.md). The MCP
wrapper still receives only that opaque value through its protected token file.

## Timeouts and leases

For both service and release monitoring, connect timeout must not exceed total
timeout. The exact lease rule is `lease_seconds * 1000 >= total_timeout_ms + 1000`:
a one-second acquisition safety margin is mandatory. For example, a 20-second
lease does not cover a 19,500 ms total timeout. Invalid combinations fail startup.

## Project GitHub observations

`BLOCKWART_PROJECT_GITHUB_SYNC_ENABLED` defaults to `false`. Explicit manual
`sync_github` also requires the repository record's `sync_enabled=true` and stable
numeric GitHub repository ID. This is separate from public service-release
monitoring; it is neither a scheduler nor permission to write to GitHub.

`BLOCKWART_PROJECT_GITHUB_CREDENTIAL_FILES` is a JSON object, not a
comma-separated list. Each key binds an immutable Project instance, repository
record UUID, numeric upstream repository ID and exact credential reference to
one protected runtime token file. Example shape (replace all identifiers and
paths with approved bindings):

```json
{
  "11111111-1111-4111-8111-111111111111/22222222-2222-4222-8222-222222222222/12345/credential_reference:github-read": "/run/secrets/project-github-token"
}
```

Store that JSON mapping in the environment setting, not the token contents.
There is no global-reference fallback. Recreated Projects, another repository
record, retargeted GitHub ID or changed reference require a new exact binding.
Catalog reference readability is necessary but not authority to read a secret;
the operator binding provides that separate boundary. A required missing or
unreadable token file fails closed. With no credential reference, access is
explicitly anonymous/public-only. See [Project management](project-management.md).

## Example Seed Import

The example catalog seed lives at `seeds/pilot_objects.yaml`. Its hostnames,
addresses, identities, and credential references are fictional. Use the
packaged CLI only after database migration and creation of the existing active
owner principal. `--create-schema` migrates the schema; it does **not** create
that identity. Follow the ordered [local bootstrap](deployment.md#local-package-run)
first, then use the chosen owner login:

```bash
blockwart-seed --create-schema --seed seeds/pilot_objects.yaml --owner-login example-owner
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
