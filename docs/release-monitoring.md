# Public GitHub release monitoring

Blockwart can opt one service into observing the latest stable full release of
one public GitHub repository. It compares that observation only with the
manually maintained `data.service_information.running_version`. The feature
never reads `installed_software`, free `sources`, hosts, containers, package
managers, or deployment APIs, and it never changes a running version or starts
an installation, download, restart, deployment, rollback, notification, or
agent action.

## Service configuration

The service document is closed and absent by default:

```json
{
  "release_monitoring": {
    "enabled": true,
    "provider": "github_releases",
    "interval_seconds": 86400,
    "github": {
      "owner": "example-org",
      "repo": "example-service"
    }
  }
}
```

`enabled` is required whenever the document exists. `provider` defaults to the
only v1 provider, `github_releases`. The interval override is optional and may
be 3600 through 604800 seconds; the deployment default is one day. Owner and
repository are validated as bounded GitHub path segments. No host, scheme,
port, URL, API path, token, private-repository flag, prerelease channel, draft
channel, raw-tag source, or credential reference is expressible. Existing free
`data.sources` remain inert catalog text.

Configuration writes use the ordinary service command: object `write`, CSRF in
the browser, strong ETag/CAS, schema and secret rejection, revision change, and
one object audit entry. Checks do not use that command and never change the
catalog row, revision, business `updated_at`, provenance, or object audit.

## Provider and comparison contract

The provider sends one unauthenticated HTTPS `GET` to exactly
`api.github.com:443/repos/{owner}/{repo}/releases/latest`, using GitHub's
versioned REST media contract. It does not use environment proxies or redirects
and does not retry inside one run. DNS is resolved once; every answer must be a
public, non-special address, and the selected address is pinned while TLS SNI
and certificate validation remain bound to `api.github.com`. Connect and total
deadlines, header count and size, body size, response encoding, User-Agent, and
accepted JSON fields are fixed and bounded.

An accepted result must be HTTP 200 JSON with one bounded `tag_name`,
`draft=false`, `prerelease=false`, and a valid `published_at`. Blockwart stores
only tag, normalized comparison value, publish time, ETag, HTTP status, stable
error code, failure count, and check/schedule times. It neither stores nor
renders release name, notes, author, assets, upstream URLs, response bodies, or
exception text. The displayed repository and release links are reconstructed
from validated identity and tag segments.

The only normalization removes one leading `v` or `V` when followed by a
digit. Equality after that normalization is `current`. Ordering is attempted
only when both values are one to four numeric dotted components; a greater
observed value is `update_available`, and an equal or lower one is `current`.
SemVer prerelease/build precedence, named CalVer variants, channels, and other
tags are not guessed and remain `unknown`. Numeric date-like versions such as
`2026.08` are comparable by the same explicitly numeric rule.

The public states are `current`, `update_available`, `unknown`, and `error`.
Pending or stale evidence and any non-comparable value are `unknown`.
Configuration or controlled acquisition failures are `error`; they never
become service-health observations.

## Scheduling, rate limits, and manual checks

Runtime is disabled by default at two levels:

```text
BLOCKWART_RELEASE_MONITORING_ENABLED=false
BLOCKWART_RELEASE_MONITORING_POLLER_ENABLED=false
```

The master switch is required for every outbound release request. The poller
switch additionally starts the periodic due loop. Enabling either variable
does not opt in any service. This repository ships both switches false and does
not change a production allowlist or catalog.

Every service/provider observation and lease is bound to the immutable catalog
object instance. SQLite and PostgreSQL use one conditional lease update, so
manual and scheduled processes cannot check the same instance concurrently.
Checks are serial and every pass is bounded. New schedules receive stable
jitter; expired leases recover automatically. A manual UI or
`POST /api/v1/objects/{id}/release-check` request requires object `write`, uses
the same application function and lease, and observes a five-minute cooldown.

GitHub currently associates unauthenticated requests with the deployment IP
and documents 60 requests per hour. Conditional `If-None-Match` requests reuse
the stored ETag and a 304 refreshes successful evidence without replacing the
release. Because v1 deliberately sends no token, operators must still budget a
304 against the unauthenticated limit. `Retry-After` and
`X-RateLimit-Reset` only delay the next due time. Other failures use bounded
exponential schedule backoff (maximum factor eight); there is no tight retry
loop.

## Reading, authorization, and recovery

Readable service detail, REST/MCP context, `/release-updates`,
`GET /api/v1/release-updates`, and the `release_update_available` Attention
reason share one projection. Authorization is applied before evidence,
filtering, counts, ordering, and cursor construction. Discover-only stubs and
concealed objects carry no release configuration, status, count, timing, or
existence hint.

Stable acquisition codes distinguish DNS, connect, TLS, timeout, policy,
redirect, not-found, rate-limit, client/server, size, JSON and release-contract
failures. Diagnose a problem in this order:

1. leave both runtime switches false while inspecting configuration and stored
   status;
2. verify the canonical public repository and documented running version;
3. inspect the stable error code and the next due time; do not copy upstream
   response text into logs or catalog data;
4. for rate limiting, wait for the projected due time; for an expired worker,
   allow the lease to recover; for repeated 404, correct or disable the service
   instead of forcing checks;
5. enable the master switch, and the poller only if periodic execution is
   explicitly approved.

Migration `20260825_0021` adds only `service_release_observations` and
`service_release_check_leases`; it rewrites no catalog JSON and therefore opts
in no service. Downgrade removes exactly those re-derivable release/cache rows.
Stop Blockwart before a live downgrade and use the matching previous image and
verified pre-upgrade backup under the deployment rollback contract. No service
configuration is rewritten during downgrade; the previous application treats
the unknown flexible data field as inert and performs no release request.

Provider references:

- <https://docs.github.com/en/rest/releases/releases#get-the-latest-release>
- <https://docs.github.com/en/rest/using-the-rest-api/best-practices-for-using-the-rest-api>
- <https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api>
