# Service Interfaces

Blockwart keeps three related concepts separate:

- An **endpoint** is a usable service capability such as Web, REST API, MCP,
  HEC, SSH, SMB, a database listener, S2S, metrics, a webhook, or generic
  HTTP/TCP/UDP.
- A **port** is only a technical listener that cannot yet be represented as a
  complete endpoint. A port already present on an endpoint is not stored a
  second time in the normalized view.
- An **access method** describes administrative access. It references an
  endpoint by stable `endpoint_id` and may carry authentication mode,
  credential-reference IDs, and operating notes. Credential values never
  belong in Blockwart.

## Canonical endpoint

Each normalized endpoint has:

| Field | Meaning |
|---|---|
| `id` | Stable object-local identifier |
| `type` | Capability from the built-in vocabulary or an `x-...` extension |
| `label` | Optional human label |
| `url` or `host` | Reachable address |
| `port` | Optional integer from 1 through 65535 |
| `protocol` | Application protocol such as `https`, `ssh`, or `smb` |
| `transport` | Exactly `tcp` or `udp` |
| `path` | Optional application path |
| `exposure` | `loopback`, `lan`, `vpn`, `internal`, `public`, or `unknown` |
| `health_url` | Optional health target |

For an opted-in service, exactly one explicit canonical `health_url` takes
precedence. Without one, monitoring derives `/health` only from exactly one
complete canonical HTTP(S) endpoint origin and port. Ambiguous or incomplete
records remain visible diagnostics and never trigger discovery. See
[Service monitoring](service-monitoring.md).

The built-in endpoint types are Web, REST API, MCP, HEC, SSH, SMB, Database,
S2S, Metrics, Webhook, HTTP, TCP, and UDP. Missing legacy types are derived
only when the protocol proves the capability. An HTTP URL without a declared
business capability becomes generic `HTTP`; it is never guessed to be Web,
REST, metrics, or a webhook.

A service with endpoints has `interface.state=available`. A known internal
worker with `endpoint_required=false` becomes `not_applicable`. Every other
service without an endpoint is explicitly `incomplete`.

## Read and write compatibility

The domain normalizer is pure and deterministic. Agent API and MCP always use
its normalized view, including endpoints promoted from legacy access methods.
Current human UI payloads remain accepted and stored unchanged until the
separate UI redesign; backend validation still runs the same contract before
each write. The compatibility `access_methods[].endpoint` value may remain
beside the canonical `endpoint_id` so existing UI reads do not break.

## Controlled data normalization

The default command is a read-only dry run:

```bash
blockwart-db interfaces
```

It reports every stable diagnostic and a summary with scanned objects, changed
objects, and diagnostic count. Apply only after reviewing that exact plan and
creating a verified database backup:

```bash
blockwart-db --apply interfaces
```

Dry run and apply build the same plan. Apply rechecks every original JSON
document, writes all changes and audit events in one transaction, and rolls
back completely if an object changed after planning or any later write fails.
Running the dry run again after a successful apply must report zero changes.

The live-data apply is a deployment operation and is deliberately not
automatic during application startup.
