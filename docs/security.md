# Security Policy

Blockwart stores operational knowledge and credential references. It does not store credential values.

The global secret-shape validator runs before the fixed catalog object-schema
registry and cannot be disabled by a kind or field declaration. The registry
also refuses to declare raw secret/value paths; see `object-validation.md`.
Common database, cache, queue, and broker connection-string shapes are rejected
as secret-like values even when they do not visibly include a password.

Agents may read canonical records through API/MCP in the MVP. Agents must not receive raw credential values through prompts, issues, Markdown, exports, fixtures, logs, or screenshots.

Credential-reference records must keep:

- `secret_value_stored: false`
- `handling_rules.telegram_allowed: false`
- `handling_rules.markdown_secret_allowed: false`
- `handling_rules.agents_may_read_value: false`

The authentication foundation uses Argon2id password hashes, hashed opaque
browser sessions and service tokens, one-time login challenges, session-bound
CSRF validation, revocation, expiry, and a separate security-event stream.
Plaintext credential material must never enter logs, audit details, database
rows, command-line arguments, or generated documentation. See
`auth-rbac.md`.

Catalog reads are authenticated and object-authorized across UI, REST, Agent
API, and MCP. No-discover objects are concealed and discover-only objects use
a strict safe stub. Catalog and grant commands are also object-authorized.
The ETag-bound object-update preview requires effective `write` on the exact
object and applies the same concealment, validation, and strong-precondition
policy as the real update. Its bounded diff redacts secret-shaped values and
typed identities the caller cannot read before calculating either digest. A
valid or object-denied preview writes no catalog, authentication timestamp,
security-event, audit, idempotency, relationship, or sequence state and creates
no later-apply guarantee.
The known-ID batch context read (`POST /api/v1/object-contexts` and
`blockwart.get_object_contexts`) applies the same policy per requested ID:
readable objects return the full detail, discover-only objects return the
strict stub, and concealed or missing IDs return an indistinguishable
concealed placeholder carrying only the requested ID. The batch is bounded to
20 IDs, never becomes an existence oracle through status, text, counts, order,
or metadata, and performs no batch write or recursive graph expansion.
Production identity bootstrap, persistent services, and infrastructure exposure
require their dedicated rollout and approval. Browser identity, challenge, CSRF,
and clearing cookies are always `Secure`; deploy the browser surface only behind
an explicitly trusted HTTPS reverse proxy that adds HSTS.

Object comments use the same object policy and global secret detector. Their
Markdown source is stored exactly, but browser HTML is produced only through a
CommonMark parser with raw HTML disabled and an independent sanitizer. Images,
embedded media, scripts, styles, event handlers, and unsafe link schemes never
become active content. Audit and idempotency records contain comment IDs and
redacted technical metadata, never comment bodies. See `object-comments.md`.

Comment origin is authenticated provenance. A server-stored service-token
audience binds a token to `api` or `mcp` comment writes, so the client-controlled
channel header alone cannot claim MCP origin. Audience does not grant catalog
access; normal `read` and `write` policy remains mandatory.

Opt-in service monitoring is an outbound SSRF boundary. It is disabled by
default and uses an empty network allowlist by default. Every DNS answer and the
concrete pinned connection address must pass the scheme, port, and network
policy; broad public allowlists do not unlock private, loopback, link-local,
reserved, or metadata ranges. The original hostname remains bound to HTTP Host
and TLS SNI/certificate validation. The adapter follows no redirect, uses no
environment proxy, sends no credential or cookie, reads no body, and exposes
only stable redacted errors. See [Service monitoring](service-monitoring.md).
