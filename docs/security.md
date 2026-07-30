# Security Policy

Blockwart stores operational knowledge and credential references. It does not store credential values.

The global secret-shape validator runs before the fixed catalog object-schema
registry and cannot be disabled by a kind or field declaration. The registry
also refuses to declare raw secret/value paths; see `object-validation.md`.

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

The foundation does not yet authorize catalog reads or writes. Production
identity bootstrap, removal of the legacy global admin gate, writable API/MCP
operations, persistent services, and infrastructure exposure require their
dedicated rollout and approval.
