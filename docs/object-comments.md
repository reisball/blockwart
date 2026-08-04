# Object comments

Object comments are an append-only operational timeline attached to one
specific catalog-object instance. They answer what an operator or agent did,
observed, or decided. They are deliberately separate from the object audit,
which remains the technical record of mutations.

## Data and authorization contract

Every catalog row has an internal random, unique `instance_id` retained across
ordinary updates. Every entry has a stable UUID, the object ID, instance ID,
and creation timestamp that bind it to the current object instance, plus an
immutable author snapshot, origin, format, exact source text, and RFC3339 UTC
creation time. Reusing a deleted object ID cannot expose comments from the old
instance, even if its creation timestamp collides.

- `read` is required to list comments or receive `recent_comments`.
- `write` is required to append a comment.
- Discover-only and absent objects return the normal concealed `404` on reads;
  a discoverable object without `write` returns `403` on append.
- There is no update or delete operation. SQLite triggers also reject direct
  updates and deletes.

New comments contain 1..4000 characters, are stored exactly as submitted with
`format=markdown`, and pass the shared secret detector before any write.
Whitespace-only input is rejected. UI, API, and MCP origin values are derived
from authenticated server context, not accepted in the request body.

## Markdown contract

Blockwart stores Markdown source, never generated HTML. API, MCP, and
`recent_comments` return the exact source and its format marker. The browser
renders CommonMark on the server and sanitizes it with an independent HTML
sanitizer.

Supported presentation includes headings, emphasis, lists, quotes, links,
inline code, and fenced code blocks. Raw HTML remains escaped. Images and
embedded media are removed to prevent tracking and external fetches. Links are
limited to `http`, `https`, and `mailto`, and receive
`rel="noopener noreferrer nofollow"`. Scripts, styles, event handlers, and
unsafe schemes such as `javascript`, `data`, and `file` cannot become active
markup.

## API, MCP, and UI

REST v1 exposes:

```text
GET  /api/v1/objects/{object_id}/comments
POST /api/v1/objects/{object_id}/comments
```

The list is newest-first and uses database-level keyset pagination with the
standard query-bound opaque cursor envelope. Append requires
`Idempotency-Key`; an exact replay returns `200` with `replayed=true`, while a
new entry returns `201`, a `Location` pointing to the matching UI timeline
anchor, and the new object ETag. Append does not use `If-Match`, so independent
concurrent notes do not conflict. It
atomically advances the object revision while intentionally leaving the
business `updated_at` timestamp unchanged.

MCP maps those resources to `blockwart.list_comments` and
`blockwart.add_comment`. The latter accepts only `object_id`, Markdown `body`,
and `idempotency_key`. Its runtime service token must have the server-stored
`mcp` audience. Normal API comment writes require an `api`-audience token.

The object detail page shows the five newest entries and links to the paged
timeline. The v1 detail and agent context expose the same five authorized
entries under `recent_comments`; compact search stubs never include them.

## Audit and migration

A successful append writes exactly one `comment_create` audit event containing
the comment ID, actor, trusted channel, request ID, and new revision. It never
copies the comment body or a before/after payload into audit or the persisted
idempotency response. Replays and rejected writes add no object audit event.

Alembic revision `20260804_0014` moves every existing string
`data.comment` value exactly once into the timeline as `origin=legacy` and
`format=plain_text`, then removes the old key and advances that object's
revision without changing `updated_at`. Legacy text is not secret-scanned,
truncated, or interpreted as Markdown. Missing author provenance stays
explicitly null. This includes an empty legacy string even though new comments
must be nonblank. A non-string legacy value aborts before schema mutation; the
migration itself creates no audit event. The same revision adds the internal
catalog `instance_id` used for collision-safe timeline binding.

All existing service tokens migrate conservatively to audience `api`. The
revision can be downgraded only while `object_comments` is empty. Once a legacy
or new timeline entry exists, application rollback requires the paired
pre-migration database backup; the downgrade fails closed rather than losing
history.
