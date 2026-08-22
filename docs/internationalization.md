# Canonical English Contract and UI Localization

Blockwart separates its storage/API vocabulary from user-facing language.
English is the only canonical backend language. The UI is English by default
and currently ships complete English and German catalogs.

## Canonical backend vocabulary

The public object kinds are:

| Canonical kind | Meaning | English UI | German UI |
|---|---|---|---|
| `host` | physical hardware | Hardware | Hardware |
| `system` | LXC, VM, WSL, or another runtime environment | Host | Host |
| `service` | one deployed service instance | Service | Dienst |
| `network` | a network or segment | Network | Netzwerk |
| `device` | a separately managed physical or virtual device | Device | Gerät |

Database values, typed references, JSON keys, Pydantic/OpenAPI schemas, Agent
API, MCP, seeds, diagnostics, logs, and audit event codes use the canonical
English terms. Localized prose is never a backend key or stored as the source
of truth.

Alembic revision `20260729_0007` migrates the former `netzwerk` kind to
`network`. It plans and validates all object, relationship, typed-reference,
and audit changes before the first write. Exact JSON keys and typed-reference
values are rewritten recursively. Collisions, dangling references, kind
mismatches, unknown kinds, and invalid relationship results fail the upgrade.
Unreadable legacy JSON remains byte-identical and opaque; it is not guessed or
silently repaired.

The migration also adds `audit_events.details_json`. Existing human-written
summaries are preserved exactly as `legacy_summary` audit details, while their
canonical `summary` column becomes the stable English event code `legacy`.
New audit records likewise store a stable English event code and structured
values. English or German sentences are rendered only at a read/UI boundary.

## Locale resolution and catalogs

Locale resolution uses this precedence:

1. `?lang=en` or `?lang=de`
2. the `blockwart-language` cookie
3. `Accept-Language`
4. English

A valid query selection is persisted for one year. Every HTML surface includes
the same language switcher: catalog, topology, object details/editing, schema
settings, and identity access.

The identity login form localizes its default-off persistence control as **Keep
me signed in** in English and **Angemeldet bleiben** in German. Its submitted
backend value remains the canonical fixed English marker `remember=on`; labels
never become stored session metadata or client-selected lifetime input.

Catalogs live in:

- `src/blockwart/ui/locales/en.json`
- `src/blockwart/ui/locales/de.json`

Application startup fails if the locale files do not have exactly the same
keys. Tests also require matching Python-format placeholders for every key.
Missing runtime translations fall back to English, but incomplete packaged
catalogs are rejected at startup.

To add another language:

1. copy `en.json` to `<locale>.json`;
2. translate values without changing keys or format placeholders;
3. add the locale to the schema-override locale validation when overrides must
   be editable in that language;
4. run the UI, accessibility, package, and full test suites.

## Schema override file migration

Schema override format version 2 stores locale-specific `labels` and
`placeholders`. Version 1 did not record which language a string used.
Migration therefore copies each original string byte-for-byte into both
`en` and `de`; it never guesses a language.

The migration is explicit and dry-run first:

```bash
blockwart-schema-overrides
blockwart-schema-overrides --apply
```

Apply creates `<configured-path>.v1.bak` with mode `0600` before atomically
writing version 2. An existing backup is never overwritten. The active file is
unchanged when validation or backup creation fails.

## Production sequence and rollback

Before deploying this contract:

1. stop or drain writers;
2. create and verify a database backup;
3. back up the configured schema override file, if present;
4. run `blockwart-schema-overrides` and review the dry-run result;
5. deploy the matching application image and run `blockwart-db upgrade`;
6. run `blockwart-schema-overrides --apply` when the plan reports a change;
7. run `blockwart-db check`, `blockwart-db integrity`, readiness, API/MCP, and
   English/German UI smoke checks;
8. compare object, relationship, audit, and provenance counts and hashes with
   the pre-deployment evidence.

There is no automatic downgrade for revision `20260729_0007`. Rollback restores
the verified pre-upgrade database, the matching application image, and the
schema override `.v1.bak` together.
