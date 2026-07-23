# Config

Blockwart configuration uses environment variables prefixed with `BLOCKWART_`.

Current local keys:

- `BLOCKWART_ENV`
- `BLOCKWART_DATABASE_URL`
- `BLOCKWART_SECRET_REFERENCE`

`BLOCKWART_SECRET_REFERENCE` is a reference label only. It must never contain a raw secret value.

## Pilot Seed Import

The pilot catalog seed lives at `seeds/pilot_objects.yaml`. Use the packaged CLI for local or
deployment-prep initialization:

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
