# Config

Blockwart configuration uses environment variables prefixed with `BLOCKWART_`.

Current local keys:

- `BLOCKWART_ENV`
- `BLOCKWART_DATABASE_URL`
- `BLOCKWART_SECRET_REFERENCE`

`BLOCKWART_SECRET_REFERENCE` is a reference label only. It must never contain a raw secret value.

## Pilot Seed Import

The pilot catalog seed lives at `seeds/pilot_objects.yaml`. Import code should call
`blockwart.services.seeds.import_seed_file(session, "seeds/pilot_objects.yaml")` with a fresh
or existing SQLAlchemy session. The seed stores credential references only; it must not contain raw
passwords, tokens, private keys, cookies, or `.env` file bodies.
