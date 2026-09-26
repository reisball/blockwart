"""Shared test helpers for the catalog ownership invariant."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from blockwart.db.migrations import upgrade_database
from blockwart.db.session import build_engine, transaction
from blockwart.models import Principal
from blockwart.services.identity import create_service_account

SEED_OWNER_LOGIN = "seed.owner"


def ensure_seed_owner(session: Session, *, login: str = SEED_OWNER_LOGIN) -> str:
    """Return an active principal that seeds and imports may name as first Owner."""
    existing = session.scalar(select(Principal).where(Principal.login == login))
    if existing is not None:
        return existing.id
    return create_service_account(
        session,
        login=login,
        display_name="Seed Owner",
    ).id


def prepare_cli_owner(
    database_url: str,
    *,
    login: str = SEED_OWNER_LOGIN,
) -> str:
    """Upgrade one test database and persist the owner required by import CLIs."""
    upgrade_database(database_url)
    engine = build_engine(database_url)
    try:
        with Session(engine) as session:
            with transaction(session):
                ensure_seed_owner(session, login=login)
    finally:
        engine.dispose()
    return login
