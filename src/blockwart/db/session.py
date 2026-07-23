from collections.abc import Generator, Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from blockwart.config import get_settings


class DatabaseTransactionError(RuntimeError):
    """Stable public error for failed database transactions."""


def build_engine(database_url: str | None = None):
    url = database_url or get_settings().database_url
    connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    return create_engine(url, connect_args=connect_args)


engine = build_engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


@contextmanager
def transaction(session: Session) -> Iterator[None]:
    """Commit one application use case or roll back all of its changes."""

    try:
        yield
        session.commit()
    except SQLAlchemyError as exc:
        session.rollback()
        raise DatabaseTransactionError("Database transaction failed") from exc
    except Exception:
        session.rollback()
        raise


def get_session() -> Generator[Session, None, None]:
    with SessionLocal() as session:
        yield session
