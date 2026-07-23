from collections.abc import Generator, Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine, event, make_url
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from blockwart.config import get_settings


class DatabaseTransactionError(RuntimeError):
    """Stable public error for failed database transactions."""


def build_engine(
    database_url: str | None = None,
    *,
    sqlite_busy_timeout_ms: int | None = None,
    sqlite_wal_enabled: bool | None = None,
) -> Engine:
    settings = get_settings()
    url = database_url or settings.database_url
    parsed_url = make_url(url)
    is_sqlite = parsed_url.get_backend_name() == "sqlite"
    busy_timeout_ms = (
        sqlite_busy_timeout_ms
        if sqlite_busy_timeout_ms is not None
        else settings.sqlite_busy_timeout_ms
    )
    wal_enabled = (
        sqlite_wal_enabled if sqlite_wal_enabled is not None else settings.sqlite_wal_enabled
    )
    connect_args = (
        {
            "check_same_thread": False,
            "timeout": busy_timeout_ms / 1000,
        }
        if is_sqlite
        else {}
    )
    configured_engine = create_engine(
        url,
        connect_args=connect_args,
        pool_pre_ping=True,
    )
    if is_sqlite:
        persistent = _is_persistent_sqlite(parsed_url.database)
        _configure_sqlite_connections(
            configured_engine,
            busy_timeout_ms=busy_timeout_ms,
            journal_mode=("wal" if wal_enabled else "delete") if persistent else None,
        )
    return configured_engine


def _configure_sqlite_connections(
    configured_engine: Engine,
    *,
    busy_timeout_ms: int,
    journal_mode: str | None,
) -> None:
    @event.listens_for(configured_engine, "connect")
    def set_sqlite_pragmas(dbapi_connection, _connection_record) -> None:
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute(f"PRAGMA busy_timeout={busy_timeout_ms}")
            if journal_mode is not None:
                effective_mode = cursor.execute(
                    f"PRAGMA journal_mode={journal_mode.upper()}"
                ).fetchone()[0]
                if str(effective_mode).lower() != journal_mode:
                    raise RuntimeError("SQLite journal mode could not be configured")
        finally:
            cursor.close()


def _is_persistent_sqlite(database: str | None) -> bool:
    if not database:
        return False
    normalized = database.lower()
    return normalized != ":memory:" and not normalized.startswith("file::memory:")


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
