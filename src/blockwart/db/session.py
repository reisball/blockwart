import hashlib
import shutil
from collections.abc import Generator, Iterator
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import unquote

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
    sqlite_configure_journal_mode: bool = True,
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
            journal_mode=(
                ("wal" if wal_enabled else "delete")
                if persistent and sqlite_configure_journal_mode
                else None
            ),
        )
    return configured_engine


def build_read_only_engine(database_url: str | None = None) -> Engine:
    """Open an inspection engine without changing a persistent SQLite source."""
    settings = get_settings()
    url = database_url or settings.database_url
    parsed_url = make_url(url)
    snapshot_directory: TemporaryDirectory[str] | None = None
    if (
        parsed_url.get_backend_name() == "sqlite"
        and _is_persistent_sqlite(parsed_url.database)
    ):
        source_path = _sqlite_database_path(str(parsed_url.database))
        snapshot_directory = TemporaryDirectory(prefix="blockwart-read-only-")
        snapshot_path = Path(snapshot_directory.name) / source_path.name
        try:
            _copy_stable_sqlite_snapshot(source_path, snapshot_path)
        except Exception:
            snapshot_directory.cleanup()
            raise
        read_only_url = parsed_url.set(
            database=f"file:{snapshot_path}",
            query={
                **{
                    key: value
                    for key, value in dict(parsed_url.query).items()
                    if key not in {"immutable", "mode", "uri"}
                },
                "mode": "ro",
                "uri": "true",
            },
        )
        url = read_only_url.render_as_string(hide_password=False)
    try:
        read_only_engine = build_engine(
            url,
            sqlite_configure_journal_mode=False,
        )
    except Exception:
        if snapshot_directory is not None:
            snapshot_directory.cleanup()
        raise
    if snapshot_directory is not None:
        event.listen(
            read_only_engine,
            "engine_disposed",
            lambda _engine: snapshot_directory.cleanup(),
            once=True,
        )
    return read_only_engine


def _sqlite_database_path(database: str) -> Path:
    path = database[5:] if database.lower().startswith("file:") else database
    return Path(unquote(path))


def _copy_stable_sqlite_snapshot(source_path: Path, snapshot_path: Path) -> None:
    source_wal_path = source_path.with_name(f"{source_path.name}-wal")
    snapshot_wal_path = snapshot_path.with_name(f"{snapshot_path.name}-wal")

    for _attempt in range(3):
        try:
            before = _sqlite_snapshot_state(source_path, source_wal_path)
            shutil.copyfile(source_path, snapshot_path)
            if source_wal_path.exists():
                shutil.copyfile(source_wal_path, snapshot_wal_path)
            else:
                snapshot_wal_path.unlink(missing_ok=True)
            source_hashes = _sqlite_snapshot_hashes(source_path, source_wal_path)
            snapshot_hashes = _sqlite_snapshot_hashes(snapshot_path, snapshot_wal_path)
            after = _sqlite_snapshot_state(source_path, source_wal_path)
        except FileNotFoundError:
            continue
        if before == after and source_hashes == snapshot_hashes:
            return

    raise RuntimeError("SQLite source changed while creating read-only snapshot")


def _sqlite_snapshot_state(database_path: Path, wal_path: Path) -> tuple[tuple, ...]:
    return tuple(
        (
            suffix,
            path.stat().st_dev,
            path.stat().st_ino,
            path.stat().st_size,
            path.stat().st_mtime_ns,
        )
        for suffix, path in (("", database_path), ("-wal", wal_path))
        if path.exists()
    )


def _sqlite_snapshot_hashes(database_path: Path, wal_path: Path) -> tuple[bytes, ...]:
    return tuple(
        _file_sha256(path)
        for path in (database_path, wal_path)
        if path.exists()
    )


def _file_sha256(path: Path) -> bytes:
    with path.open("rb") as file_handle:
        return hashlib.file_digest(file_handle, "sha256").digest()


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
