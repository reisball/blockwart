from __future__ import annotations

import os
import shutil
import sqlite3
import stat
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from blockwart.release.canonical import (
    create_exclusive_json,
    file_digest,
    fsync_directory,
    is_digest,
    read_json_document,
)
from blockwart.release.errors import ReleaseError

BACKUP_RECEIPT_SCHEMA_VERSION = 1
BACKUP_RECEIPT_MODE = "release-pre-cutover-backup"
_SIDECAR_SUFFIXES = ("-wal", "-shm", "-journal")


@dataclass(frozen=True, slots=True)
class BackupReceipt:
    """Secret-free evidence describing one verified pre-release backup."""

    release_id: str
    source_commit: str
    backup_file: str
    backup_sha256: str
    receipt_sha256: str
    size_bytes: int
    created_at: str

    def summary(self) -> dict[str, Any]:
        return {
            "backup_file": self.backup_file,
            "backup_sha256": self.backup_sha256,
            "receipt_sha256": self.receipt_sha256,
            "size_bytes": self.size_bytes,
        }


def create_online_backup(
    *,
    database_path: Path,
    backup_path: Path,
    release_id: str,
    source_commit: str,
    created_at: str,
    timeout_seconds: int = 300,
    monotonic: Callable[[], float] = time.monotonic,
) -> BackupReceipt:
    """Create and verify a consistent SQLite online backup.

    The live database is opened read-only and copied through SQLite's own
    backup API, so the copy is transaction consistent and the live file is
    never written by this workflow.
    """
    if not database_path.is_file() or database_path.is_symlink():
        raise ReleaseError("live_database_missing", gate="database_backup")
    if backup_path.exists():
        raise ReleaseError("backup_target_exists", gate="database_backup")
    receipt_path = _receipt_path(backup_path)
    if receipt_path.exists():
        raise ReleaseError("backup_target_exists", gate="database_backup")
    descriptor, temporary_raw = tempfile.mkstemp(
        prefix=f".{backup_path.name}.", suffix=".tmp", dir=backup_path.parent
    )
    os.close(descriptor)
    temporary = Path(temporary_raw)
    try:
        os.chmod(temporary, 0o600)
        _copy_database(
            database_path,
            temporary,
            timeout_seconds=timeout_seconds,
            monotonic=monotonic,
        )
        require_sqlite_integrity(
            temporary,
            gate="database_backup",
            timeout_seconds=timeout_seconds,
            monotonic=monotonic,
        )
        os.chmod(temporary, 0o400)
        os.replace(temporary, backup_path)
        fsync_directory(backup_path.parent)
    except ReleaseError:
        temporary.unlink(missing_ok=True)
        raise
    except SQLiteBackupTimeout as exc:
        temporary.unlink(missing_ok=True)
        raise ReleaseError("database_backup_timeout", gate="database_backup") from exc
    except (OSError, sqlite3.Error) as exc:
        temporary.unlink(missing_ok=True)
        raise ReleaseError("database_backup_failed", gate="database_backup") from exc
    payload = {
        "schema_version": BACKUP_RECEIPT_SCHEMA_VERSION,
        "mode": BACKUP_RECEIPT_MODE,
        "release_id": release_id,
        "source_commit": source_commit,
        "backup_file": backup_path.name,
        "backup_sha256": file_digest(backup_path),
        "size_bytes": backup_path.stat().st_size,
        "sqlite_integrity": "ok",
        "created_at": created_at,
    }
    receipt_digest = create_exclusive_json(receipt_path, payload, mode=0o400)
    return BackupReceipt(
        release_id=release_id,
        source_commit=source_commit,
        backup_file=backup_path.name,
        backup_sha256=str(payload["backup_sha256"]),
        receipt_sha256=receipt_digest,
        size_bytes=int(payload["size_bytes"]),
        created_at=created_at,
    )


def verify_backup(
    backup_path: Path,
    receipt: BackupReceipt,
    *,
    gate: str,
    timeout_seconds: int = 300,
    monotonic: Callable[[], float] = time.monotonic,
) -> None:
    """Re-verify digest, permissions, and SQLite integrity before trusting a backup."""
    if not backup_path.is_file() or backup_path.is_symlink():
        raise ReleaseError("backup_missing", gate=gate)
    backup_info = backup_path.lstat()
    mode = stat.S_IMODE(backup_info.st_mode)
    if mode & 0o222 or backup_info.st_uid != os.geteuid():
        raise ReleaseError("backup_unprotected", gate=gate)
    receipt_path = _receipt_path(backup_path)
    if not receipt_path.is_file() or receipt_path.is_symlink():
        raise ReleaseError("invalid_backup_receipt", gate=gate)
    receipt_info = receipt_path.lstat()
    if (
        receipt_info.st_uid != os.geteuid()
        or stat.S_IMODE(receipt_info.st_mode) & 0o222
        or file_digest(receipt_path) != receipt.receipt_sha256
    ):
        raise ReleaseError("invalid_backup_receipt", gate=gate)
    if file_digest(backup_path) != receipt.backup_sha256:
        raise ReleaseError("backup_digest_mismatch", gate=gate)
    stored = read_json_document(receipt_path, code="invalid_backup_receipt")
    expected_fields = {
        "schema_version",
        "mode",
        "release_id",
        "source_commit",
        "backup_file",
        "backup_sha256",
        "size_bytes",
        "sqlite_integrity",
        "created_at",
    }
    if (
        not isinstance(stored, dict)
        or set(stored) != expected_fields
        or stored.get("schema_version") != BACKUP_RECEIPT_SCHEMA_VERSION
        or stored.get("mode") != BACKUP_RECEIPT_MODE
        or stored.get("release_id") != receipt.release_id
        or stored.get("source_commit") != receipt.source_commit
        or stored.get("backup_file") != receipt.backup_file
        or stored.get("size_bytes") != receipt.size_bytes
        or stored.get("sqlite_integrity") != "ok"
        or stored.get("created_at") != receipt.created_at
    ):
        raise ReleaseError("invalid_backup_receipt", gate=gate)
    if not is_digest(stored.get("backup_sha256")) or (
        stored.get("backup_sha256") != receipt.backup_sha256
    ):
        raise ReleaseError("backup_digest_mismatch", gate=gate)
    require_sqlite_integrity(
        backup_path,
        gate=gate,
        timeout_seconds=timeout_seconds,
        monotonic=monotonic,
    )


def prune_managed_backups(
    backup_root: Path,
    *,
    retention: int,
    protected: tuple[Path, ...],
) -> tuple[str, ...]:
    """Bound managed backup attempts without touching unrelated host content.

    Only directories carrying a valid Blockwart pre-release receipt whose
    release id prefixes the directory name are eligible.  The current
    invocation is protected explicitly.  Failed rollback evidence is never
    pruned by the failing invocation because retention runs only after a fully
    verified successful cutover.
    """
    if not backup_root.exists():
        return ()
    protected_paths = {path for path in protected}
    candidates: list[Path] = []
    for directory in backup_root.iterdir():
        if directory in protected_paths:
            candidates.append(directory)
            continue
        if directory.is_symlink() or not directory.is_dir():
            continue
        receipt_path = directory / "pre-release.sqlite3.receipt.json"
        if not receipt_path.is_file() or receipt_path.is_symlink():
            continue
        document = read_json_document(receipt_path, code="invalid_backup_receipt")
        if not isinstance(document, dict):
            continue
        release_id = document.get("release_id")
        if (
            document.get("schema_version") != BACKUP_RECEIPT_SCHEMA_VERSION
            or document.get("mode") != BACKUP_RECEIPT_MODE
            or not isinstance(release_id, str)
            or not directory.name.startswith(f"{release_id}-")
        ):
            continue
        candidates.append(directory)
    keep = set(
        sorted(
            candidates,
            key=lambda path: (path.stat().st_mtime_ns, path.name),
            reverse=True,
        )[:retention]
    )
    keep.update(protected_paths)
    removed: list[str] = []
    for directory in sorted(candidates, key=lambda path: path.name):
        if directory in keep:
            continue
        _remove_managed_backup_tree(directory)
        removed.append(directory.name)
    if removed:
        fsync_directory(backup_root)
    return tuple(removed)


def restore_candidate_copy(
    backup_path: Path,
    target_path: Path,
    *,
    gate: str,
    timeout_seconds: int = 300,
    monotonic: Callable[[], float] = time.monotonic,
) -> str:
    """Materialize a private, writable candidate database from a verified backup."""
    if target_path.exists():
        raise ReleaseError("candidate_database_exists", gate=gate)
    target_path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    if target_path.parent.is_symlink():
        raise ReleaseError("candidate_restore_failed", gate=gate)
    try:
        descriptor = os.open(
            target_path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        os.close(descriptor)
        _copy_database(
            backup_path,
            target_path,
            timeout_seconds=timeout_seconds,
            monotonic=monotonic,
        )
    except SQLiteBackupTimeout as exc:
        target_path.unlink(missing_ok=True)
        raise ReleaseError("candidate_restore_timeout", gate=gate) from exc
    except (OSError, sqlite3.Error) as exc:
        target_path.unlink(missing_ok=True)
        raise ReleaseError("candidate_restore_failed", gate=gate) from exc
    require_sqlite_integrity(
        target_path,
        gate=gate,
        timeout_seconds=timeout_seconds,
        monotonic=monotonic,
    )
    return file_digest(target_path)


def restore_live_database(
    *,
    backup_path: Path,
    database_path: Path,
    evidence_path: Path,
    gate: str,
    timeout_seconds: int = 300,
    monotonic: Callable[[], float] = time.monotonic,
) -> tuple[str, bool]:
    """Replace the live database with the verified backup, preserving the failed copy.

    The failed database is moved aside first, so a rollback never destroys the
    evidence needed to diagnose the release that failed.
    """
    evidence_path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    candidate: Path | None = None
    try:
        if database_path.exists():
            database_info = database_path.lstat()
            if not stat.S_ISREG(database_info.st_mode):
                raise ReleaseError("unsafe_live_database", gate=gate)
            if evidence_path.exists():
                raise ReleaseError("rollback_evidence_exists", gate=gate)
            shutil.move(str(database_path), str(evidence_path))
            os.chmod(evidence_path, 0o400)
        for suffix in _SIDECAR_SUFFIXES:
            sidecar = database_path.with_name(f"{database_path.name}{suffix}")
            if sidecar.exists():
                if not stat.S_ISREG(sidecar.lstat().st_mode):
                    raise ReleaseError("unsafe_live_database", gate=gate)
                sidecar_evidence = evidence_path.with_name(f"{evidence_path.name}{suffix}")
                if sidecar_evidence.exists():
                    raise ReleaseError("rollback_evidence_exists", gate=gate)
                shutil.move(str(sidecar), str(sidecar_evidence))
                os.chmod(sidecar_evidence, 0o400)
        fsync_directory(evidence_path.parent)
        descriptor, candidate_raw = tempfile.mkstemp(
            prefix=f".{database_path.name}.restore.", dir=database_path.parent
        )
        os.close(descriptor)
        candidate = Path(candidate_raw)
        os.chmod(candidate, 0o600)
        shutil.copyfile(backup_path, candidate)
        require_sqlite_integrity(
            candidate,
            gate=gate,
            timeout_seconds=timeout_seconds,
            monotonic=monotonic,
        )
        with candidate.open("rb") as handle:
            os.fsync(handle.fileno())
        os.replace(candidate, database_path)
        fsync_directory(database_path.parent)
    except ReleaseError:
        if candidate is not None:
            candidate.unlink(missing_ok=True)
        raise
    except (OSError, sqlite3.Error) as exc:
        if candidate is not None:
            candidate.unlink(missing_ok=True)
        raise ReleaseError("rollback_database_restore_failed", gate=gate) from exc
    return file_digest(database_path), evidence_path.is_file()


def require_sqlite_integrity(
    path: Path,
    *,
    gate: str,
    timeout_seconds: int = 300,
    monotonic: Callable[[], float] = time.monotonic,
) -> None:
    deadline = monotonic() + timeout_seconds
    timed_out = False

    def progress() -> int:
        nonlocal timed_out
        if monotonic() >= deadline:
            timed_out = True
            return 1
        return 0

    try:
        connection = sqlite3.connect(_read_only_uri(path), uri=True)
    except sqlite3.Error as exc:
        raise ReleaseError("sqlite_integrity_failed", gate=gate) from exc
    try:
        connection.set_progress_handler(progress, 10_000)
        integrity = connection.execute("PRAGMA integrity_check").fetchone()
        foreign_keys = connection.execute("PRAGMA foreign_key_check").fetchone()
    except sqlite3.Error as exc:
        if timed_out:
            raise ReleaseError("sqlite_integrity_timeout", gate=gate) from exc
        raise ReleaseError("sqlite_integrity_failed", gate=gate) from exc
    finally:
        connection.close()
    if integrity != ("ok",) or foreign_keys is not None:
        raise ReleaseError("sqlite_integrity_failed", gate=gate)


class SQLiteBackupTimeout(RuntimeError):
    """Internal bounded-backup timeout."""


def _copy_database(
    source_path: Path,
    destination_path: Path,
    *,
    timeout_seconds: int,
    monotonic: Callable[[], float],
) -> None:
    source = sqlite3.connect(_read_only_uri(source_path), uri=True)
    destination = sqlite3.connect(destination_path)
    deadline = monotonic() + timeout_seconds

    def progress(_status: int, _remaining: int, _total: int) -> None:
        if monotonic() >= deadline:
            raise SQLiteBackupTimeout

    try:
        source.backup(destination, pages=256, progress=progress, sleep=0.05)
        destination.execute("PRAGMA journal_mode=DELETE").fetchone()
    finally:
        source.close()
        destination.close()


def _receipt_path(backup_path: Path) -> Path:
    return backup_path.with_name(f"{backup_path.name}.receipt.json")


def _read_only_uri(path: Path) -> str:
    return f"{path.resolve().as_uri()}?mode=ro"


def _remove_managed_backup_tree(directory: Path) -> None:
    for path in sorted(directory.rglob("*"), reverse=True):
        if path.is_symlink():
            raise ReleaseError("unsafe_backup_root", gate="retention_applied")
        if path.is_file():
            os.chmod(path, 0o600)
    shutil.rmtree(directory)
