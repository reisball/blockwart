from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

from blockwart.domain.security import find_secret_violations
from blockwart.release.errors import ReleaseError

DIGEST_PATTERN = "^[0-9a-f]{64}$"
IMAGE_DIGEST_PATTERN = "^sha256:[0-9a-f]{64}$"
COMMIT_PATTERN = "^[0-9a-f]{40}$"
_HEX = frozenset("0123456789abcdef")


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize deterministically: sorted keys, no NaN, compact separators."""
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ReleaseError("non_canonical_json") from exc


def canonical_json_text(value: Any) -> str:
    return canonical_json_bytes(value).decode("utf-8")


def domain_digest(domain: str, value: Any) -> str:
    prefix = f"blockwart:release:{domain}:v1\n".encode()
    return hashlib.sha256(prefix + canonical_json_bytes(value)).hexdigest()


def file_digest(path: Path) -> str:
    with path.open("rb") as file_handle:
        return hashlib.file_digest(file_handle, "sha256").hexdigest()


def is_digest(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and not set(value) - _HEX


def is_image_digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and value.startswith("sha256:")
        and is_digest(value[len("sha256:") :])
    )


def is_commit_sha(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 40 and not set(value) - _HEX


def require_secret_free(payload: Any, *, code: str) -> None:
    """Refuse to emit a document that carries secret-shaped keys or values."""
    if find_secret_violations(payload):
        raise ReleaseError(code)


def safe_absolute_path(raw: str, *, code: str) -> Path:
    """Return an absolute, traversal-free, symlink-free path.

    The workflow refuses relative inputs, ``..`` components, and any path whose
    real location differs from its lexical location, so a swapped symlink
    cannot redirect an immutable bundle, backup, or pointer write.
    """
    if not isinstance(raw, str) or not raw:
        raise ReleaseError(code)
    candidate = Path(raw)
    if not candidate.is_absolute():
        raise ReleaseError(code)
    if any(part == ".." for part in PurePosixPath(raw).parts):
        raise ReleaseError(code)
    normalized = Path(os.path.normpath(str(candidate)))
    if Path(os.path.realpath(str(candidate))) != normalized:
        raise ReleaseError(code)
    return normalized


def require_protected_directory(path: Path, *, code: str) -> None:
    """Require an existing directory owned by this user and not writable by others."""
    try:
        info = path.lstat()
    except OSError as exc:
        raise ReleaseError(code) from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise ReleaseError(code)
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o022:
        raise ReleaseError(code)


def require_protected_file(path: Path, *, code: str, read_only: bool = False) -> None:
    """Require an owned regular file with no group/other write access."""
    try:
        info = path.lstat()
    except OSError as exc:
        raise ReleaseError(code) from exc
    mode = stat.S_IMODE(info.st_mode)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or mode & 0o022
        or (read_only and mode & 0o200)
    ):
        raise ReleaseError(code)


def require_regular_file(path: Path, *, code: str) -> None:
    """Require a regular, non-symlink file without imposing runtime ownership."""
    try:
        info = path.lstat()
    except OSError as exc:
        raise ReleaseError(code) from exc
    if not stat.S_ISREG(info.st_mode):
        raise ReleaseError(code)


def require_disjoint(first: Path, second: Path, *, code: str) -> None:
    """Refuse overlapping state layouts such as a backup root inside the data path."""
    if first == second or first in second.parents or second in first.parents:
        raise ReleaseError(code)


def fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_write_bytes(path: Path, payload: bytes, *, mode: int = 0o600) -> None:
    """Durably replace ``path`` with ``payload`` through a same-directory temporary."""
    descriptor, temporary_raw = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_raw)
    try:
        os.chmod(temporary, mode)
        with os.fdopen(descriptor, "wb") as file_handle:
            descriptor = -1
            file_handle.write(payload)
            file_handle.flush()
            os.fsync(file_handle.fileno())
        os.replace(temporary, path)
    except Exception:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise
    fsync_directory(path.parent)


def atomic_write_json(path: Path, payload: Any, *, mode: int = 0o600) -> str:
    """Write canonical JSON atomically and return its sha256 digest."""
    body = canonical_json_bytes(payload) + b"\n"
    atomic_write_bytes(path, body, mode=mode)
    return hashlib.sha256(body).hexdigest()


def create_exclusive_json(path: Path, payload: Any, *, mode: int = 0o400) -> str:
    """Create an immutable JSON artifact that must not already exist."""
    body = canonical_json_bytes(payload) + b"\n"
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            mode,
        )
        with os.fdopen(descriptor, "wb") as file_handle:
            descriptor = -1
            file_handle.write(body)
            file_handle.flush()
            os.fsync(file_handle.fileno())
    except FileExistsError as exc:
        raise ReleaseError("bundle_artifact_exists") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    fsync_directory(path.parent)
    return hashlib.sha256(body).hexdigest()


def create_exclusive_bytes(path: Path, payload: bytes, *, mode: int = 0o400) -> None:
    """Durably create a byte artifact without replacing existing evidence."""
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            mode,
        )
        with os.fdopen(descriptor, "wb") as file_handle:
            descriptor = -1
            file_handle.write(payload)
            file_handle.flush()
            os.fsync(file_handle.fileno())
    except FileExistsError as exc:
        raise ReleaseError("bundle_artifact_exists") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    fsync_directory(path.parent)


def json_artifact_digest(payload: Any) -> str:
    """Digest of a JSON artifact exactly as it is written to disk."""
    return hashlib.sha256(canonical_json_bytes(payload) + b"\n").hexdigest()


def read_json_document(path: Path, *, code: str) -> Any:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ReleaseError(code) from exc
    try:
        return json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ReleaseError(code) from exc
