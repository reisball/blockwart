from __future__ import annotations

import fcntl
import json
import os
import shutil
import stat
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jsonschema import ValidationError, validate

from blockwart.release.canonical import (
    atomic_write_json,
    canonical_json_bytes,
    create_exclusive_bytes,
    create_exclusive_json,
    file_digest,
    fsync_directory,
    is_commit_sha,
    is_digest,
    is_image_digest,
    read_json_document,
    require_protected_directory,
    require_secret_free,
)
from blockwart.release.errors import ReleaseError
from blockwart.release.manifest import manifest_json_schema
from blockwart.release.spec import POINTER_SCHEMA_VERSION

CURRENT_POINTER = "current"
PREVIOUS_POINTER = "previous"
POINTERS_STATE_SCHEMA_VERSION = 1
_POINTER_FIELDS = (
    "schema_version",
    "release_id",
    "generation",
    "manifest_digest",
    "image_digest",
    "source_commit",
    "schema_revision",
    "runtime_layout_digest",
    "updated_at",
)
_MAX_HISTORY_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class Pointer:
    """A durable reference to one immutable release bundle."""

    release_id: str
    generation: int
    manifest_digest: str
    image_digest: str
    source_commit: str
    schema_revision: str
    runtime_layout_digest: str
    updated_at: str

    def payload(self) -> dict[str, Any]:
        return {
            "schema_version": POINTER_SCHEMA_VERSION,
            "release_id": self.release_id,
            "generation": self.generation,
            "manifest_digest": self.manifest_digest,
            "image_digest": self.image_digest,
            "source_commit": self.source_commit,
            "schema_revision": self.schema_revision,
            "runtime_layout_digest": self.runtime_layout_digest,
            "updated_at": self.updated_at,
        }

    def summary(self) -> dict[str, Any]:
        return {
            "release_id": self.release_id,
            "generation": self.generation,
            "manifest_digest": self.manifest_digest,
            "image_digest": self.image_digest,
            "source_commit": self.source_commit,
            "schema_revision": self.schema_revision,
            "runtime_layout_digest": self.runtime_layout_digest,
        }


@dataclass(frozen=True, slots=True)
class BundleRecord:
    release_id: str
    manifest_digest: str
    created: bool


class ReleaseStore:
    """Immutable release bundles, safe pointers, history, and reports.

    The store holds release code evidence only. Databases, backups, runtime
    configuration, and secret material live outside it by construction.
    """

    def __init__(self, root: Path) -> None:
        self.root = root

    @property
    def releases_dir(self) -> Path:
        return self.root / "releases"

    @property
    def reports_dir(self) -> Path:
        return self.root / "reports"

    @property
    def lock_path(self) -> Path:
        return self.root / "lock"

    @property
    def history_path(self) -> Path:
        return self.root / "history.jsonl"

    def pointer_path(self, name: str) -> Path:
        return self.root / "pointers.json"

    def bundle_dir(self, release_id: str) -> Path:
        return self.releases_dir / release_id

    def manifest_path(self, release_id: str) -> Path:
        return self.bundle_dir(release_id) / "manifest.json"

    def exists(self) -> bool:
        return self.root.is_dir()

    def verify_layout(self) -> None:
        require_protected_directory(self.root, code="unsafe_state_root")
        for directory in (self.releases_dir, self.reports_dir):
            if directory.exists():
                require_protected_directory(directory, code="unsafe_state_layout")
        path = self.pointer_path(CURRENT_POINTER)
        if path.exists():
            try:
                info = path.lstat()
            except OSError as exc:
                raise ReleaseError("unsafe_state_layout") from exc
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) & 0o022
            ):
                raise ReleaseError("unsafe_state_layout")

    def prepare(self) -> None:
        """Create the release state layout with owner-only write permissions."""
        for directory in (self.root, self.releases_dir, self.reports_dir):
            directory.mkdir(mode=0o750, parents=True, exist_ok=True)
        try:
            descriptor = os.open(
                self.lock_path,
                os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
                0o640,
            )
        except OSError as exc:
            raise ReleaseError("unsafe_state_layout") from exc
        else:
            os.close(descriptor)
        self.verify_layout()

    def read_pointer(self, name: str) -> Pointer | None:
        if name not in {CURRENT_POINTER, PREVIOUS_POINTER}:
            raise ReleaseError("invalid_pointer_name")
        path = self.pointer_path(name)
        if not path.exists():
            return None
        if path.is_symlink() or not path.is_file():
            raise ReleaseError("unsafe_state_layout")
        document = read_json_document(path, code="invalid_release_pointer")
        if (
            not isinstance(document, dict)
            or set(document) != {"schema_version", CURRENT_POINTER, PREVIOUS_POINTER}
            or document.get("schema_version") != POINTERS_STATE_SCHEMA_VERSION
        ):
            raise ReleaseError("invalid_release_pointer")
        value = document[name]
        return None if value is None else parse_pointer(value)

    def write_pointer(self, name: str, pointer: Pointer) -> None:
        if name not in {CURRENT_POINTER, PREVIOUS_POINTER}:
            raise ReleaseError("invalid_pointer_name")
        current = self.read_pointer(CURRENT_POINTER)
        previous = self.read_pointer(PREVIOUS_POINTER)
        if name == CURRENT_POINTER:
            current = pointer
        else:
            previous = pointer
        self.write_pointers(current=current, previous=previous)

    def write_pointers(
        self, *, current: Pointer | None, previous: Pointer | None
    ) -> None:
        """Atomically replace the current/previous pointer pair as one document."""
        payload = {
            "schema_version": POINTERS_STATE_SCHEMA_VERSION,
            CURRENT_POINTER: current.payload() if current is not None else None,
            PREVIOUS_POINTER: previous.payload() if previous is not None else None,
        }
        require_secret_free(payload, code="unsafe_pointer_content")
        atomic_write_json(self.pointer_path(CURRENT_POINTER), payload, mode=0o640)

    def next_generation(self) -> int:
        generations = [entry.get("generation", 0) for entry in self.read_history()]
        for name in (CURRENT_POINTER, PREVIOUS_POINTER):
            pointer = self.read_pointer(name)
            if pointer is not None:
                generations.append(pointer.generation)
        return (max(generations) if generations else 0) + 1

    def write_bundle(
        self,
        release_id: str,
        *,
        manifest: Mapping[str, Any],
        artifacts: Mapping[str, Any],
    ) -> BundleRecord:
        """Create one immutable bundle, or confirm an identical existing bundle."""
        require_secret_free(manifest, code="unsafe_manifest_content")
        require_secret_free(artifacts, code="unsafe_manifest_content")
        _validate_manifest(manifest)
        directory = self.bundle_dir(release_id)
        manifest_path = self.manifest_path(release_id)
        if directory.exists():
            if directory.is_symlink() or not directory.is_dir():
                raise ReleaseError("unsafe_state_layout", gate="bundle_written")
            existing = read_json_document(manifest_path, code="invalid_release_manifest")
            if canonical_json_bytes(existing) != canonical_json_bytes(manifest):
                raise ReleaseError("bundle_manifest_conflict", gate="bundle_written")
            digest = self.verify_bundle(release_id)
            return BundleRecord(release_id, digest, created=False)
        staging = self.releases_dir / f".{release_id}.staging"
        if staging.exists():
            raise ReleaseError("bundle_staging_exists", gate="bundle_written")
        staging.mkdir(mode=0o750, parents=True)
        artifacts_dir = staging / "artifacts"
        artifacts_dir.mkdir(mode=0o750)
        for name, payload in sorted(artifacts.items()):
            create_exclusive_json(artifacts_dir / f"{name}.json", payload, mode=0o440)
        digest = create_exclusive_json(staging / "manifest.json", manifest, mode=0o440)
        create_exclusive_bytes(
            staging / "manifest.sha256", f"{digest}\n".encode("ascii"), mode=0o440
        )
        fsync_directory(artifacts_dir)
        fsync_directory(staging)
        try:
            os.rename(staging, directory)
        except OSError as exc:
            shutil.rmtree(staging, ignore_errors=True)
            raise ReleaseError("bundle_write_failed", gate="bundle_written") from exc
        fsync_directory(self.releases_dir)
        self.verify_bundle(release_id)
        return BundleRecord(release_id, digest, created=True)

    def verify_bundle(self, release_id: str) -> str:
        """Verify the complete immutable bundle and all bound artifact evidence."""
        directory = self.bundle_dir(release_id)
        if directory.is_symlink() or not directory.is_dir():
            raise ReleaseError("release_bundle_missing")
        require_protected_directory(directory, code="unsafe_release_bundle")
        direct_names = {path.name for path in directory.iterdir()}
        if direct_names != {"artifacts", "manifest.json", "manifest.sha256"}:
            raise ReleaseError("invalid_release_bundle")
        artifacts_dir = directory / "artifacts"
        require_protected_directory(artifacts_dir, code="unsafe_release_bundle")
        manifest_path = directory / "manifest.json"
        sidecar_path = directory / "manifest.sha256"
        for path in (manifest_path, sidecar_path):
            _require_immutable_file(path)
        digest = file_digest(manifest_path)
        try:
            recorded_digest = sidecar_path.read_text(encoding="ascii").strip()
        except (OSError, UnicodeError) as exc:
            raise ReleaseError("invalid_release_bundle") from exc
        if recorded_digest != digest or not is_digest(recorded_digest):
            raise ReleaseError("bundle_manifest_digest_mismatch")
        manifest = self.read_manifest(release_id)
        _validate_manifest(manifest)
        if manifest.get("release_id") != release_id:
            raise ReleaseError("invalid_release_manifest")
        artifact_entries = manifest.get("artifacts")
        if not isinstance(artifact_entries, list):
            raise ReleaseError("invalid_release_manifest")
        expected: dict[str, str] = {}
        for entry in artifact_entries:
            if not isinstance(entry, dict) or set(entry) != {"name", "sha256"}:
                raise ReleaseError("invalid_release_manifest")
            name = entry.get("name")
            artifact_digest = entry.get("sha256")
            if (
                not isinstance(name, str)
                or not name
                or set(name) - set("abcdefghijklmnopqrstuvwxyz0123456789-_")
                or name in expected
                or not is_digest(artifact_digest)
            ):
                raise ReleaseError("invalid_release_manifest")
            expected[name] = artifact_digest
        actual_names = {path.name for path in artifacts_dir.iterdir()}
        if actual_names != {f"{name}.json" for name in expected}:
            raise ReleaseError("bundle_artifact_missing")
        for name, expected_digest in expected.items():
            path = artifacts_dir / f"{name}.json"
            _require_immutable_file(path)
            if file_digest(path) != expected_digest:
                raise ReleaseError("bundle_artifact_digest_mismatch")
        return digest

    def manifest_digest(self, release_id: str) -> str:
        path = self.manifest_path(release_id)
        if not path.is_file() or path.is_symlink():
            raise ReleaseError("release_bundle_missing")
        return file_digest(path)

    def read_manifest(self, release_id: str) -> dict[str, Any]:
        document = read_json_document(
            self.manifest_path(release_id), code="invalid_release_manifest"
        )
        if not isinstance(document, dict):
            raise ReleaseError("invalid_release_manifest")
        return document

    def artifact_digests(self, release_id: str) -> dict[str, str]:
        artifacts_dir = self.bundle_dir(release_id) / "artifacts"
        if not artifacts_dir.is_dir():
            return {}
        return {
            path.stem: file_digest(path)
            for path in sorted(artifacts_dir.iterdir())
            if path.is_file() and not path.is_symlink()
        }

    def append_history(self, entry: Mapping[str, Any]) -> None:
        require_secret_free(entry, code="unsafe_history_content")
        body = canonical_json_bytes(entry) + b"\n"
        path = self.history_path
        if path.exists() and (path.is_symlink() or not path.is_file()):
            raise ReleaseError("unsafe_state_layout")
        if path.exists() and path.stat().st_size + len(body) > _MAX_HISTORY_BYTES:
            raise ReleaseError("release_history_full")
        with path.open("ab") as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(path, 0o640)

    def read_history(self) -> list[dict[str, Any]]:
        path = self.history_path
        if not path.exists():
            return []
        if path.is_symlink() or not path.is_file():
            raise ReleaseError("unsafe_state_layout")
        entries: list[dict[str, Any]] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                document = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ReleaseError("invalid_release_history") from exc
            if not isinstance(document, dict):
                raise ReleaseError("invalid_release_history")
            entries.append(document)
        return entries

    def prune(self, *, retention: int, protected: Sequence[str]) -> tuple[str, ...]:
        """Remove old bundles, never the active or rollback release.

        ``retention`` counts the newest committed releases that are kept in
        addition to the protected ``current``/``previous`` identifiers.
        """
        if not self.releases_dir.is_dir():
            return ()
        keep = set(protected)
        for entry in sorted(
            self.read_history(),
            key=lambda item: int(item.get("generation", 0)),
            reverse=True,
        )[:retention]:
            release_id = entry.get("release_id")
            if isinstance(release_id, str):
                keep.add(release_id)
        removed: list[str] = []
        for directory in sorted(self.releases_dir.iterdir()):
            if not directory.is_dir() or directory.is_symlink():
                continue
            if directory.name in keep or directory.name.startswith("."):
                continue
            _remove_immutable_tree(directory)
            removed.append(directory.name)
        if removed:
            fsync_directory(self.releases_dir)
        return tuple(removed)

    def write_report(self, name: str, payload: Mapping[str, Any]) -> str:
        require_secret_free(payload, code="unsafe_report_content")
        self.reports_dir.mkdir(mode=0o750, parents=True, exist_ok=True)
        return atomic_write_json(self.reports_dir / f"{name}.json", payload, mode=0o640)


def parse_pointer(document: Any) -> Pointer:
    if not isinstance(document, dict) or set(document) != set(_POINTER_FIELDS):
        raise ReleaseError("invalid_release_pointer")
    if document["schema_version"] != POINTER_SCHEMA_VERSION:
        raise ReleaseError("unsupported_pointer_version")
    generation = document["generation"]
    if not isinstance(generation, int) or isinstance(generation, bool) or generation < 1:
        raise ReleaseError("invalid_release_pointer")
    if (
        not is_digest(document["manifest_digest"])
        or not is_image_digest(document["image_digest"])
        or not is_commit_sha(document["source_commit"])
        or not is_digest(document["runtime_layout_digest"])
    ):
        raise ReleaseError("invalid_release_pointer")
    for key in ("release_id", "schema_revision", "updated_at"):
        if not isinstance(document[key], str) or not document[key]:
            raise ReleaseError("invalid_release_pointer")
    return Pointer(
        release_id=document["release_id"],
        generation=generation,
        manifest_digest=document["manifest_digest"],
        image_digest=document["image_digest"],
        source_commit=document["source_commit"],
        schema_revision=document["schema_revision"],
        runtime_layout_digest=document["runtime_layout_digest"],
        updated_at=document["updated_at"],
    )


@contextmanager
def release_lock(store: ReleaseStore, *, exclusive: bool) -> Iterator[bool]:
    """Single-writer release lock.

    Apply takes an exclusive lock; a dry run takes a shared lock and never
    creates state. A held lock fails fast instead of waiting behind another
    release.
    """
    if not store.exists():
        if exclusive:
            raise ReleaseError("release_state_missing")
        yield False
        return
    if not exclusive and not store.lock_path.exists():
        yield False
        return
    try:
        descriptor = os.open(
            store.lock_path,
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
            0o640,
        )
    except OSError as exc:
        raise ReleaseError("unsafe_state_layout") from exc
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o022
        ):
            raise ReleaseError("unsafe_state_layout")
        mode = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
        try:
            fcntl.flock(descriptor, mode | fcntl.LOCK_NB)
        except OSError as exc:
            raise ReleaseError("release_lock_held") from exc
        try:
            yield True
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def _remove_immutable_tree(directory: Path) -> None:
    for path in sorted(directory.rglob("*"), reverse=True):
        if path.is_dir() and not path.is_symlink():
            continue
        os.chmod(path, 0o600)
    shutil.rmtree(directory)


def _require_immutable_file(path: Path) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise ReleaseError("bundle_artifact_missing") from exc
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o222
    ):
        raise ReleaseError("unsafe_release_bundle")


def _validate_manifest(manifest: Mapping[str, Any]) -> None:
    try:
        validate(instance=dict(manifest), schema=manifest_json_schema())
    except ValidationError as exc:
        raise ReleaseError("invalid_release_manifest") from exc
