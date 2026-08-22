from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from blockwart.release.canonical import (
    domain_digest,
    is_commit_sha,
    is_image_digest,
    read_json_document,
    require_secret_free,
    safe_absolute_path,
)
from blockwart.release.errors import ReleaseError

SPEC_VERSION = 1
MANIFEST_VERSION = 1
REPORT_SCHEMA_VERSION = 1
POINTER_SCHEMA_VERSION = 1

_NAME_CHARACTERS = frozenset(
    "abcdefghijklmnopqrstuvwxyz0123456789._-"
)


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=False)


class SourceSpec(_StrictModel):
    """The exact immutable source the release is built from."""

    commit: str
    repository_root: str

    @field_validator("commit")
    @classmethod
    def _exact_sha(cls, value: str) -> str:
        if not is_commit_sha(value):
            raise ValueError("source commit must be an exact 40-character lowercase SHA")
        return value


class ImageSpec(_StrictModel):
    runtime: Literal["docker", "podman"] = "docker"
    repository: str
    mode: Literal["build", "existing"] = "build"
    digest: str | None = None
    containerfile: str = "Dockerfile"

    @field_validator("repository")
    @classmethod
    def _image_repository(cls, value: str) -> str:
        components = value.split("/")
        if (
            not value
            or value.startswith("/")
            or set(value) - (_NAME_CHARACTERS | set("/"))
            or any(component in {"", ".", ".."} for component in components)
        ):
            raise ValueError("image repository must be a lowercase local repository name")
        return value

    @field_validator("digest")
    @classmethod
    def _image_digest(cls, value: str | None) -> str | None:
        if value is not None and not is_image_digest(value):
            raise ValueError("image digest must be sha256:<64 lowercase hex>")
        return value

    @field_validator("containerfile")
    @classmethod
    def _relative_containerfile(cls, value: str) -> str:
        candidate = Path(value)
        if not value or candidate.is_absolute() or ".." in candidate.parts:
            raise ValueError("containerfile must be a relative path inside the source tree")
        return value


class ServiceSpec(_StrictModel):
    """The single long-running container this workflow owns."""

    container_name: str
    data_directory: str
    database_filename: str = "blockwart.sqlite3"
    publish: str = "127.0.0.1:8000:8000"
    environment_file: str | None = None
    container_data_path: str = "/data"

    @field_validator("container_name")
    @classmethod
    def _container_name(cls, value: str) -> str:
        if not value or len(value) > 63 or set(value) - _NAME_CHARACTERS:
            raise ValueError("container name must be lowercase alphanumeric, dot, dash, underscore")
        return value

    @field_validator("database_filename")
    @classmethod
    def _database_filename(cls, value: str) -> str:
        if not value or set(value) - _NAME_CHARACTERS or value in {".", ".."}:
            raise ValueError("database filename must be a bare file name")
        return value

    @field_validator("publish")
    @classmethod
    def _loopback_publish(cls, value: str) -> str:
        parts = value.split(":")
        if len(parts) != 3 or parts[0] != "127.0.0.1":
            raise ValueError("publish must use 127.0.0.1:HOST_PORT:CONTAINER_PORT")
        try:
            ports = tuple(int(port) for port in parts[1:])
        except ValueError as exc:
            raise ValueError("publish ports must be integers") from exc
        if any(port < 1 or port > 65535 for port in ports):
            raise ValueError("publish ports must be in 1..65535")
        return value

    @field_validator("container_data_path")
    @classmethod
    def _container_data_path(cls, value: str) -> str:
        candidate = Path(value)
        if not candidate.is_absolute() or ".." in candidate.parts:
            raise ValueError("container data path must be absolute")
        return value


class StateSpec(_StrictModel):
    root: str
    retention: int = Field(default=5, ge=2, le=100)


class BackupSpec(_StrictModel):
    root: str


class TimeoutSpec(_StrictModel):
    build_seconds: int = Field(default=1800, ge=1, le=21600)
    command_seconds: int = Field(default=300, ge=1, le=3600)
    readiness_seconds: int = Field(default=120, ge=1, le=3600)
    health_seconds: int = Field(default=120, ge=1, le=3600)
    cutover_seconds: int = Field(default=300, ge=1, le=3600)
    rollback_seconds: int = Field(default=600, ge=1, le=3600)
    stop_seconds: int = Field(default=30, ge=1, le=600)
    poll_interval_seconds: float = Field(default=1.0, gt=0.0, le=60.0)


class HookSpec(_StrictModel):
    """An explicit argv contract executed after a verified release."""

    name: str
    argv: tuple[str, ...]
    timeout_seconds: int = Field(default=60, ge=1, le=600)

    @field_validator("name")
    @classmethod
    def _hook_name(cls, value: str) -> str:
        if not value or set(value) - _NAME_CHARACTERS:
            raise ValueError("hook name must be lowercase alphanumeric, dot, dash, underscore")
        return value

    @field_validator("argv")
    @classmethod
    def _hook_argv(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value or len(value) > 32:
            raise ValueError("hook argv must hold 1..32 explicit arguments")
        if not Path(value[0]).is_absolute():
            raise ValueError("hook program must be an absolute path")
        if any(not isinstance(item, str) or "\x00" in item for item in value):
            raise ValueError("hook argv must hold plain arguments")
        forbidden_switches = (
            "--api-key",
            "--apikey",
            "--bearer",
            "--client-secret",
            "--cookie",
            "--password",
            "--private-key",
            "--secret",
            "--session",
            "--token",
        )
        if any(
            argument.casefold() == switch
            or argument.casefold().startswith(f"{switch}=")
            for argument in value[1:]
            for switch in forbidden_switches
        ):
            raise ValueError("hook argv must not carry credential-shaped arguments")
        return value


class ReleaseSpec(_StrictModel):
    spec_version: Literal[1]
    expected_schema_revision: str
    source: SourceSpec
    image: ImageSpec
    service: ServiceSpec
    state: StateSpec
    backup: BackupSpec
    timeouts: TimeoutSpec = TimeoutSpec()
    hooks: tuple[HookSpec, ...] = ()

    @field_validator("expected_schema_revision")
    @classmethod
    def _schema_revision(cls, value: str) -> str:
        if not value or set(value) - _NAME_CHARACTERS:
            raise ValueError("expected schema revision must be a packaged Alembic revision id")
        return value

    @field_validator("hooks")
    @classmethod
    def _unique_hooks(cls, value: tuple[HookSpec, ...]) -> tuple[HookSpec, ...]:
        if len(value) > 8:
            raise ValueError("at most eight post-verification hooks are supported")
        names = [hook.name for hook in value]
        if len(set(names)) != len(names):
            raise ValueError("hook names must be unique")
        return value


class ResolvedPaths:
    """Validated, symlink-free filesystem layout for one release invocation."""

    __slots__ = (
        "repository_root",
        "state_root",
        "backup_root",
        "data_directory",
        "database_path",
        "environment_file",
        "containerfile",
    )

    def __init__(self, spec: ReleaseSpec) -> None:
        self.repository_root = safe_absolute_path(
            spec.source.repository_root, code="unsafe_repository_root"
        )
        self.state_root = safe_absolute_path(spec.state.root, code="unsafe_state_root")
        self.backup_root = safe_absolute_path(spec.backup.root, code="unsafe_backup_root")
        self.data_directory = safe_absolute_path(
            spec.service.data_directory, code="unsafe_data_directory"
        )
        self.database_path = self.data_directory / spec.service.database_filename
        self.containerfile = safe_absolute_path(
            str(self.repository_root / spec.image.containerfile),
            code="unsafe_containerfile",
        )
        self.environment_file = (
            safe_absolute_path(
                spec.service.environment_file,
                code="unsafe_environment_file",
            )
            if spec.service.environment_file is not None
            else None
        )


def spec_digest(spec: ReleaseSpec) -> str:
    return domain_digest("spec", canonical_spec_payload(spec))


def canonical_spec_payload(spec: ReleaseSpec) -> dict[str, Any]:
    """Return the canonical, secret-free specification document."""
    payload = spec.model_dump(mode="json")
    require_secret_free(payload, code="unsafe_spec_content")
    return payload


def public_contract_payload(spec: ReleaseSpec) -> dict[str, Any]:
    """Return bundle-safe release inputs without host runtime configuration.

    Persistent paths, bind addresses, environment-file locations, hooks, and
    timeouts belong to the host invocation.  They are intentionally excluded
    from immutable bundle artifacts and manifests.
    """
    payload = {
        "spec_version": spec.spec_version,
        "expected_schema_revision": spec.expected_schema_revision,
        "source_commit": spec.source.commit,
        "image": {
            "runtime": spec.image.runtime,
            "repository": spec.image.repository,
            "mode": spec.image.mode,
            "declared_digest": spec.image.digest,
            "containerfile": spec.image.containerfile,
        },
    }
    require_secret_free(payload, code="unsafe_manifest_content")
    return payload


def runtime_layout_digest(spec: ReleaseSpec) -> str:
    """Bind pointer state to the non-secret persistent runtime layout.

    Only the digest is persisted.  The bind address and host paths themselves
    never enter a bundle, manifest, report, pointer, or history entry.
    """
    payload = {
        "container_name": spec.service.container_name,
        "data_directory": spec.service.data_directory,
        "database_filename": spec.service.database_filename,
        "publish": spec.service.publish,
        "environment_file": spec.service.environment_file,
        "container_data_path": spec.service.container_data_path,
    }
    return domain_digest("runtime-layout", payload)


def contract_digest(spec: ReleaseSpec) -> str:
    """Digest the host-neutral inputs that define an immutable release bundle."""
    return domain_digest("contract", public_contract_payload(spec))


def release_id(spec: ReleaseSpec) -> str:
    """A deterministic identifier shared by equivalent host installations."""
    return f"{spec.source.commit[:12]}-{contract_digest(spec)[:12]}"


def load_spec(path: str | Path) -> ReleaseSpec:
    resolved = safe_absolute_path(str(Path(path).absolute()), code="unsafe_spec_path")
    document = read_json_document(resolved, code="invalid_spec_document")
    return parse_spec(document)


def parse_spec(document: Any) -> ReleaseSpec:
    if not isinstance(document, dict):
        raise ReleaseError("invalid_spec_document")
    if document.get("spec_version") != SPEC_VERSION:
        raise ReleaseError("unsupported_spec_version")
    try:
        spec = ReleaseSpec.model_validate(document)
    except ValidationError as exc:
        raise ReleaseError("invalid_spec_document") from exc
    if spec.image.mode == "existing" and spec.image.digest is None:
        raise ReleaseError("image_digest_required")
    canonical_spec_payload(spec)
    return spec
