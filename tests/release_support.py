"""Deterministic host fakes for the atomic release workflow.

Docker, git, and process execution are injected boundaries, so the complete
release state machine, including every post-cutover failure path, runs without
a container runtime. SQLite is deliberately real.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from blockwart.release.runtime import (
    PACKAGED_SCHEMA_PROBE,
    READINESS_PROBE,
    CommandResult,
)
from blockwart.release.spec import ReleaseSpec, parse_spec

COMMIT = "a" * 40
TREE = "b" * 40
SCHEMA_REVISION = "20260818_0018"
NEW_IMAGE = "sha256:" + "1" * 64
OLD_IMAGE = "sha256:" + "2" * 64
STALE_PROBE_END = datetime(2020, 1, 1, tzinfo=UTC)


class FakeClock:
    """Monotonic, fully deterministic clock."""

    def __init__(self, start: datetime | None = None) -> None:
        self._now = start or datetime(2026, 8, 22, 11, 43, 0, tzinfo=UTC)
        self._monotonic = 1000.0
        self.slept: list[float] = []

    def now(self) -> datetime:
        return self._now

    def monotonic(self) -> float:
        return self._monotonic

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.advance(seconds)

    def advance(self, seconds: float) -> None:
        self._now = self._now + timedelta(seconds=seconds)
        self._monotonic += seconds


@dataclass
class FakeImage:
    """One local image plus the behaviour of containers started from it."""

    digest: str
    build_revision: str = COMMIT
    packaged_head: str = SCHEMA_REVISION
    build_revision_present: bool = True
    migration_ok: bool = True
    candidate_check_ok: bool = True
    candidate_integrity_ok: bool = True
    service_check_ok: bool = True
    service_integrity_ok: bool = True
    candidate_start_ok: bool = True
    candidate_start_timeout: bool = False
    service_start_ok: bool = True
    service_start_timeout: bool = False
    candidate_readiness: Any = "ok"
    service_readiness: Any = "ok"
    candidate_health: tuple[tuple[str, Any], ...] = (("healthy", "fresh"),)
    service_health: tuple[tuple[str, Any], ...] = (("healthy", "fresh"),)

    def environment(self) -> list[str]:
        values = ["PYTHONUNBUFFERED=1"]
        if self.build_revision_present:
            values.append(f"BLOCKWART_BUILD_REVISION={self.build_revision}")
        return values

    def readiness_payload(self, *, candidate: bool) -> Any:
        value = self.candidate_readiness if candidate else self.service_readiness
        if value == "ok":
            return {
                "ok": True,
                "revision": self.packaged_head,
                "build_revision": self.build_revision,
                "error_code": None,
            }
        return value


@dataclass
class FakeContainer:
    name: str
    image: str
    health_index: int = 0


@dataclass
class FakeHost:
    """Simulated git repository and container runtime behind an argv boundary."""

    clock: FakeClock
    repository_root: Path
    images: dict[str, FakeImage]
    commit: str = COMMIT
    tree: str = TREE
    head: str | None = None
    git_status: str = ""
    git_symbolic: str = ""
    known_commits: tuple[str, ...] = (COMMIT,)
    commit_reachable: bool = True
    is_repository: bool = True
    toplevel: str | None = None
    build_ok: bool = True
    build_timeout: bool = False
    built_digest: str = NEW_IMAGE
    drift_source_after_build: bool = False
    packaged_schema_ok: bool = True
    stop_ok: bool = True
    stop_timeout: bool = False
    remove_ok: bool = True
    hook_results: dict[str, str] = field(default_factory=dict)
    service_start_side_effect: Callable[[str], None] | None = None
    candidate_start_side_effect: Callable[[str], None] | None = None
    containers: dict[str, FakeContainer] = field(default_factory=dict)
    calls: list[tuple[str, ...]] = field(default_factory=list)
    hook_contexts: list[dict[str, str]] = field(default_factory=list)

    def start_container(self, name: str, image: str) -> None:
        self.containers[name] = FakeContainer(name=name, image=image)

    # -- command boundary -------------------------------------------------
    def run(
        self,
        argv: Sequence[str],
        *,
        timeout_seconds: int,
        context: Mapping[str, str] | None = None,
    ) -> CommandResult:
        command = tuple(str(item) for item in argv)
        self.calls.append(command)
        if command[0] == "git":
            return self._git(command)
        if command[0] in {"docker", "podman"}:
            return self._container(command)
        return self._hook(command, context)

    # -- git ---------------------------------------------------------------
    def _git(self, command: tuple[str, ...]) -> CommandResult:
        arguments = list(command[4:])  # git -C <root> --no-pager ...
        if not self.is_repository:
            return _result(command, 128, "", "not a git repository")
        if arguments[:2] == ["rev-parse", "--show-toplevel"]:
            return _ok(command, self.toplevel or str(self.repository_root))
        if arguments[0] == "for-each-ref" and "--contains" not in arguments:
            return _ok(command, self.git_symbolic)
        if arguments[:2] == ["cat-file", "-t"]:
            if arguments[2] not in self.known_commits:
                return _result(command, 128, "", "unknown object")
            return _ok(command, "commit")
        if arguments[0] == "for-each-ref" and "--contains" in arguments:
            return _ok(command, "refs/heads/main" if self.commit_reachable else "")
        if arguments[:2] == ["rev-parse", "HEAD"]:
            return _ok(command, self.head or self.commit)
        if arguments[0] == "status":
            return _ok(command, self.git_status)
        if arguments[0] == "rev-parse" and arguments[-1].endswith("^{tree}"):
            return _ok(command, self.tree)
        return _result(command, 1, "", "unsupported git command")

    # -- container runtime -------------------------------------------------
    def _container(self, command: tuple[str, ...]) -> CommandResult:
        arguments = list(command[1:])
        verb = arguments[0]
        if verb == "build":
            return self._build(command, arguments)
        if verb == "tag":
            source, tag = arguments[1:3]
            image = self.images.get(source)
            if image is None:
                return _result(command, 1, "", "no such image")
            self.images[tag] = image
            return _ok(command, "")
        if verb == "image" and arguments[1] == "inspect":
            return self._image_inspect(command, arguments)
        if verb == "image" and arguments[1] == "rm":
            self.images.pop(arguments[2], None)
            return _ok(command, "")
        if verb == "container" and arguments[1] == "inspect":
            return self._container_inspect(command, arguments)
        if verb == "run":
            return self._run_container(command, arguments)
        if verb == "exec":
            return self._exec(command, arguments)
        if verb == "stop":
            if self.stop_timeout:
                self.stop_timeout = False
                return CommandResult(command, 124, "", "", timed_out=True)
            return _result(command, 0 if self.stop_ok else 1, "", "")
        if verb == "rm":
            name = arguments[-1]
            self.containers.pop(name, None)
            return _result(command, 0 if self.remove_ok else 1, "", "")
        return _result(command, 1, "", "unsupported container command")

    def _build(self, command: tuple[str, ...], arguments: list[str]) -> CommandResult:
        if self.build_timeout:
            return CommandResult(command, 124, "", "", timed_out=True)
        if not self.build_ok:
            return _result(command, 1, "", "build failed")
        tag = arguments[arguments.index("--tag") + 1]
        image = self.images[self.built_digest]
        self.images[tag] = image
        if self.drift_source_after_build:
            self.head = "f" * 40
        return _ok(command, "")

    def _image_inspect(self, command: tuple[str, ...], arguments: list[str]) -> CommandResult:
        reference = arguments[-1]
        image = self.images.get(reference)
        if image is None:
            return _result(command, 1, "", "no such image")
        template = arguments[arguments.index("--format") + 1]
        if template == "{{.Id}}":
            return _ok(command, image.digest)
        if template == "{{json .Config.Env}}":
            return _ok(command, json.dumps(image.environment()))
        return _result(command, 1, "", "unsupported format")

    def _container_inspect(self, command: tuple[str, ...], arguments: list[str]) -> CommandResult:
        name = arguments[-1]
        container = self.containers.get(name)
        if container is None:
            return _result(command, 1, "", "no such container")
        template = arguments[arguments.index("--format") + 1]
        if template == "{{.Id}}":
            return _ok(command, f"container-{name}")
        if template == "{{.Image}}":
            return _ok(command, container.image)
        if template == "{{.State.Status}}":
            return _ok(command, "running")
        if template == "{{json .State.Health}}":
            return _ok(command, json.dumps(self._health_payload(container)))
        return _result(command, 1, "", "unsupported format")

    def _health_payload(self, container: FakeContainer) -> Any:
        image = self.images[container.image]
        candidate = "-candidate-" in container.name
        sequence = image.candidate_health if candidate else image.service_health
        index = min(container.health_index, len(sequence) - 1)
        container.health_index += 1
        status, end = sequence[index]
        if end == "fresh":
            self.clock.advance(0.001)
            timestamp = self.clock.now()
        elif end == "stale":
            timestamp = STALE_PROBE_END
        else:
            timestamp = end
        if status == "none":
            return None
        log = []
        if timestamp is not None:
            log.append({"Start": _rfc3339(timestamp), "End": _rfc3339(timestamp), "ExitCode": 0})
        return {"Status": status, "FailingStreak": 0, "Log": log}

    def _run_container(self, command: tuple[str, ...], arguments: list[str]) -> CommandResult:
        detached = "--detach" in arguments
        name = arguments[arguments.index("--name") + 1] if "--name" in arguments else ""
        reference = _image_reference(arguments, self.images)
        image = self.images[reference]
        trailing = list(arguments[arguments.index(reference) + 1 :])
        if detached:
            candidate = "-candidate-" in name
            timed_out = image.candidate_start_timeout if candidate else image.service_start_timeout
            started = image.candidate_start_ok if candidate else image.service_start_ok
            if timed_out:
                return CommandResult(command, 124, "", "", timed_out=True)
            if not started:
                return _result(command, 1, "", "start failed")
            self.start_container(name, reference)
            if candidate and self.candidate_start_side_effect is not None:
                self.candidate_start_side_effect(reference)
            if not candidate and self.service_start_side_effect is not None:
                self.service_start_side_effect(reference)
            return _ok(command, f"container-{name}")
        if trailing[:2] == ["blockwart-db", "upgrade"]:
            return _result(command, 0 if image.migration_ok else 1, "", "")
        if trailing[:2] == ["blockwart-db", "check"]:
            return _result(command, 0 if image.candidate_check_ok else 1, "", "")
        if trailing[:2] == ["blockwart-db", "integrity"]:
            return _result(command, 0 if image.candidate_integrity_ok else 1, "", "")
        if trailing[:2] == ["python", "-c"] and trailing[2] == PACKAGED_SCHEMA_PROBE:
            if not self.packaged_schema_ok:
                return _result(command, 1, "", "probe failed")
            return _ok(command, json.dumps([image.packaged_head]))
        return _result(command, 1, "", "unsupported run command")

    def _exec(self, command: tuple[str, ...], arguments: list[str]) -> CommandResult:
        name = arguments[1]
        container = self.containers.get(name)
        if container is None:
            return _result(command, 1, "", "no such container")
        image = self.images[container.image]
        candidate = "-candidate-" in name
        trailing = list(arguments[2:])
        if trailing[:2] == ["python", "-c"] and trailing[2] == READINESS_PROBE:
            payload = image.readiness_payload(candidate=candidate)
            if payload == "never":
                return _result(command, 1, "", "probe failed")
            return _ok(command, json.dumps(payload, sort_keys=True))
        if trailing[:2] == ["blockwart-db", "check"]:
            return _result(command, 0 if image.service_check_ok else 1, "", "")
        if trailing[:2] == ["blockwart-db", "integrity"]:
            return _result(command, 0 if image.service_integrity_ok else 1, "", "")
        return _result(command, 1, "", "unsupported exec command")

    # -- hooks -------------------------------------------------------------
    def _hook(self, command: tuple[str, ...], context: Mapping[str, str] | None) -> CommandResult:
        self.hook_contexts.append(dict(context or {}))
        behaviour = self.hook_results.get(command[0], "ok")
        if behaviour == "timeout":
            return CommandResult(command, 124, "", "", timed_out=True)
        if behaviour == "fail":
            return _result(command, 1, "", "hook failed")
        return _ok(command, "")


def _image_reference(arguments: list[str], images: Mapping[str, FakeImage]) -> str:
    for item in arguments:
        if item in images:
            return item
    raise AssertionError(f"no image reference in {arguments}")


def _rfc3339(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f000Z")


def _ok(command: tuple[str, ...], stdout: str) -> CommandResult:
    return CommandResult(command, 0, stdout, "")


def _result(
    command: tuple[str, ...], returncode: int, stdout: str, stderr: str
) -> CommandResult:
    return CommandResult(command, returncode, stdout, stderr)


# ----------------------------------------------------------------------
# installation fixtures
# ----------------------------------------------------------------------
def build_installation(tmp_path: Path) -> dict[str, Path]:
    root = tmp_path.resolve()
    layout = {
        "repository": root / "repository",
        "state": root / "state",
        "backups": root / "backups",
        "data": root / "data",
    }
    for name, path in layout.items():
        if name == "state":
            # The release state root is created by the first apply, never by a plan.
            continue
        path.mkdir(mode=0o750, parents=True, exist_ok=True)
        path.chmod(0o750)
    (layout["repository"] / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    create_live_database(layout["data"] / "blockwart.sqlite3")
    return layout


def create_live_database(path: Path, *, rows: int = 3) -> None:
    """A real SQLite database, so backup and integrity checks are genuine."""
    connection = sqlite3.connect(path)
    try:
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("CREATE TABLE IF NOT EXISTS catalog_objects (id TEXT PRIMARY KEY)")
        connection.execute(
            "CREATE TABLE IF NOT EXISTS alembic_version (version_num TEXT PRIMARY KEY)"
        )
        connection.execute(
            "INSERT OR REPLACE INTO alembic_version VALUES (?)", (SCHEMA_REVISION,)
        )
        for index in range(rows):
            connection.execute(
                "INSERT OR REPLACE INTO catalog_objects VALUES (?)", (f"object-{index}",)
            )
        connection.commit()
    finally:
        connection.close()
    path.chmod(0o640)


def spec_document(layout: Mapping[str, Path], **overrides: Any) -> dict[str, Any]:
    document: dict[str, Any] = {
        "spec_version": 1,
        "expected_schema_revision": SCHEMA_REVISION,
        "source": {"commit": COMMIT, "repository_root": str(layout["repository"])},
        "image": {
            "runtime": "docker",
            "repository": "blockwart",
            "mode": "build",
            "containerfile": "Dockerfile",
        },
        "service": {
            "container_name": "blockwart",
            "data_directory": str(layout["data"]),
            "database_filename": "blockwart.sqlite3",
            "publish": "127.0.0.1:8000:8000",
        },
        "state": {"root": str(layout["state"]), "retention": 3},
        "backup": {"root": str(layout["backups"])},
        "timeouts": {"poll_interval_seconds": 1.0},
    }
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(document.get(key), dict):
            document[key] = {**document[key], **value}
        else:
            document[key] = value
    return document


def build_spec(layout: Mapping[str, Path], **overrides: Any) -> ReleaseSpec:
    return parse_spec(spec_document(layout, **overrides))


def default_images(**overrides: Any) -> dict[str, FakeImage]:
    new_image = FakeImage(digest=NEW_IMAGE, **overrides)
    old_image = FakeImage(digest=OLD_IMAGE, build_revision="c" * 40)
    return {NEW_IMAGE: new_image, OLD_IMAGE: old_image}
