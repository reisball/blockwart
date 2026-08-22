from __future__ import annotations

import json
import subprocess
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

from blockwart.release.errors import ReleaseError

# Every command this workflow runs is an explicit argv list executed without a
# shell, with a bounded timeout and a fixed minimal environment.
BASE_ENVIRONMENT: Mapping[str, str] = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "LC_ALL": "C.UTF-8",
    "LANG": "C.UTF-8",
}

READINESS_PROBE = (
    "import json,urllib.request;"
    "r=urllib.request.urlopen('http://127.0.0.1:8000/api/health/ready',timeout=5);"
    "b=json.load(r);"
    "print(json.dumps({'ok':bool(b.get('ok')),'revision':b.get('revision'),"
    "'build_revision':b.get('build_revision'),'error_code':b.get('error_code')},sort_keys=True))"
)

PACKAGED_SCHEMA_PROBE = (
    "import json;"
    "from alembic.script import ScriptDirectory;"
    "from blockwart.db.migrations import build_alembic_config;"
    "print(json.dumps(sorted("
    "ScriptDirectory.from_config(build_alembic_config('sqlite:///:memory:')).get_heads())))"
)


@dataclass(frozen=True, slots=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


class CommandRunner(Protocol):
    def run(
        self,
        argv: Sequence[str],
        *,
        timeout_seconds: int,
        context: Mapping[str, str] | None = None,
    ) -> CommandResult: ...


class Clock(Protocol):
    def now(self) -> datetime: ...

    def monotonic(self) -> float: ...

    def sleep(self, seconds: float) -> None: ...


class SubprocessCommandRunner:
    """Argv-only process boundary. ``shell=True`` is never used."""

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout_seconds: int,
        context: Mapping[str, str] | None = None,
    ) -> CommandResult:
        command = tuple(str(item) for item in argv)
        if not command:
            raise ReleaseError("empty_command")
        environment = dict(BASE_ENVIRONMENT)
        environment.update(dict(context or {}))
        try:
            completed = subprocess.run(  # noqa: S603 - argv only, never shell=True
                list(command),
                shell=False,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                env=environment,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return CommandResult(command, returncode=124, stdout="", stderr="", timed_out=True)
        except OSError as exc:
            raise ReleaseError("command_unavailable") from exc
        return CommandResult(
            command,
            returncode=completed.returncode,
            stdout=completed.stdout or "",
            stderr=completed.stderr or "",
        )


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(tz=UTC)

    def monotonic(self) -> float:
        return time.monotonic()

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)


@dataclass(frozen=True, slots=True)
class HealthObservation:
    """A container health status plus the end time of its newest health probe."""

    status: str
    last_probe_end: datetime | None
    failing_streak: int = 0


@dataclass(frozen=True, slots=True)
class ReadinessObservation:
    ok: bool
    revision: str | None
    build_revision: str | None
    error_code: str | None
    observed_at: datetime


@dataclass(frozen=True)
class ContainerEngine:
    """Thin argv wrapper around a local OCI runtime (``docker`` or ``podman``)."""

    binary: str
    runner: CommandRunner
    command_timeout_seconds: int = 300

    def _run(self, argv: Sequence[str], *, timeout_seconds: int | None = None) -> CommandResult:
        return self.runner.run(
            (self.binary, *argv),
            timeout_seconds=timeout_seconds or self.command_timeout_seconds,
        )

    def build_image(
        self,
        *,
        context: str,
        containerfile: str,
        tag: str,
        build_revision: str,
        timeout_seconds: int,
    ) -> CommandResult:
        return self._run(
            (
                "build",
                "--file",
                containerfile,
                "--build-arg",
                f"BLOCKWART_BUILD_REVISION={build_revision}",
                "--tag",
                tag,
                context,
            ),
            timeout_seconds=timeout_seconds,
        )

    def image_id(self, reference: str) -> str | None:
        result = self._run(("image", "inspect", "--format", "{{.Id}}", reference))
        if not result.ok:
            return None
        value = result.stdout.strip()
        return value or None

    def image_environment(self, reference: str, *, gate: str = "image_resolved") -> tuple[str, ...]:
        result = self._run(("image", "inspect", "--format", "{{json .Config.Env}}", reference))
        if not result.ok:
            raise ReleaseError("image_inspect_failed", gate=gate)
        try:
            payload = json.loads(result.stdout.strip() or "null")
        except json.JSONDecodeError as exc:
            raise ReleaseError("image_inspect_failed", gate=gate) from exc
        if payload is None:
            return ()
        if not isinstance(payload, list) or any(not isinstance(item, str) for item in payload):
            raise ReleaseError("image_inspect_failed", gate=gate)
        return tuple(payload)

    def tag_image(self, reference: str, tag: str) -> CommandResult:
        return self._run(("tag", reference, tag))

    def remove_image_reference(self, reference: str) -> CommandResult:
        return self._run(("image", "rm", reference))

    def container_exists(self, name: str) -> bool:
        return self._run(("container", "inspect", "--format", "{{.Id}}", name)).ok

    def container_image_id(self, name: str) -> str | None:
        result = self._run(("container", "inspect", "--format", "{{.Image}}", name))
        if not result.ok:
            return None
        return result.stdout.strip() or None

    def container_state(self, name: str) -> str | None:
        result = self._run(("container", "inspect", "--format", "{{.State.Status}}", name))
        if not result.ok:
            return None
        return result.stdout.strip() or None

    def health(self, name: str, *, timeout_seconds: int | None = None) -> HealthObservation:
        result = self._run(
            ("container", "inspect", "--format", "{{json .State.Health}}", name),
            timeout_seconds=timeout_seconds,
        )
        if not result.ok:
            return HealthObservation(status="unknown", last_probe_end=None)
        return parse_health(result.stdout)

    def run_detached(self, argv: Sequence[str], *, timeout_seconds: int) -> CommandResult:
        return self._run(("run", "--detach", *argv), timeout_seconds=timeout_seconds)

    def run_once(self, argv: Sequence[str], *, timeout_seconds: int) -> CommandResult:
        return self._run(("run", "--rm", *argv), timeout_seconds=timeout_seconds)

    def execute(self, name: str, argv: Sequence[str], *, timeout_seconds: int) -> CommandResult:
        return self._run(("exec", name, *argv), timeout_seconds=timeout_seconds)

    def stop_container(self, name: str, *, stop_seconds: int) -> CommandResult:
        return self._run(
            ("stop", "--time", str(stop_seconds), name),
            timeout_seconds=stop_seconds + 30,
        )

    def remove_container(self, name: str, *, stop_seconds: int) -> CommandResult:
        return self._run(("rm", "--force", name), timeout_seconds=stop_seconds + 30)


def parse_health(raw: str) -> HealthObservation:
    text = raw.strip()
    if not text or text == "null":
        return HealthObservation(status="none", last_probe_end=None)
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return HealthObservation(status="unknown", last_probe_end=None)
    if not isinstance(payload, dict):
        return HealthObservation(status="unknown", last_probe_end=None)
    status = payload.get("Status")
    log = payload.get("Log")
    last_end: datetime | None = None
    if isinstance(log, list) and log:
        entry = log[-1]
        if isinstance(entry, dict):
            last_end = parse_container_timestamp(entry.get("End"))
    streak = payload.get("FailingStreak")
    return HealthObservation(
        status=status if isinstance(status, str) and status else "unknown",
        last_probe_end=last_end,
        failing_streak=streak if isinstance(streak, int) else 0,
    )


def parse_container_timestamp(value: Any) -> datetime | None:
    """Parse an RFC3339 container timestamp, tolerating nanosecond precision."""
    if not isinstance(value, str) or not value:
        return None
    text = value.strip()
    if text.startswith("0001-01-01"):
        return None
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    if "." in text:
        head, _, tail = text.partition(".")
        fraction = ""
        offset = ""
        for index, character in enumerate(tail):
            if character.isdigit():
                fraction += character
            else:
                offset = tail[index:]
                break
        text = f"{head}.{fraction[:6]:0<6}{offset}"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)
