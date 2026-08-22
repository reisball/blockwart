from __future__ import annotations

import json
import math
import os
import shutil
import tarfile
import tempfile
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any

from blockwart.release.backup import (
    BackupReceipt,
    create_online_backup,
    prune_managed_backups,
    restore_candidate_copy,
    restore_live_database,
    verify_backup,
)
from blockwart.release.canonical import (
    domain_digest,
    fsync_directory,
    is_image_digest,
    require_disjoint,
    require_protected_directory,
    require_protected_file,
    require_regular_file,
    require_secret_free,
)
from blockwart.release.errors import ReleaseError, ReleaseRollbackError
from blockwart.release.manifest import build_artifacts, build_manifest
from blockwart.release.runtime import (
    PACKAGED_SCHEMA_PROBE,
    READINESS_PROBE,
    Clock,
    CommandResult,
    CommandRunner,
    ContainerEngine,
    ReadinessObservation,
)
from blockwart.release.source import SourceEvidence, verify_source
from blockwart.release.spec import (
    MANIFEST_VERSION,
    REPORT_SCHEMA_VERSION,
    ReleaseSpec,
    ResolvedPaths,
    runtime_environment,
    runtime_layout_digest,
    spec_digest,
)
from blockwart.release.spec import (
    release_id as compute_release_id,
)
from blockwart.release.state import (
    CURRENT_POINTER,
    PREVIOUS_POINTER,
    Pointer,
    ReleaseStore,
    release_lock,
)

PLAN_MODE = "plan"
APPLY_MODE = "apply"

OUTCOME_PLANNED = "planned"
OUTCOME_SUCCEEDED = "succeeded"
OUTCOME_FAILED = "failed"
OUTCOME_ROLLED_BACK = "rolled_back"
OUTCOME_ROLLBACK_FAILED = "rollback_failed"

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2
EXIT_ROLLED_BACK = 3
EXIT_ROLLBACK_FAILED = 4

EXIT_CODES: Mapping[str, int] = {
    OUTCOME_PLANNED: EXIT_OK,
    OUTCOME_SUCCEEDED: EXIT_OK,
    OUTCOME_FAILED: EXIT_FAILED,
    OUTCOME_ROLLED_BACK: EXIT_ROLLED_BACK,
    OUTCOME_ROLLBACK_FAILED: EXIT_ROLLBACK_FAILED,
}

GATE_STATUS_PASSED = "passed"
GATE_STATUS_FAILED = "failed"
GATE_STATUS_SKIPPED = "skipped"
GATE_STATUS_PLANNED = "planned"

# Allowlisted, non-secret context handed to post-verification hooks.
HOOK_CONTEXT_KEYS = (
    "BLOCKWART_RELEASE_ID",
    "BLOCKWART_RELEASE_SOURCE_COMMIT",
    "BLOCKWART_RELEASE_IMAGE_DIGEST",
    "BLOCKWART_RELEASE_MANIFEST_DIGEST",
    "BLOCKWART_RELEASE_SCHEMA_REVISION",
    "BLOCKWART_RELEASE_OUTCOME",
)


@dataclass
class GateLog:
    entries: list[dict[str, Any]] = field(default_factory=list)

    def record(self, name: str, status: str, code: str | None = None) -> None:
        self.entries.append({"name": name, "status": status, "code": code})

    @contextmanager
    def gate(self, name: str) -> Iterator[None]:
        try:
            yield
        except ReleaseError as exc:
            self.record(name, GATE_STATUS_FAILED, exc.code)
            raise
        except Exception as exc:
            error = ReleaseError(f"{name}_failed", gate=name)
            self.record(name, GATE_STATUS_FAILED, error.code)
            raise error from exc
        self.record(name, GATE_STATUS_PASSED)

    def payload(self) -> list[dict[str, Any]]:
        return list(self.entries)


@dataclass(frozen=True, slots=True)
class ReleaseOutcome:
    report: dict[str, Any]

    @property
    def outcome(self) -> str:
        return str(self.report["outcome"])

    @property
    def exit_code(self) -> int:
        return EXIT_CODES[self.outcome]


class ReleaseWorkflow:
    """Host-neutral, rollback-safe release state machine.

    Every process and container interaction is injected, so the complete
    state machine, including each post-cutover failure path, is exercised
    without touching a real host.
    """

    def __init__(
        self,
        spec: ReleaseSpec,
        *,
        runner: CommandRunner,
        clock: Clock,
    ) -> None:
        self.spec = spec
        self.runner = runner
        self.clock = clock
        self.paths = ResolvedPaths(spec)
        self.release_id = compute_release_id(spec)
        self.store = ReleaseStore(self.paths.state_root)
        self.engine = ContainerEngine(
            binary=spec.image.runtime,
            runner=runner,
            command_timeout_seconds=spec.timeouts.command_seconds,
        )

    # ------------------------------------------------------------------
    # public entry points
    # ------------------------------------------------------------------
    def plan(self) -> ReleaseOutcome:
        """Produce a write-free, repeatable release plan."""
        gates = GateLog()
        started_at = self._timestamp()
        diagnostics: list[dict[str, str]] = []
        try:
            with gates.gate("spec_validated"):
                self._validate_layout(require_state=False)
            with gates.gate("source_verified"):
                source = verify_source(
                    runner=self.runner,
                    repository_root=self.paths.repository_root,
                    commit=self.spec.source.commit,
                    timeout_seconds=self.spec.timeouts.command_seconds,
                )
            with release_lock(self.store, exclusive=False):
                current = self._read_pointer_if_present(CURRENT_POINTER)
                previous = self._read_pointer_if_present(PREVIOUS_POINTER)
                image_digest: str | None = None
                if self.spec.image.mode == "existing":
                    with gates.gate("image_resolved"):
                        image_digest = self._resolve_existing_image(source)
                    with gates.gate("source_reverified"):
                        self._reverify_source(source)
                else:
                    gates.record("image_resolved", GATE_STATUS_PLANNED)
                    gates.record("source_reverified", GATE_STATUS_PLANNED)
                for name in (
                    "packaged_schema",
                    "bundle_written",
                    "database_backup",
                    "rollback_image_pinned",
                    "candidate_restore",
                    "candidate_migration",
                    "candidate_schema",
                    "candidate_db_check",
                    "candidate_integrity",
                    "candidate_runtime_layout",
                    "candidate_readiness",
                    "candidate_health",
                    "candidate_cleanup",
                    "cutover_service_stopped",
                    "cutover_database_snapshot",
                    "cutover_service_started",
                    "cutover_runtime_layout",
                    "cutover_readiness",
                    "cutover_health",
                    "cutover_schema",
                    "cutover_integrity",
                    "hooks",
                    "pointers_committed",
                    "retention_applied",
                ):
                    gates.record(name, GATE_STATUS_PLANNED)
                manifest = None
                if image_digest is not None:
                    artifacts = build_artifacts(
                        self.spec, source=source, image_tag=self._image_tag()
                    )
                    manifest = build_manifest(
                        self.spec,
                        source=source,
                        image_digest=image_digest,
                        packaged_schema_revision=self.spec.expected_schema_revision,
                        artifacts=artifacts,
                    )
                replayed = current is not None and current.release_id == self.release_id
                if replayed:
                    diagnostics.append(_ALREADY_CURRENT)
                return ReleaseOutcome(
                    self._report(
                        mode=PLAN_MODE,
                        outcome=OUTCOME_PLANNED,
                        gates=gates,
                        started_at=started_at,
                        changed=False,
                        replayed=replayed,
                        source=source,
                        image_digest=image_digest,
                        manifest=manifest,
                        manifest_digest=None,
                        current=current,
                        previous=previous,
                        diagnostics=diagnostics,
                    )
                )
        except ReleaseError as exc:
            return ReleaseOutcome(
                self._failure_report(
                    mode=PLAN_MODE,
                    gates=gates,
                    started_at=started_at,
                    error=exc,
                    diagnostics=diagnostics,
                )
            )

    def apply(self, *, expect_current: str) -> ReleaseOutcome:
        """Execute the release with automatic, verified rollback."""
        if expect_current != "none" and not expect_current:
            raise ReleaseError(
                "expect_current_required", gate="current_pointer_verified"
            )
        gates = GateLog()
        started_at = self._timestamp()
        token = _attempt_token(self.clock.now())
        diagnostics: list[dict[str, str]] = []
        state: _ApplyState = _ApplyState(release_id=self.release_id, token=token)
        try:
            with gates.gate("spec_validated"):
                self._validate_layout(require_state=False)
            with gates.gate("source_verified"):
                state.source = verify_source(
                    runner=self.runner,
                    repository_root=self.paths.repository_root,
                    commit=self.spec.source.commit,
                    timeout_seconds=self.spec.timeouts.command_seconds,
                )
            with gates.gate("state_prepared"):
                self.store.prepare()
            with release_lock(self.store, exclusive=True):
                return self._apply_locked(
                    gates=gates,
                    started_at=started_at,
                    state=state,
                    diagnostics=diagnostics,
                    expect_current=expect_current,
                )
        except ReleaseRollbackError as exc:
            return ReleaseOutcome(
                self._failure_report(
                    mode=APPLY_MODE,
                    gates=gates,
                    started_at=started_at,
                    error=exc,
                    diagnostics=diagnostics,
                    outcome=OUTCOME_ROLLBACK_FAILED,
                    state=state,
                )
            )
        except ReleaseError as exc:
            return ReleaseOutcome(
                self._failure_report(
                    mode=APPLY_MODE,
                    gates=gates,
                    started_at=started_at,
                    error=exc,
                    diagnostics=diagnostics,
                    state=state,
                )
            )

    def status(self) -> dict[str, Any]:
        """Read-only view of the recorded release state."""
        self._validate_layout(require_state=False)
        with release_lock(self.store, exclusive=False):
            current = self._read_pointer_if_present(CURRENT_POINTER)
            previous = self._read_pointer_if_present(PREVIOUS_POINTER)
            history = self.store.read_history() if self.store.exists() else []
            payload = {
                "schema_version": REPORT_SCHEMA_VERSION,
                "mode": "status",
                "release_id": self.release_id,
                "current": current.summary() if current else None,
                "previous": previous.summary() if previous else None,
                "history": [
                    {
                        "generation": entry.get("generation"),
                        "release_id": entry.get("release_id"),
                        "outcome": entry.get("outcome"),
                    }
                    for entry in history[-20:]
                ],
            }
        require_secret_free(payload, code="unsafe_report_content")
        return payload

    # ------------------------------------------------------------------
    # apply phases
    # ------------------------------------------------------------------
    def _apply_locked(
        self,
        *,
        gates: GateLog,
        started_at: str,
        state: _ApplyState,
        diagnostics: list[dict[str, str]],
        expect_current: str | None,
    ) -> ReleaseOutcome:
        source = state.source
        if source is None:  # pragma: no cover - guarded by the source gate
            raise ReleaseError("source_evidence_missing", gate="source_verified")
        with gates.gate("current_pointer_verified"):
            state.current = self._verify_current_pointer(expect_current)
            state.previous = self._read_pointer_if_present(PREVIOUS_POINTER)
            state.previous_image_digest = (
                state.current.image_digest if state.current is not None else None
            )

        if self._is_replay(state):
            gates.record("release_replayed", GATE_STATUS_PASSED)
            diagnostics.append(_ALREADY_CURRENT)
            return ReleaseOutcome(
                self._report(
                    mode=APPLY_MODE,
                    outcome=OUTCOME_SUCCEEDED,
                    gates=gates,
                    started_at=started_at,
                    changed=False,
                    replayed=True,
                    source=source,
                    image_digest=state.current.image_digest if state.current else None,
                    manifest=self.store.read_manifest(self.release_id),
                    manifest_digest=self.store.manifest_digest(self.release_id),
                    current=state.current,
                    previous=state.previous,
                    diagnostics=diagnostics,
                )
            )

        with gates.gate("image_resolved"):
            state.image_digest = self._resolve_image(source)
        with gates.gate("source_reverified"):
            self._reverify_source(source)
        with gates.gate("packaged_schema"):
            state.packaged_schema_revision = self._verify_packaged_schema(state.image_digest)
        with gates.gate("bundle_written"):
            artifacts = build_artifacts(self.spec, source=source, image_tag=self._image_tag())
            manifest = build_manifest(
                self.spec,
                source=source,
                image_digest=state.image_digest,
                packaged_schema_revision=state.packaged_schema_revision,
                artifacts=artifacts,
            )
            record = self.store.write_bundle(
                self.release_id, manifest=manifest, artifacts=artifacts
            )
            state.manifest = manifest
            state.manifest_digest = record.manifest_digest
        with gates.gate("database_backup"):
            state.backup = self._create_backup(state)
        with gates.gate("rollback_image_pinned"):
            self._pin_rollback_image(state)

        try:
            self._run_candidate(gates=gates, state=state)
        finally:
            with gates.gate("candidate_cleanup"):
                self._release_candidate(state)

        try:
            self._cutover(gates=gates, state=state)
            self._run_hooks(gates=gates, state=state)
            self._commit_pointers(gates=gates, state=state)
        except ReleaseError as exc:
            return ReleaseOutcome(
                self._rollback(
                    gates=gates,
                    state=state,
                    started_at=started_at,
                    diagnostics=diagnostics,
                    failure=exc,
                )
            )

        self._apply_retention(gates=gates, state=state, diagnostics=diagnostics)
        self._discard_candidate_database(state)
        report = self._report(
            mode=APPLY_MODE,
            outcome=OUTCOME_SUCCEEDED,
            gates=gates,
            started_at=started_at,
            changed=True,
            replayed=False,
            source=source,
            image_digest=state.image_digest,
            manifest=state.manifest,
            manifest_digest=state.manifest_digest,
            current=state.committed_current,
            previous=state.committed_previous,
            diagnostics=diagnostics,
            backup=state.backup,
            retention=state.retention,
            hooks=state.hooks,
        )
        try:
            self.store.write_report(f"{self.release_id}-{state.token}", report)
        except (ReleaseError, OSError):
            failure = ReleaseError(
                "completion_report_write_failed", gate="completion_report"
            )
            return ReleaseOutcome(
                self._rollback(
                    gates=gates,
                    state=state,
                    started_at=started_at,
                    diagnostics=diagnostics,
                    failure=failure,
                )
            )
        return ReleaseOutcome(report)

    def _run_candidate(self, *, gates: GateLog, state: _ApplyState) -> None:
        """Prove the release against a restored copy, never the live database."""
        with gates.gate("candidate_restore"):
            verify_backup(
                state.backup_path(self.paths),
                state.backup,
                gate="candidate_restore",
                timeout_seconds=self.spec.timeouts.command_seconds,
                monotonic=self.clock.monotonic,
            )
            state.candidate_digest = restore_candidate_copy(
                state.backup_path(self.paths),
                state.candidate_database_path(
                    self.paths, self.spec.service.database_filename
                ),
                gate="candidate_restore",
                timeout_seconds=self.spec.timeouts.command_seconds,
                monotonic=self.clock.monotonic,
            )
        candidate_name = state.candidate_container(self.spec)
        if self.engine.container_exists(candidate_name):
            removed = self.engine.remove_container(
                candidate_name, stop_seconds=self.spec.timeouts.stop_seconds
            )
            if not removed.ok:
                raise ReleaseError("candidate_collision", gate="candidate_restore")
        with gates.gate("candidate_migration"):
            self._candidate_command(
                state,
                step="migration",
                argv=("blockwart-db", "upgrade"),
                gate="candidate_migration",
            )
        with gates.gate("candidate_schema"):
            observed = self._candidate_schema_revision(state)
            if observed != self.spec.expected_schema_revision:
                raise ReleaseError("candidate_schema_mismatch", gate="candidate_schema")
            state.candidate_schema_revision = observed
        with gates.gate("candidate_db_check"):
            self._candidate_command(
                state,
                step="db-check",
                argv=("blockwart-db", "check"),
                gate="candidate_db_check",
            )
        with gates.gate("candidate_integrity"):
            self._candidate_command(
                state,
                step="integrity",
                argv=("blockwart-db", "integrity"),
                gate="candidate_integrity",
            )
        with gates.gate("candidate_started"):
            result = self.engine.run_detached(
                self._candidate_run_argv(state),
                timeout_seconds=self.spec.timeouts.command_seconds,
            )
            if not result.ok:
                raise ReleaseError("candidate_start_failed", gate="candidate_started")
        with gates.gate("candidate_runtime_layout"):
            self._verify_candidate_runtime_layout(state)
        with gates.gate("candidate_readiness"):
            state.candidate_readiness = self._await_readiness(
                candidate_name,
                gate="candidate_readiness",
                timeout_seconds=self.spec.timeouts.readiness_seconds,
                expected_revision=self.spec.expected_schema_revision,
                expected_build_revision=self.spec.source.commit,
                prefix="candidate",
            )
        with gates.gate("candidate_health"):
            self._await_health(
                candidate_name,
                gate="candidate_health",
                timeout_seconds=self.spec.timeouts.health_seconds,
                not_before=state.candidate_readiness.observed_at,
                prefix="candidate",
            )

    def _cutover(self, *, gates: GateLog, state: _ApplyState) -> None:
        """Replace the running service and prove the new release, fail-closed."""
        name = self.spec.service.container_name
        with gates.gate("cutover_service_stopped"):
            if self.engine.container_exists(name):
                stopped = self.engine.stop_container(
                    name, stop_seconds=self.spec.timeouts.stop_seconds
                )
                # The running service is the point of no return: once it is
                # stopped, every later failure must roll back.
                state.cutover_started = True
                if stopped.timed_out:
                    raise ReleaseError("cutover_timeout", gate="cutover_service_stopped")
                if not stopped.ok:
                    raise ReleaseError("cutover_stop_failed", gate="cutover_service_stopped")
                removed = self.engine.remove_container(
                    name, stop_seconds=self.spec.timeouts.stop_seconds
                )
                if not removed.ok:
                    raise ReleaseError("cutover_remove_failed", gate="cutover_service_stopped")
        with gates.gate("cutover_database_snapshot"):
            self._refresh_backup_after_stop(state)
        with gates.gate("cutover_service_started"):
            state.cutover_started = True
            result = self.engine.run_detached(
                self._service_run_argv(
                    state.image_digest,
                    build_revision=self.spec.source.commit,
                ),
                timeout_seconds=self.spec.timeouts.cutover_seconds,
            )
            if result.timed_out:
                raise ReleaseError("cutover_timeout", gate="cutover_service_started")
            if not result.ok:
                raise ReleaseError("cutover_start_failed", gate="cutover_service_started")
        with gates.gate("cutover_runtime_layout"):
            self._verify_service_runtime_layout(
                name,
                image_digest=state.image_digest,
                build_revision=self.spec.source.commit,
                gate="cutover_runtime_layout",
            )
        with gates.gate("cutover_readiness"):
            state.service_readiness = self._await_readiness(
                name,
                gate="cutover_readiness",
                timeout_seconds=self.spec.timeouts.readiness_seconds,
                expected_revision=self.spec.expected_schema_revision,
                expected_build_revision=self.spec.source.commit,
                prefix="cutover",
            )
        with gates.gate("cutover_health"):
            self._await_health(
                name,
                gate="cutover_health",
                timeout_seconds=self.spec.timeouts.health_seconds,
                not_before=state.service_readiness.observed_at,
                prefix="cutover",
            )
        with gates.gate("cutover_schema"):
            result = self.engine.execute(
                name,
                ("blockwart-db", "check"),
                timeout_seconds=self.spec.timeouts.command_seconds,
            )
            if not result.ok:
                raise ReleaseError("cutover_schema_check_failed", gate="cutover_schema")
        with gates.gate("cutover_integrity"):
            result = self.engine.execute(
                name,
                ("blockwart-db", "integrity"),
                timeout_seconds=self.spec.timeouts.command_seconds,
            )
            if not result.ok:
                raise ReleaseError("cutover_integrity_failed", gate="cutover_integrity")

    def _run_hooks(self, *, gates: GateLog, state: _ApplyState) -> None:
        if not self.spec.hooks:
            gates.record("hooks", GATE_STATUS_SKIPPED)
            return
        values = {
            "BLOCKWART_RELEASE_ID": self.release_id,
            "BLOCKWART_RELEASE_SOURCE_COMMIT": self.spec.source.commit,
            "BLOCKWART_RELEASE_IMAGE_DIGEST": state.image_digest,
            "BLOCKWART_RELEASE_MANIFEST_DIGEST": state.manifest_digest or "",
            "BLOCKWART_RELEASE_SCHEMA_REVISION": self.spec.expected_schema_revision,
            "BLOCKWART_RELEASE_OUTCOME": "verified",
        }
        # Hooks receive the allowlisted keys only; nothing else crosses the boundary.
        context = {key: values[key] for key in HOOK_CONTEXT_KEYS}
        with gates.gate("hooks"):
            for hook in self.spec.hooks:
                result = self.runner.run(
                    hook.argv,
                    timeout_seconds=hook.timeout_seconds,
                    context=context,
                )
                if result.timed_out:
                    state.hooks.append(
                        {"name": hook.name, "status": "failed", "code": "hook_timeout"}
                    )
                    raise ReleaseError("hook_timeout", gate="hooks")
                if not result.ok:
                    state.hooks.append(
                        {"name": hook.name, "status": "failed", "code": "hook_failed"}
                    )
                    raise ReleaseError("hook_failed", gate="hooks")
                state.hooks.append({"name": hook.name, "status": "passed", "code": None})

    def _commit_pointers(self, *, gates: GateLog, state: _ApplyState) -> None:
        with gates.gate("pointers_committed"):
            layout_digest = self._verify_service_runtime_layout(
                self.spec.service.container_name,
                image_digest=state.image_digest,
                build_revision=self.spec.source.commit,
                gate="pointers_committed",
            )
            generation = self.store.next_generation()
            pointer = Pointer(
                release_id=self.release_id,
                generation=generation,
                manifest_digest=str(state.manifest_digest),
                image_digest=state.image_digest,
                source_commit=self.spec.source.commit,
                schema_revision=self.spec.expected_schema_revision,
                runtime_layout_digest=layout_digest,
                updated_at=self._timestamp(),
            )
            state.pointer_mutation_started = True
            self.store.write_pointers(current=pointer, previous=state.current)
            state.committed_current = pointer
            state.committed_previous = state.current
            self.store.append_history(
                {
                    "generation": generation,
                    "release_id": self.release_id,
                    "image_digest": state.image_digest,
                    "manifest_digest": state.manifest_digest,
                    "source_commit": self.spec.source.commit,
                    "outcome": OUTCOME_SUCCEEDED,
                    "committed_at": pointer.updated_at,
                }
            )
            state.pointers_committed = True

    def _apply_retention(
        self,
        *,
        gates: GateLog,
        state: _ApplyState,
        diagnostics: list[dict[str, str]],
    ) -> str:
        protected = [self.release_id]
        if state.committed_previous is not None:
            protected.append(state.committed_previous.release_id)
        if state.previous is not None:
            # Completion-report persistence can still restore the complete
            # pre-transaction current/previous pointer pair.
            protected.append(state.previous.release_id)
        try:
            removed = self.store.prune(
                retention=self.spec.state.retention, protected=protected
            )
            backup_removed = prune_managed_backups(
                self.paths.backup_root,
                retention=self.spec.state.retention,
                protected=(state.backup_directory(self.paths),),
            )
            image_references_removed = self._prune_image_references(removed)
        except (ReleaseError, OSError):
            # Bounded housekeeping never invalidates a verified release; the
            # active and rollback bundles are protected either way.
            gates.record("retention_applied", GATE_STATUS_FAILED, "retention_incomplete")
            diagnostics.append({"gate": "retention_applied", "code": "retention_incomplete"})
            state.retention = {
                "retained": len(protected),
                "removed": [],
                "backup_directories_removed": [],
                "image_references_removed": [],
            }
            return
        gates.record("retention_applied", GATE_STATUS_PASSED)
        state.retention = {
            "retained": self.spec.state.retention,
            "removed": list(removed),
            "backup_directories_removed": list(backup_removed),
            "image_references_removed": list(image_references_removed),
        }

    def _prune_image_references(
        self, removed_release_ids: Sequence[str]
    ) -> tuple[str, ...]:
        removed: list[str] = []
        for release_id in removed_release_ids:
            for reference in (
                f"{self.spec.image.repository}:{release_id}",
                f"{self.spec.image.repository}:rollback-{release_id}",
            ):
                if self.engine.image_id(reference) is None:
                    continue
                result = self.engine.remove_image_reference(reference)
                if not result.ok:
                    raise ReleaseError(
                        "retention_image_remove_failed", gate="retention_applied"
                    )
                removed.append(reference)
        return tuple(removed)

    # ------------------------------------------------------------------
    # rollback
    # ------------------------------------------------------------------
    def _rollback(
        self,
        *,
        gates: GateLog,
        state: _ApplyState,
        started_at: str,
        diagnostics: list[dict[str, str]],
        failure: ReleaseError,
    ) -> dict[str, Any]:
        """Restore the exact previous image and verified pre-release backup."""
        if not state.cutover_started:
            raise failure
        diagnostics.append({"gate": failure.gate, "code": failure.code})
        evidence: dict[str, Any] = {
            "triggered_by": {"gate": failure.gate, "code": failure.code},
            "previous_release_id": state.current.release_id if state.current else None,
            "previous_image_digest": state.previous_image_digest,
            "restored_backup_sha256": state.backup.backup_sha256 if state.backup else None,
            "database_restored": False,
            "failed_database_preserved": False,
            "pointers_restored": False,
            "service_contained": False,
        }
        name = self.spec.service.container_name
        try:
            with gates.gate("rollback_service_stopped"):
                if self.engine.container_exists(name):
                    stopped = self.engine.stop_container(
                        name, stop_seconds=self.spec.timeouts.stop_seconds
                    )
                    if stopped.timed_out:
                        raise ReleaseError(
                            "rollback_timeout", gate="rollback_service_stopped"
                        )
                    if not stopped.ok:
                        raise ReleaseError(
                            "rollback_stop_failed", gate="rollback_service_stopped"
                        )
                    removed = self.engine.remove_container(
                        name, stop_seconds=self.spec.timeouts.stop_seconds
                    )
                    if not removed.ok:
                        raise ReleaseError(
                            "rollback_remove_failed", gate="rollback_service_stopped"
                        )
            with gates.gate("rollback_database_restored"):
                if state.backup is None:
                    raise ReleaseError("rollback_backup_missing", gate="rollback_database_restored")
                self._refresh_rollback_backup_if_needed(state)
                evidence["restored_backup_sha256"] = state.backup.backup_sha256
                verify_backup(
                    state.backup_path(self.paths),
                    state.backup,
                    gate="rollback_database_restored",
                    timeout_seconds=self.spec.timeouts.command_seconds,
                    monotonic=self.clock.monotonic,
                )
                restored_digest, failed_database_preserved = restore_live_database(
                    backup_path=state.backup_path(self.paths),
                    database_path=self.paths.database_path,
                    evidence_path=state.failed_database_path(self.paths),
                    gate="rollback_database_restored",
                    timeout_seconds=self.spec.timeouts.command_seconds,
                    monotonic=self.clock.monotonic,
                )
                if restored_digest != state.backup.backup_sha256:
                    raise ReleaseError(
                        "rollback_database_digest_mismatch",
                        gate="rollback_database_restored",
                    )
                evidence["database_restored"] = True
                evidence["failed_database_preserved"] = failed_database_preserved
            self._restore_previous_service(gates=gates, state=state, evidence=evidence)
            with gates.gate("rollback_pointers_restored"):
                self._restore_pointers(state)
                evidence["pointers_restored"] = True
        except ReleaseError as exc:
            contained, containment_error = self._contain_failed_service(name)
            evidence["service_contained"] = contained
            if containment_error is not None:
                evidence["containment_error"] = containment_error
            evidence["rollback_error"] = {"gate": exc.gate, "code": exc.code}
            state.rollback_evidence = evidence
            raise ReleaseRollbackError(
                exc.code, gate=exc.gate, original_code=failure.code
            ) from exc

        state.rollback_evidence = evidence
        evidence["service_contained"] = False
        report = self._report(
            mode=APPLY_MODE,
            outcome=OUTCOME_ROLLED_BACK,
            gates=gates,
            started_at=started_at,
            changed=False,
            replayed=False,
            source=state.source,
            image_digest=state.image_digest,
            manifest=state.manifest,
            manifest_digest=state.manifest_digest,
            current=state.current,
            previous=state.previous,
            diagnostics=diagnostics,
            backup=state.backup,
            hooks=state.hooks,
            rollback=evidence,
            error=failure.code,
        )
        try:
            self.store.write_report(f"{self.release_id}-{state.token}", report)
        except (ReleaseError, OSError):
            report["diagnostics"].append(
                {"gate": "report", "code": "report_not_persisted"}
            )
            report["report_digest"] = domain_digest(
                "report",
                {
                    key: value
                    for key, value in report.items()
                    if key not in _VOLATILE_REPORT_KEYS
                },
            )
        return report

    def _refresh_rollback_backup_if_needed(self, state: _ApplyState) -> None:
        """Preserve writes when cutover failed before the post-stop snapshot."""
        if state.backup is None or state.backup.backup_file != "pre-release.sqlite3":
            return
        rollback_path = state.backup_directory(self.paths) / "rollback-cutover.sqlite3"
        refreshed = create_online_backup(
            database_path=self.paths.database_path,
            backup_path=rollback_path,
            release_id=self.release_id,
            source_commit=self.spec.source.commit,
            created_at=self._timestamp(),
            timeout_seconds=self.spec.timeouts.command_seconds,
            monotonic=self.clock.monotonic,
        )
        verify_backup(
            rollback_path,
            refreshed,
            gate="rollback_database_restored",
            timeout_seconds=self.spec.timeouts.command_seconds,
            monotonic=self.clock.monotonic,
        )
        state.backup = refreshed

    def _restore_previous_service(
        self,
        *,
        gates: GateLog,
        state: _ApplyState,
        evidence: dict[str, Any],
    ) -> None:
        """Start the exact previous image and re-prove its release gates."""
        name = self.spec.service.container_name
        if state.previous_image_digest is None:
            # No recorded predecessor: the verified database is restored and the
            # service stays stopped rather than being started from a guess.
            for gate_name in (
                "rollback_service_started",
                "rollback_runtime_layout",
                "rollback_readiness",
                "rollback_health",
                "rollback_schema",
                "rollback_integrity",
            ):
                gates.record(gate_name, GATE_STATUS_SKIPPED)
            evidence["service_restored"] = False
            return
        with gates.gate("rollback_service_started"):
            result = self.engine.run_detached(
                self._service_run_argv(
                    state.previous_image_digest,
                    build_revision=(
                        state.current.source_commit
                        if state.current is not None
                        else self.spec.source.commit
                    ),
                ),
                timeout_seconds=self.spec.timeouts.rollback_seconds,
            )
            if result.timed_out:
                raise ReleaseError("rollback_timeout", gate="rollback_service_started")
            if not result.ok:
                raise ReleaseError("rollback_start_failed", gate="rollback_service_started")
        with gates.gate("rollback_runtime_layout"):
            self._verify_service_runtime_layout(
                name,
                image_digest=state.previous_image_digest,
                build_revision=(
                    state.current.source_commit
                    if state.current is not None
                    else self.spec.source.commit
                ),
                gate="rollback_runtime_layout",
            )
        with gates.gate("rollback_readiness"):
            readiness = self._await_readiness(
                name,
                gate="rollback_readiness",
                timeout_seconds=self.spec.timeouts.readiness_seconds,
                expected_revision=(
                    state.current.schema_revision if state.current is not None else None
                ),
                expected_build_revision=(
                    state.current.source_commit if state.current is not None else None
                ),
                prefix="rollback",
            )
            evidence["readiness_revision"] = readiness.revision
        with gates.gate("rollback_health"):
            self._await_health(
                name,
                gate="rollback_health",
                timeout_seconds=self.spec.timeouts.health_seconds,
                not_before=readiness.observed_at,
                prefix="rollback",
            )
        with gates.gate("rollback_schema"):
            result = self.engine.execute(
                name,
                ("blockwart-db", "check"),
                timeout_seconds=self.spec.timeouts.command_seconds,
            )
            if not result.ok:
                raise ReleaseError("rollback_schema_check_failed", gate="rollback_schema")
        with gates.gate("rollback_integrity"):
            result = self.engine.execute(
                name,
                ("blockwart-db", "integrity"),
                timeout_seconds=self.spec.timeouts.command_seconds,
            )
            if not result.ok:
                raise ReleaseError("rollback_integrity_failed", gate="rollback_integrity")
        evidence["service_restored"] = True

    def _contain_failed_service(
        self, name: str
    ) -> tuple[bool, dict[str, str] | None]:
        """Ensure an unverified restored service cannot remain published."""
        if not self.engine.container_exists(name):
            return True, None
        stopped = self.engine.stop_container(
            name, stop_seconds=self.spec.timeouts.stop_seconds
        )
        removed = self.engine.remove_container(
            name, stop_seconds=self.spec.timeouts.stop_seconds
        )
        if removed.ok and not removed.timed_out and not self.engine.container_exists(name):
            return True, None
        code = "rollback_containment_timeout" if (
            stopped.timed_out or removed.timed_out
        ) else "rollback_containment_failed"
        return False, {"gate": "rollback_containment", "code": code}

    def _restore_pointers(self, state: _ApplyState) -> None:
        if not state.pointer_mutation_started:
            return
        self.store.write_pointers(current=state.current, previous=state.previous)
        self.store.append_history(
            {
                "generation": state.committed_current.generation
                if state.committed_current
                else 0,
                "release_id": self.release_id,
                "image_digest": state.image_digest,
                "manifest_digest": state.manifest_digest,
                "source_commit": self.spec.source.commit,
                "outcome": OUTCOME_ROLLED_BACK,
                "committed_at": self._timestamp(),
            }
        )

    # ------------------------------------------------------------------
    # gate helpers
    # ------------------------------------------------------------------
    def _await_readiness(
        self,
        name: str,
        *,
        gate: str,
        timeout_seconds: int,
        expected_revision: str | None,
        expected_build_revision: str | None,
        prefix: str,
    ) -> ReadinessObservation:
        """Poll Blockwart's own internal readiness contract inside the container."""
        deadline = self.clock.monotonic() + timeout_seconds
        last_code = f"{prefix}_readiness_timeout"
        while True:
            remaining = deadline - self.clock.monotonic()
            probe_timeout = max(
                1,
                min(self.spec.timeouts.command_seconds, math.ceil(max(remaining, 0))),
            )
            result = self.engine.execute(
                name,
                ("python", "-c", READINESS_PROBE),
                timeout_seconds=probe_timeout,
            )
            observed_at = self.clock.now()
            if result.ok:
                payload = _parse_probe_json(result.stdout)
                if payload is not None and payload.get("ok") is True:
                    revision = payload.get("revision")
                    build_revision = payload.get("build_revision")
                    if expected_revision is not None and revision != expected_revision:
                        raise ReleaseError(f"{prefix}_schema_mismatch", gate=gate)
                    if (
                        expected_build_revision is not None
                        and build_revision != expected_build_revision
                    ):
                        raise ReleaseError(f"{prefix}_build_revision_mismatch", gate=gate)
                    return ReadinessObservation(
                        ok=True,
                        revision=revision if isinstance(revision, str) else None,
                        build_revision=(
                            build_revision if isinstance(build_revision, str) else None
                        ),
                        error_code=None,
                        observed_at=observed_at,
                    )
                if payload is not None and isinstance(payload.get("error_code"), str):
                    last_code = f"{prefix}_not_ready"
            if self.clock.monotonic() >= deadline:
                raise ReleaseError(last_code, gate=gate)
            self.clock.sleep(self.spec.timeouts.poll_interval_seconds)

    def _await_health(
        self,
        name: str,
        *,
        gate: str,
        timeout_seconds: int,
        not_before: datetime,
        prefix: str,
    ) -> None:
        """Container health is a separate gate from internal readiness.

        Readiness can pass while the container healthcheck still reports its
        previous ``starting``/``unhealthy`` result. Accepting that stale
        observation is the known readiness-before-health race, so a health
        probe is accepted only when it finished after readiness succeeded.
        """
        deadline = self.clock.monotonic() + timeout_seconds
        last_code = f"{prefix}_health_timeout"
        while True:
            remaining = deadline - self.clock.monotonic()
            probe_timeout = max(
                1,
                min(self.spec.timeouts.command_seconds, math.ceil(max(remaining, 0))),
            )
            observation = self.engine.health(name, timeout_seconds=probe_timeout)
            if observation.status == "healthy":
                if observation.last_probe_end is None:
                    last_code = f"{prefix}_health_unobserved"
                elif observation.last_probe_end <= not_before:
                    last_code = f"{prefix}_health_stale"
                else:
                    return
            elif observation.status == "unhealthy":
                last_code = f"{prefix}_health_unhealthy"
            elif observation.status in {"none", "unknown"}:
                last_code = f"{prefix}_health_unavailable"
            if self.clock.monotonic() >= deadline:
                raise ReleaseError(last_code, gate=gate)
            self.clock.sleep(self.spec.timeouts.poll_interval_seconds)

    def _verify_current_pointer(self, expect_current: str | None) -> Pointer | None:
        current = self._read_pointer_if_present(CURRENT_POINTER)
        expected = None if expect_current in {None, "none"} else expect_current
        if expected is not None and (current is None or current.release_id != expected):
            raise ReleaseError("stale_current_pointer", gate="current_pointer_verified")
        if expect_current == "none" and current is not None:
            raise ReleaseError("stale_current_pointer", gate="current_pointer_verified")
        name = self.spec.service.container_name
        running_image = self.engine.container_image_id(name)
        if current is not None:
            if current.runtime_layout_digest != runtime_layout_digest(
                self.spec, build_revision=current.source_commit
            ):
                raise ReleaseError(
                    "current_runtime_layout_drift", gate="current_pointer_verified"
                )
            try:
                manifest_digest = self.store.verify_bundle(current.release_id)
            except ReleaseError as exc:
                raise ReleaseError(exc.code, gate="current_pointer_verified") from exc
            if manifest_digest != current.manifest_digest:
                raise ReleaseError(
                    "current_pointer_manifest_drift", gate="current_pointer_verified"
                )
            manifest = self.store.read_manifest(current.release_id)
            if (
                manifest.get("source", {}).get("commit") != current.source_commit
                or manifest.get("image", {}).get("digest") != current.image_digest
                or manifest.get("schema", {}).get("packaged_revision")
                != current.schema_revision
            ):
                raise ReleaseError(
                    "current_pointer_evidence_drift", gate="current_pointer_verified"
                )
            if self.engine.image_id(current.image_digest) != current.image_digest:
                raise ReleaseError(
                    "rollback_image_missing", gate="current_pointer_verified"
                )
            self._require_image_build_revision(
                current.image_digest,
                current.source_commit,
                gate="current_pointer_verified",
            )
        if running_image is None:
            if current is not None:
                raise ReleaseError(
                    "current_service_missing", gate="current_pointer_verified"
                )
            return None
        if current is None:
            raise ReleaseError("unmanaged_service_state", gate="current_pointer_verified")
        if running_image != current.image_digest:
            raise ReleaseError("current_pointer_image_drift", gate="current_pointer_verified")
        if self.engine.container_state(name) != "running":
            raise ReleaseError("current_service_not_running", gate="current_pointer_verified")
        self._verify_service_runtime_layout(
            name,
            image_digest=current.image_digest,
            build_revision=current.source_commit,
            gate="current_pointer_verified",
        )
        return current

    def _verify_service_runtime_layout(
        self,
        name: str,
        *,
        image_digest: str,
        build_revision: str,
        gate: str,
    ) -> None:
        configuration = self.engine.container_configuration(name)
        image_environment = _environment_mapping(
            self.engine.image_environment(image_digest, gate=gate)
        )
        actual_environment = (
            _environment_mapping(configuration.environment)
            if configuration is not None
            else None
        )
        expected_environment = dict(image_environment or {})
        expected_environment.update(
            runtime_environment(self.spec, build_revision=build_revision)
        )
        host_ip, host_port, container_port = self.spec.service.publish.split(":")
        expected_mounts = (
            (
                "bind",
                str(self.paths.data_directory),
                self.spec.service.container_data_path,
                True,
            ),
        )
        expected_ports = ((f"{container_port}/tcp", host_ip, host_port),)
        if (
            configuration is None
            or image_environment is None
            or actual_environment is None
            or configuration.mounts != expected_mounts
            or configuration.published_ports != expected_ports
            or configuration.restart_policy != "unless-stopped"
            or configuration.network_mode
            != ("default" if self.spec.image.runtime == "docker" else "bridge")
            or actual_environment != expected_environment
        ):
            code = (
                "current_runtime_layout_drift"
                if gate == "current_pointer_verified"
                else f"{gate}_drift"
            )
            raise ReleaseError(code, gate=gate)
        # The digest is accepted only after every field above came from daemon
        # inspection and matched the effective service contract.
        return runtime_layout_digest(self.spec, build_revision=build_revision)

    def _verify_candidate_runtime_layout(self, state: _ApplyState) -> None:
        configuration = self.engine.container_configuration(
            state.candidate_container(self.spec)
        )
        image_environment = _environment_mapping(
            self.engine.image_environment(state.image_digest, gate="candidate_runtime_layout")
        )
        actual_environment = (
            _environment_mapping(configuration.environment)
            if configuration is not None
            else None
        )
        expected_environment = dict(image_environment or {})
        expected_environment.update(
            runtime_environment(self.spec, build_revision=self.spec.source.commit)
        )
        expected_mounts = (
            (
                "bind",
                str(state.candidate_directory(self.paths)),
                self.spec.service.container_data_path,
                True,
            ),
        )
        if (
            configuration is None
            or image_environment is None
            or actual_environment is None
            or configuration.mounts != expected_mounts
            or configuration.published_ports
            or configuration.restart_policy != "no"
            or configuration.network_mode != "none"
            or actual_environment != expected_environment
        ):
            raise ReleaseError(
                "candidate_runtime_layout_drift", gate="candidate_runtime_layout"
            )

    def _is_replay(self, state: _ApplyState) -> bool:
        current = state.current
        if current is None or current.release_id != self.release_id:
            return False
        return self.store.verify_bundle(self.release_id) == current.manifest_digest

    def _reverify_source(self, expected: SourceEvidence) -> None:
        try:
            observed = verify_source(
                runner=self.runner,
                repository_root=self.paths.repository_root,
                commit=self.spec.source.commit,
                timeout_seconds=self.spec.timeouts.command_seconds,
            )
        except ReleaseError as exc:
            raise ReleaseError(exc.code, gate="source_reverified") from exc
        if observed != expected:
            raise ReleaseError("source_evidence_drift", gate="source_reverified")

    def _pin_rollback_image(self, state: _ApplyState) -> None:
        if state.current is None:
            return
        tag = f"{self.spec.image.repository}:rollback-{state.current.release_id}"
        result = self.engine.tag_image(state.current.image_digest, tag)
        if not result.ok or self.engine.image_id(tag) != state.current.image_digest:
            raise ReleaseError("rollback_image_pin_failed", gate="rollback_image_pinned")
        state.rollback_image_tag = tag

    def _resolve_image(self, source: SourceEvidence) -> str:
        if self.spec.image.mode == "existing":
            return self._resolve_existing_image(source)
        tag = self._image_tag()
        with self._exact_build_context(source) as context:
            result = self.engine.build_image(
                context=str(context),
                containerfile=str(context / self.spec.image.containerfile),
                tag=tag,
                build_revision=source.commit,
                timeout_seconds=self.spec.timeouts.build_seconds,
            )
        if result.timed_out:
            raise ReleaseError("image_build_timeout", gate="image_resolved")
        if not result.ok:
            raise ReleaseError("image_build_failed", gate="image_resolved")
        digest = self.engine.image_id(tag)
        if digest is None or not is_image_digest(digest):
            raise ReleaseError("image_digest_unresolved", gate="image_resolved")
        self._require_image_build_revision(digest, source.commit)
        return digest

    @contextmanager
    def _exact_build_context(self, source: SourceEvidence) -> Iterator[Path]:
        """Materialize only the tracked tree bound by the verified commit.

        `git archive` cannot include ignored or untracked host files. Archive
        entries are then extracted with an allowlist that rejects links,
        devices, and traversal before the directory is handed to the runtime.
        """
        temporary = Path(
            tempfile.mkdtemp(prefix=".build-context-", dir=self.paths.state_root)
        )
        os.chmod(temporary, 0o750)
        archive = temporary / "source.tar"
        context = temporary / "tree"
        context.mkdir(mode=0o750)
        try:
            result = self.runner.run(
                (
                    "git",
                    "-C",
                    str(self.paths.repository_root),
                    "--no-pager",
                    "archive",
                    "--format=tar",
                    f"--output={archive}",
                    source.commit,
                ),
                timeout_seconds=self.spec.timeouts.command_seconds,
            )
            if result.timed_out:
                raise ReleaseError("source_archive_timeout", gate="image_resolved")
            if not result.ok or not archive.is_file() or archive.is_symlink():
                raise ReleaseError("source_archive_failed", gate="image_resolved")
            self._extract_source_archive(archive, context)
            containerfile = context / self.spec.image.containerfile
            if not containerfile.is_file() or containerfile.is_symlink():
                raise ReleaseError("source_containerfile_missing", gate="image_resolved")
            yield context
        finally:
            shutil.rmtree(temporary, ignore_errors=True)

    @staticmethod
    def _extract_source_archive(archive: Path, context: Path) -> None:
        try:
            with tarfile.open(archive, mode="r:") as source:
                for member in source.getmembers():
                    relative = PurePosixPath(member.name)
                    if (
                        relative.is_absolute()
                        or not relative.parts
                        or ".." in relative.parts
                        or member.issym()
                        or member.islnk()
                        or not (member.isdir() or member.isfile())
                    ):
                        raise ReleaseError(
                            "unsafe_source_archive", gate="image_resolved"
                        )
                    target = context.joinpath(*relative.parts)
                    if member.isdir():
                        target.mkdir(mode=0o750, parents=True, exist_ok=True)
                        continue
                    target.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
                    extracted = source.extractfile(member)
                    if extracted is None:
                        raise ReleaseError(
                            "unsafe_source_archive", gate="image_resolved"
                        )
                    with extracted, target.open("xb") as destination:
                        shutil.copyfileobj(extracted, destination)
                    os.chmod(target, member.mode & 0o755)
        except (OSError, tarfile.TarError) as exc:
            raise ReleaseError("source_archive_failed", gate="image_resolved") from exc

    def _resolve_existing_image(self, source: SourceEvidence) -> str:
        declared = self.spec.image.digest
        if declared is None:
            raise ReleaseError("image_digest_required", gate="image_resolved")
        digest = self.engine.image_id(declared)
        if digest is None:
            raise ReleaseError("image_missing", gate="image_resolved")
        if digest != declared:
            raise ReleaseError("image_digest_mismatch", gate="image_resolved")
        self._require_image_build_revision(digest, source.commit)
        return digest

    def _require_image_build_revision(
        self, digest: str, commit: str, *, gate: str = "image_resolved"
    ) -> None:
        """Missing or mismatched build evidence stops the release before any mutation."""
        environment = self.engine.image_environment(digest, gate=gate)
        revisions = [
            item.split("=", 1)[1]
            for item in environment
            if item.startswith("BLOCKWART_BUILD_REVISION=")
        ]
        if not revisions:
            raise ReleaseError("image_build_revision_missing", gate=gate)
        if revisions[-1] != commit:
            raise ReleaseError("image_build_revision_mismatch", gate=gate)

    def _verify_packaged_schema(self, image_digest: str) -> str:
        result = self._run_named_once(
            name=f"{self.spec.service.container_name}-release-{self.release_id}-packaged-schema",
            argv=(image_digest, "python", "-c", PACKAGED_SCHEMA_PROBE),
            gate="packaged_schema",
        )
        payload = _parse_probe_json(result.stdout)
        if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], str):
            raise ReleaseError("packaged_schema_unreadable", gate="packaged_schema")
        if payload[0] != self.spec.expected_schema_revision:
            raise ReleaseError("packaged_schema_mismatch", gate="packaged_schema")
        return payload[0]

    def _candidate_schema_revision(self, state: _ApplyState) -> str:
        result = self._candidate_command(
            state,
            step="schema",
            argv=("python", "-c", PACKAGED_SCHEMA_PROBE),
            gate="candidate_schema",
        )
        payload = _parse_probe_json(result.stdout)
        if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], str):
            raise ReleaseError("candidate_schema_unreadable", gate="candidate_schema")
        return payload[0]

    def _candidate_command(
        self,
        state: _ApplyState,
        *,
        step: str,
        argv: Sequence[str],
        gate: str,
    ) -> CommandResult:
        result = self._run_named_once(
            name=f"{state.candidate_container(self.spec)}-{step}",
            argv=(
                *self._candidate_mount_argv(state),
                state.image_digest,
                *argv,
            ),
            gate=gate,
        )
        return result

    def _run_named_once(
        self, *, name: str, argv: Sequence[str], gate: str
    ) -> CommandResult:
        if self.engine.container_exists(name):
            stale = self.engine.remove_container(
                name, stop_seconds=self.spec.timeouts.stop_seconds
            )
            if stale.timed_out or not stale.ok:
                raise ReleaseError(f"{gate}_cleanup_failed", gate=gate)
        result = self.engine.run_once(
            ("--name", name, *argv),
            timeout_seconds=self.spec.timeouts.command_seconds,
        )
        cleanup_failed = False
        if self.engine.container_exists(name):
            cleanup = self.engine.remove_container(
                name, stop_seconds=self.spec.timeouts.stop_seconds
            )
            cleanup_failed = cleanup.timed_out or not cleanup.ok
        if cleanup_failed:
            raise ReleaseError(f"{gate}_cleanup_failed", gate=gate)
        if result.timed_out:
            raise ReleaseError(f"{gate}_timeout", gate=gate)
        if not result.ok:
            code = (
                "packaged_schema_unreadable"
                if gate == "packaged_schema"
                else f"{gate}_failed"
            )
            raise ReleaseError(code, gate=gate)
        return result

    def _create_backup(self, state: _ApplyState) -> BackupReceipt:
        root = self.paths.backup_root
        if not root.exists():
            try:
                root.mkdir(mode=0o750, parents=False)
                os.chmod(root, 0o750)
                fsync_directory(root.parent)
            except FileExistsError:
                pass
            except OSError as exc:
                raise ReleaseError("unsafe_backup_root", gate="database_backup") from exc
        require_protected_directory(root, code="unsafe_backup_root")
        directory = state.backup_directory(self.paths)
        try:
            directory.mkdir(mode=0o750, parents=False, exist_ok=False)
            os.chmod(directory, 0o750)
            fsync_directory(root)
        except FileExistsError:
            pass
        except OSError as exc:
            raise ReleaseError("unsafe_backup_root", gate="database_backup") from exc
        require_protected_directory(directory, code="unsafe_backup_root")
        receipt = create_online_backup(
            database_path=self.paths.database_path,
            backup_path=state.backup_path(self.paths),
            release_id=self.release_id,
            source_commit=self.spec.source.commit,
            created_at=self._timestamp(),
            timeout_seconds=self.spec.timeouts.command_seconds,
            monotonic=self.clock.monotonic,
        )
        verify_backup(
            state.backup_path(self.paths),
            receipt,
            gate="database_backup",
            timeout_seconds=self.spec.timeouts.command_seconds,
            monotonic=self.clock.monotonic,
        )
        return receipt

    def _refresh_backup_after_stop(self, state: _ApplyState) -> None:
        """Bind rollback to the exact database state observed after writes stop.

        Candidate proof is valid only while the live database is unchanged. A
        changed snapshot fails closed and rolls the previous service forward
        on the new verified snapshot instead of losing intervening writes.
        """
        original = state.backup
        if original is None:
            raise ReleaseError(
                "rollback_backup_missing", gate="cutover_database_snapshot"
            )
        final_path = state.backup_directory(self.paths) / "cutover.sqlite3"
        final = create_online_backup(
            database_path=self.paths.database_path,
            backup_path=final_path,
            release_id=self.release_id,
            source_commit=self.spec.source.commit,
            created_at=self._timestamp(),
            timeout_seconds=self.spec.timeouts.command_seconds,
            monotonic=self.clock.monotonic,
        )
        verify_backup(
            final_path,
            final,
            gate="cutover_database_snapshot",
            timeout_seconds=self.spec.timeouts.command_seconds,
            monotonic=self.clock.monotonic,
        )
        state.backup = final
        if final.backup_sha256 != original.backup_sha256:
            raise ReleaseError(
                "stale_live_database", gate="cutover_database_snapshot"
            )

    def _release_candidate(self, state: _ApplyState) -> None:
        name = state.candidate_container(self.spec)
        if not self.engine.container_exists(name):
            return
        result = self.engine.remove_container(
            name, stop_seconds=self.spec.timeouts.stop_seconds
        )
        if result.timed_out:
            raise ReleaseError("candidate_cleanup_timeout", gate="candidate_cleanup")
        if not result.ok:
            raise ReleaseError("candidate_cleanup_failed", gate="candidate_cleanup")

    def _discard_candidate_database(self, state: _ApplyState) -> None:
        directory = state.candidate_directory(self.paths)
        if directory.is_dir() and not directory.is_symlink():
            shutil.rmtree(directory, ignore_errors=True)

    # ------------------------------------------------------------------
    # argv construction
    # ------------------------------------------------------------------
    def _database_url(self) -> str:
        return (
            f"sqlite:///{self.spec.service.container_data_path}/"
            f"{self.spec.service.database_filename}"
        )

    def _candidate_mount_argv(self, state: _ApplyState) -> tuple[str, ...]:
        return (
            "--volume",
            f"{state.candidate_directory(self.paths)}:{self.spec.service.container_data_path}",
            "--network",
            "none",
            "--env",
            f"BLOCKWART_DATABASE_URL={self._database_url()}",
            "--env",
            f"BLOCKWART_BUILD_REVISION={self.spec.source.commit}",
        )

    def _candidate_run_argv(self, state: _ApplyState) -> tuple[str, ...]:
        argv: list[str] = [
            "--name",
            state.candidate_container(self.spec),
            "--restart",
            "no",
        ]
        if self.spec.service.environment_file is not None:
            argv.extend(("--env-file", str(self.paths.environment_file)))
        argv.extend(self._candidate_mount_argv(state))
        argv.append(state.image_digest)
        return tuple(argv)

    def _service_run_argv(
        self, image_digest: str, *, build_revision: str
    ) -> tuple[str, ...]:
        argv: list[str] = [
            "--name",
            self.spec.service.container_name,
            "--restart",
            "unless-stopped",
        ]
        if self.spec.service.environment_file is not None:
            argv.extend(("--env-file", str(self.paths.environment_file)))
        argv.extend(
            (
                "--volume",
                f"{self.paths.data_directory}:{self.spec.service.container_data_path}",
                "--env",
                f"BLOCKWART_DATABASE_URL={self._database_url()}",
                "--env",
                f"BLOCKWART_BUILD_REVISION={build_revision}",
                "--publish",
                self.spec.service.publish,
                image_digest,
            )
        )
        return tuple(argv)

    def _image_tag(self) -> str:
        return f"{self.spec.image.repository}:{self.release_id}"

    # ------------------------------------------------------------------
    # shared helpers
    # ------------------------------------------------------------------
    def _validate_layout(self, *, require_state: bool) -> None:
        paths = self.paths
        require_disjoint(
            paths.repository_root, paths.state_root, code="unsafe_state_layout"
        )
        require_disjoint(
            paths.repository_root, paths.data_directory, code="unsafe_data_directory"
        )
        require_disjoint(
            paths.repository_root, paths.backup_root, code="unsafe_backup_root"
        )
        require_disjoint(paths.state_root, paths.data_directory, code="unsafe_state_layout")
        require_disjoint(paths.backup_root, paths.data_directory, code="unsafe_backup_root")
        require_disjoint(paths.backup_root, paths.state_root, code="unsafe_backup_root")
        require_regular_file(paths.containerfile, code="unsafe_containerfile")
        if not paths.data_directory.is_dir() or paths.data_directory.is_symlink():
            raise ReleaseError("unsafe_data_directory")
        if paths.database_path.is_symlink():
            raise ReleaseError("unsafe_data_directory")
        require_protected_directory(paths.data_directory, code="unsafe_data_directory")
        require_protected_file(paths.database_path, code="unsafe_live_database")
        if paths.environment_file is not None:
            require_protected_file(paths.environment_file, code="unsafe_environment_file")
        if paths.backup_root.exists():
            require_protected_directory(paths.backup_root, code="unsafe_backup_root")
        if self.store.exists():
            self.store.verify_layout()
        elif require_state:
            raise ReleaseError("release_state_missing")

    def _read_pointer_if_present(self, name: str) -> Pointer | None:
        if not self.store.exists():
            return None
        return self.store.read_pointer(name)

    def _timestamp(self) -> str:
        return self.clock.now().strftime("%Y-%m-%dT%H:%M:%SZ")

    def _report(
        self,
        *,
        mode: str,
        outcome: str,
        gates: GateLog,
        started_at: str,
        changed: bool,
        replayed: bool,
        source: SourceEvidence | None,
        image_digest: str | None,
        manifest: Mapping[str, Any] | None,
        manifest_digest: str | None,
        current: Pointer | None,
        previous: Pointer | None,
        diagnostics: Sequence[Mapping[str, str]],
        backup: BackupReceipt | None = None,
        retention: Mapping[str, Any] | None = None,
        hooks: Sequence[Mapping[str, Any]] = (),
        rollback: Mapping[str, Any] | None = None,
        error: str | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": REPORT_SCHEMA_VERSION,
            "manifest_version": MANIFEST_VERSION,
            "mode": mode,
            "outcome": outcome,
            "changed": changed,
            "replayed": replayed,
            "release_id": self.release_id,
            "spec_digest": spec_digest(self.spec),
            "source": dict(source.summary()) if source is not None else None,
            "image": {
                "repository": self.spec.image.repository,
                "tag": self._image_tag(),
                "digest": image_digest,
            },
            "schema": {
                "expected_revision": self.spec.expected_schema_revision,
                "packaged_revision": (
                    manifest["schema"]["packaged_revision"] if manifest is not None else None
                ),
            },
            "manifest_digest": manifest_digest,
            "artifacts": list(manifest["artifacts"]) if manifest is not None else [],
            "backup": backup.summary() if backup is not None else None,
            "gates": gates.payload(),
            "pointers": {
                "current": current.summary() if current is not None else None,
                "previous": previous.summary() if previous is not None else None,
            },
            "retention": dict(retention) if retention is not None else None,
            "hooks": [dict(hook) for hook in hooks],
            "rollback": dict(rollback) if rollback is not None else None,
            "diagnostics": [dict(item) for item in diagnostics],
            "error": error,
            "started_at": started_at,
            "finished_at": self._timestamp(),
        }
        payload["report_digest"] = domain_digest(
            "report",
            {key: value for key, value in payload.items() if key not in _VOLATILE_REPORT_KEYS},
        )
        require_secret_free(payload, code="unsafe_report_content")
        return payload

    def _failure_report(
        self,
        *,
        mode: str,
        gates: GateLog,
        started_at: str,
        error: ReleaseError,
        diagnostics: list[dict[str, str]],
        outcome: str = OUTCOME_FAILED,
        state: _ApplyState | None = None,
    ) -> dict[str, Any]:
        diagnostics = list(diagnostics)
        if not any(item.get("code") == error.code for item in diagnostics):
            diagnostics.append({"gate": error.gate, "code": error.code})
        rollback = state.rollback_evidence if state is not None else None
        if isinstance(error, ReleaseRollbackError) and rollback is not None:
            rollback = {**rollback, "original_error": error.original_code}
        report = self._report(
            mode=mode,
            outcome=outcome,
            gates=gates,
            started_at=started_at,
            changed=False,
            replayed=False,
            source=state.source if state is not None else None,
            image_digest=state.image_digest_or_none if state is not None else None,
            manifest=state.manifest if state is not None else None,
            manifest_digest=state.manifest_digest if state is not None else None,
            current=state.current if state is not None else None,
            previous=state.previous if state is not None else None,
            diagnostics=diagnostics,
            backup=state.backup if state is not None else None,
            hooks=state.hooks if state is not None else (),
            rollback=rollback,
            error=error.code,
        )
        if mode == APPLY_MODE and self.store.exists() and state is not None:
            try:
                self.store.write_report(f"{self.release_id}-{state.token}", report)
            except (ReleaseError, OSError):
                report["diagnostics"].append(
                    {"gate": "report", "code": "report_not_persisted"}
                )
                report["report_digest"] = domain_digest(
                    "report",
                    {
                        key: value
                        for key, value in report.items()
                        if key not in _VOLATILE_REPORT_KEYS
                    },
                )
        return report


_VOLATILE_REPORT_KEYS = frozenset({"started_at", "finished_at", "report_digest"})
_ALREADY_CURRENT = {"gate": "current_pointer", "code": "release_already_current"}


@dataclass
class _ApplyState:
    release_id: str
    token: str
    source: SourceEvidence | None = None
    current: Pointer | None = None
    previous: Pointer | None = None
    committed_current: Pointer | None = None
    committed_previous: Pointer | None = None
    previous_image_digest: str | None = None
    _image_digest: str | None = None
    packaged_schema_revision: str | None = None
    candidate_schema_revision: str | None = None
    candidate_digest: str | None = None
    candidate_readiness: ReadinessObservation | None = None
    service_readiness: ReadinessObservation | None = None
    manifest: dict[str, Any] | None = None
    manifest_digest: str | None = None
    backup: BackupReceipt | None = None
    hooks: list[dict[str, Any]] = field(default_factory=list)
    retention: dict[str, Any] | None = None
    rollback_evidence: dict[str, Any] | None = None
    cutover_started: bool = False
    pointers_committed: bool = False
    pointer_mutation_started: bool = False
    rollback_image_tag: str | None = None

    @property
    def image_digest(self) -> str:
        if self._image_digest is None:
            raise ReleaseError("image_digest_unresolved", gate="image_resolved")
        return self._image_digest

    @image_digest.setter
    def image_digest(self, value: str) -> None:
        self._image_digest = value

    @property
    def image_digest_or_none(self) -> str | None:
        return self._image_digest

    def backup_directory(self, paths: ResolvedPaths) -> Path:
        return paths.backup_root / f"{self.release_id}-{self.token}"

    def backup_path(self, paths: ResolvedPaths) -> Path:
        filename = self.backup.backup_file if self.backup is not None else "pre-release.sqlite3"
        return self.backup_directory(paths) / filename

    def failed_database_path(self, paths: ResolvedPaths) -> Path:
        return self.backup_directory(paths) / "failed.sqlite3"

    def candidate_directory(self, paths: ResolvedPaths) -> Path:
        return self.backup_directory(paths) / "candidate"

    def candidate_database_path(self, paths: ResolvedPaths, filename: str) -> Path:
        return self.candidate_directory(paths) / filename

    def candidate_container(self, spec: ReleaseSpec) -> str:
        return f"{spec.service.container_name}-candidate-{self.token}"


def _attempt_token(started_at: datetime) -> str:
    return started_at.strftime("%Y%m%dT%H%M%S%fZ")


def _parse_probe_json(raw: str) -> Any:
    text = raw.strip().splitlines()
    if not text:
        return None
    try:
        return json.loads(text[-1])
    except json.JSONDecodeError:
        return None


def _environment_mapping(items: Sequence[str]) -> dict[str, str] | None:
    values: dict[str, str] = {}
    for item in items:
        if "=" not in item:
            return None
        key, value = item.split("=", 1)
        if not key or key in values:
            return None
        values[key] = value
    return values
