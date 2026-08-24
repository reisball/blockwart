from __future__ import annotations

import os
import sqlite3
import stat
import subprocess
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, ValidationError, validate
from release_support import (
    COMMIT,
    NEW_IMAGE,
    OLD_IMAGE,
    SCHEMA_REVISION,
    FakeClock,
    FakeHost,
    build_installation,
    build_spec,
    default_images,
    spec_document,
)

from blockwart.release.canonical import (
    canonical_json_bytes,
    canonical_json_text,
    json_artifact_digest,
)
from blockwart.release.errors import ReleaseError
from blockwart.release.runtime import SubprocessCommandRunner
from blockwart.release.schemas import json_schema
from blockwart.release.source import SourceEvidence
from blockwart.release.spec import parse_spec, runtime_layout_digest
from blockwart.release.state import CURRENT_POINTER, PREVIOUS_POINTER, Pointer, release_lock
from blockwart.release.workflow import (
    EXIT_FAILED,
    EXIT_OK,
    EXIT_ROLLBACK_FAILED,
    EXIT_ROLLED_BACK,
    OUTCOME_FAILED,
    OUTCOME_PLANNED,
    OUTCOME_ROLLBACK_FAILED,
    OUTCOME_ROLLED_BACK,
    OUTCOME_SUCCEEDED,
    ReleaseWorkflow,
)

PREVIOUS_RELEASE_ID = "cccccccccccc-dddddddddddd"


class Installation:
    """One simulated host plus the workflow bound to it."""

    def __init__(self, tmp_path: Path, **kwargs: Any) -> None:
        self.layout = build_installation(tmp_path)
        self.clock = FakeClock()
        self.images = default_images(**kwargs.pop("image", {}))
        self.host = FakeHost(
            clock=self.clock,
            repository_root=self.layout["repository"],
            images=self.images,
            **kwargs.pop("host", {}),
        )
        self.spec = build_spec(self.layout, **kwargs.pop("spec", {}))
        self.workflow = ReleaseWorkflow(self.spec, runner=self.host, clock=self.clock)

    @property
    def new_image(self):
        return self.images[NEW_IMAGE]

    @property
    def old_image(self):
        return self.images[OLD_IMAGE]

    @property
    def database_path(self) -> Path:
        return self.layout["data"] / "blockwart.sqlite3"

    def seed_running_release(self) -> Pointer:
        """A managed installation already serving the previous release."""
        store = self.workflow.store
        store.prepare()
        artifacts = {
            "build": {"release": PREVIOUS_RELEASE_ID},
            "contract": {"release": PREVIOUS_RELEASE_ID},
            "source": {"release": PREVIOUS_RELEASE_ID},
        }
        manifest = {
            "manifest_version": 1,
            "release_id": PREVIOUS_RELEASE_ID,
            "contract_digest": "d" * 64,
            "source": {"commit": "c" * 40, "tree": "d" * 40, "clean": True},
            "image": {
                "repository": "blockwart",
                "tag": f"blockwart:{PREVIOUS_RELEASE_ID}",
                "digest": OLD_IMAGE,
                "runtime": "docker",
                "mode": "build",
                "build_revision": "c" * 40,
            },
            "schema": {
                "expected_revision": SCHEMA_REVISION,
                "packaged_revision": SCHEMA_REVISION,
            },
            "artifacts": [
                {
                    "name": name,
                    "sha256": json_artifact_digest(artifacts[name]),
                }
                for name in ("build", "contract", "source")
            ],
        }
        record = store.write_bundle(
            PREVIOUS_RELEASE_ID, manifest=manifest, artifacts=artifacts
        )
        pointer = Pointer(
            release_id=PREVIOUS_RELEASE_ID,
            generation=4,
            manifest_digest=record.manifest_digest,
            image_digest=OLD_IMAGE,
            source_commit="c" * 40,
            schema_revision=SCHEMA_REVISION,
            runtime_layout_digest=runtime_layout_digest(
                self.spec, build_revision="c" * 40
            ),
            updated_at="2026-08-01T00:00:00Z",
        )
        store.write_pointer(CURRENT_POINTER, pointer)
        store.append_history(
            {
                "generation": 4,
                "release_id": PREVIOUS_RELEASE_ID,
                "image_digest": OLD_IMAGE,
                "manifest_digest": record.manifest_digest,
                "source_commit": "c" * 40,
                "outcome": OUTCOME_SUCCEEDED,
                "committed_at": "2026-08-01T00:00:00Z",
            }
        )
        self.host._start_from_argv(  # noqa: SLF001 - deterministic runtime fixture
            "blockwart",
            OLD_IMAGE,
            list(
                self.workflow._service_run_argv(  # noqa: SLF001
                    OLD_IMAGE, build_revision="c" * 40
                )
            ),
        )
        return pointer


def gate(report: dict[str, Any], name: str) -> dict[str, Any]:
    for entry in report["gates"]:
        if entry["name"] == name:
            return entry
    raise AssertionError(f"gate {name} not recorded")


def gate_names(report: dict[str, Any]) -> list[str]:
    return [entry["name"] for entry in report["gates"]]


def row_count(path: Path) -> int:
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        return int(connection.execute("SELECT count(*) FROM catalog_objects").fetchone()[0])
    finally:
        connection.close()


# ----------------------------------------------------------------------
# dry run
# ----------------------------------------------------------------------
def test_plan_is_write_free_and_repeatable(tmp_path: Path) -> None:
    installation = Installation(tmp_path)

    first = installation.workflow.plan()
    second = installation.workflow.plan()

    assert first.outcome == OUTCOME_PLANNED
    assert first.exit_code == EXIT_OK
    assert first.report["changed"] is False
    assert first.report["report_digest"] == second.report["report_digest"]
    assert canonical_json_bytes(first.report) == canonical_json_bytes(second.report)
    assert not installation.layout["state"].exists()
    assert list(installation.layout["backups"].iterdir()) == []
    assert all(
        command[0] not in {"docker", "podman"} or command[1] != "run"
        for command in installation.host.calls
    )


def test_plan_reports_planned_gates_without_resolving_a_built_image(tmp_path: Path) -> None:
    installation = Installation(tmp_path)

    report = installation.workflow.plan().report

    assert gate(report, "source_verified")["status"] == "passed"
    assert gate(report, "image_resolved")["status"] == "planned"
    assert gate(report, "cutover_readiness")["status"] == "planned"
    assert report["image"]["digest"] is None


def test_release_identity_is_host_neutral(tmp_path: Path) -> None:
    first = Installation(tmp_path / "first")
    second = Installation(tmp_path / "second")

    assert first.workflow.release_id == second.workflow.release_id
    assert first.spec.source.repository_root != second.spec.source.repository_root


def test_plan_resolves_and_binds_an_existing_image(tmp_path: Path) -> None:
    installation = Installation(
        tmp_path, spec={"image": {"mode": "existing", "digest": NEW_IMAGE}}
    )

    report = installation.workflow.plan().report

    assert gate(report, "image_resolved")["status"] == "passed"
    assert report["image"]["digest"] == NEW_IMAGE
    assert report["manifest_digest"] is None


def test_existing_image_schema_and_parser_both_require_digest(tmp_path: Path) -> None:
    document = Installation(tmp_path).spec.model_dump(mode="json")
    document["image"]["mode"] = "existing"
    document["image"]["digest"] = None
    schema = json_schema("spec")

    Draft202012Validator.check_schema(schema)
    with pytest.raises(ValidationError):
        validate(document, schema)
    with pytest.raises(ReleaseError) as failure:
        parse_spec(document)

    assert failure.value.code == "image_digest_required"


# ----------------------------------------------------------------------
# source verification before any mutation
# ----------------------------------------------------------------------
@pytest.mark.parametrize(
    ("attribute", "value", "code"),
    [
        ("git_status", " M src/blockwart/main.py", "source_tree_dirty"),
        ("head", "f" * 40, "source_ref_drift"),
        ("known_commits", (), "source_commit_missing"),
        ("commit_reachable", False, "source_commit_unreachable"),
        ("git_symbolic", "refs/heads/main", "source_commit_ambiguous"),
        ("is_repository", False, "source_not_a_repository"),
        ("toplevel", "/somewhere/else", "source_root_mismatch"),
    ],
)
def test_apply_rejects_unsafe_source_state_before_mutation(
    tmp_path: Path, attribute: str, value: Any, code: str
) -> None:
    installation = Installation(tmp_path)
    setattr(installation.host, attribute, value)

    outcome = installation.workflow.apply(expect_current="none")

    assert outcome.outcome == OUTCOME_FAILED
    assert outcome.exit_code == EXIT_FAILED
    assert outcome.report["error"] == code
    assert gate(outcome.report, "source_verified")["status"] == "failed"
    assert not installation.layout["state"].exists()
    assert list(installation.layout["backups"].iterdir()) == []


def test_apply_rejects_missing_image_build_evidence(tmp_path: Path) -> None:
    installation = Installation(tmp_path, image={"build_revision_present": False})

    outcome = installation.workflow.apply(expect_current="none")

    assert outcome.report["error"] == "image_build_revision_missing"
    assert list(installation.layout["backups"].iterdir()) == []


def test_apply_rejects_image_built_from_another_commit(tmp_path: Path) -> None:
    installation = Installation(tmp_path, image={"build_revision": "9" * 40})

    outcome = installation.workflow.apply(expect_current="none")

    assert outcome.report["error"] == "image_build_revision_mismatch"


def test_apply_rejects_packaged_schema_drift(tmp_path: Path) -> None:
    installation = Installation(tmp_path, image={"packaged_head": "20260101_0001"})

    outcome = installation.workflow.apply(expect_current="none")

    assert outcome.report["error"] == "packaged_schema_mismatch"
    assert gate(outcome.report, "packaged_schema")["status"] == "failed"
    assert list(installation.layout["backups"].iterdir()) == []


def test_source_drift_during_build_is_rejected_before_backup(tmp_path: Path) -> None:
    installation = Installation(tmp_path, host={"drift_source_after_build": True})

    outcome = installation.workflow.apply(expect_current="none")

    assert outcome.report["error"] == "source_ref_drift"
    assert gate(outcome.report, "source_reverified")["status"] == "failed"
    assert list(installation.layout["backups"].iterdir()) == []


def test_build_context_contains_only_exact_commit_files(tmp_path: Path) -> None:
    installation = Installation(tmp_path)
    (installation.layout["repository"] / ".env").write_text(
        "PRIVATE_TOKEN=must-not-enter-build\n", encoding="utf-8"
    )
    (installation.layout["repository"] / "private.sqlite3").write_bytes(b"private")

    outcome = installation.workflow.apply(expect_current="none")

    assert outcome.outcome == OUTCOME_SUCCEEDED
    assert installation.host.build_context_entries == ("Dockerfile",)
    build_call = next(call for call in installation.host.calls if call[1] == "build")
    assert build_call[-1] != str(installation.layout["repository"])
    assert "PRIVATE_TOKEN" not in canonical_json_text(outcome.report)


def test_real_git_archive_context_excludes_ignored_private_files(tmp_path: Path) -> None:
    layout = build_installation(tmp_path)
    repository = layout["repository"]
    (repository / ".gitignore").write_text(".env\n*.sqlite3\n", encoding="utf-8")
    (repository / ".env").write_text("PRIVATE_TOKEN=ignored\n", encoding="utf-8")
    (repository / "private.sqlite3").write_bytes(b"ignored")

    def git(*argv: str) -> str:
        completed = subprocess.run(  # noqa: S603 - fixed git argv in a temp repository
            ("git", "-C", str(repository), *argv),
            check=True,
            capture_output=True,
            text=True,
        )
        return completed.stdout.strip()

    git("init", "--quiet")
    git("add", "Dockerfile", ".gitignore")
    git(
        "-c",
        "user.name=Blockwart Test",
        "-c",
        "user.email=release-test@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "fixture",
    )
    commit = git("rev-parse", "HEAD")
    tree = git("rev-parse", f"{commit}^{{tree}}")
    document = spec_document(layout)
    document["source"]["commit"] = commit
    spec = parse_spec(document)
    workflow = ReleaseWorkflow(
        spec, runner=SubprocessCommandRunner(), clock=FakeClock()
    )
    workflow.store.prepare()

    with workflow._exact_build_context(  # noqa: SLF001 - focused boundary proof
        SourceEvidence(commit=commit, tree=tree, clean=True)
    ) as context:
        assert (context / "Dockerfile").is_file()
        assert (context / ".gitignore").is_file()
        assert not (context / ".env").exists()
        assert not (context / "private.sqlite3").exists()


def test_exported_apply_requires_compare_and_set_argument(tmp_path: Path) -> None:
    installation = Installation(tmp_path)

    with pytest.raises(TypeError):
        installation.workflow.apply()  # type: ignore[call-arg]
    with pytest.raises(ReleaseError) as failure:
        installation.workflow.apply(expect_current=None)  # type: ignore[arg-type]

    assert failure.value.code == "expect_current_required"
    assert not installation.layout["state"].exists()


# ----------------------------------------------------------------------
# happy path
# ----------------------------------------------------------------------
def test_apply_completes_candidate_and_cutover(tmp_path: Path) -> None:
    installation = Installation(tmp_path)
    installation.seed_running_release()

    outcome = installation.workflow.apply(expect_current=PREVIOUS_RELEASE_ID)
    report = outcome.report

    assert outcome.outcome == OUTCOME_SUCCEEDED
    assert outcome.exit_code == EXIT_OK
    assert report["changed"] is True
    assert report["replayed"] is False
    assert report["error"] is None
    assert report["image"]["digest"] == NEW_IMAGE
    for name in (
        "candidate_migration",
        "candidate_schema",
        "candidate_db_check",
        "candidate_integrity",
        "candidate_runtime_layout",
        "candidate_readiness",
        "candidate_health",
        "cutover_service_stopped",
        "cutover_service_started",
        "cutover_runtime_layout",
        "cutover_readiness",
        "cutover_health",
        "cutover_schema",
        "cutover_integrity",
        "pointers_committed",
        "retention_applied",
    ):
        assert gate(report, name)["status"] == "passed", name
    assert installation.host.containers["blockwart"].image == NEW_IMAGE

    store = installation.workflow.store
    current = store.read_pointer(CURRENT_POINTER)
    previous = store.read_pointer(PREVIOUS_POINTER)
    assert current is not None and current.release_id == installation.workflow.release_id
    assert current.image_digest == NEW_IMAGE
    assert previous is not None and previous.release_id == PREVIOUS_RELEASE_ID
    assert current.generation > previous.generation


def test_release_bundle_is_immutable_and_binds_release_evidence(tmp_path: Path) -> None:
    installation = Installation(tmp_path)
    installation.seed_running_release()

    installation.workflow.apply(expect_current=PREVIOUS_RELEASE_ID)

    store = installation.workflow.store
    release_id = installation.workflow.release_id
    manifest = store.read_manifest(release_id)
    assert manifest["manifest_version"] == 1
    assert manifest["source"]["commit"] == COMMIT
    assert manifest["image"]["digest"] == NEW_IMAGE
    assert manifest["image"]["build_revision"] == COMMIT
    assert manifest["schema"]["expected_revision"] == SCHEMA_REVISION
    assert manifest["schema"]["packaged_revision"] == SCHEMA_REVISION
    assert {item["name"] for item in manifest["artifacts"]} == {
        "build",
        "contract",
        "source",
    }
    recorded = store.artifact_digests(release_id)
    for artifact in manifest["artifacts"]:
        assert recorded[artifact["name"]] == artifact["sha256"]
    manifest_file = store.manifest_path(release_id)
    assert manifest_file.stat().st_mode & 0o222 == 0
    with pytest.raises(PermissionError):
        manifest_file.write_text("tampered", encoding="utf-8")


def test_manifest_and_report_are_schema_valid_and_host_configuration_free(
    tmp_path: Path,
) -> None:
    environment_file = tmp_path / "runtime.env"
    environment_file.write_text("BLOCKWART_SECRET_REFERENCE=example-reference\n", encoding="utf-8")
    environment_file.chmod(0o640)
    installation = Installation(
        tmp_path,
        spec={"service": {"environment_file": str(environment_file)}},
    )
    installation.seed_running_release()

    outcome = installation.workflow.apply(expect_current=PREVIOUS_RELEASE_ID)
    manifest = installation.workflow.store.read_manifest(installation.workflow.release_id)
    current = installation.workflow.store.read_pointer(CURRENT_POINTER)

    validate(manifest, json_schema("manifest"))
    validate(outcome.report, json_schema("report"))
    assert current is not None
    validate(current.payload(), json_schema("pointer"))
    rendered = canonical_json_text(manifest)
    assert str(environment_file) not in rendered
    assert str(installation.layout["data"]) not in rendered
    assert "127.0.0.1:8000:8000" not in rendered


def test_repeated_apply_replays_without_a_second_cutover(tmp_path: Path) -> None:
    installation = Installation(tmp_path)
    installation.seed_running_release()
    first = installation.workflow.apply(expect_current=PREVIOUS_RELEASE_ID)
    assert first.outcome == OUTCOME_SUCCEEDED
    calls_after_first = len(installation.host.calls)

    second = installation.workflow.apply(
        expect_current=installation.workflow.release_id
    )

    assert second.outcome == OUTCOME_SUCCEEDED
    assert second.report["changed"] is False
    assert second.report["replayed"] is True
    assert "cutover_service_stopped" not in gate_names(second.report)
    assert len(installation.host.calls) - calls_after_first < 15
    backups = sorted(path.name for path in installation.layout["backups"].iterdir())
    assert len(backups) == 1


def test_release_lock_is_single_writer(tmp_path: Path) -> None:
    installation = Installation(tmp_path)
    installation.workflow.store.prepare()

    with release_lock(installation.workflow.store, exclusive=True):
        with pytest.raises(ReleaseError) as failure:
            with release_lock(installation.workflow.store, exclusive=True):
                pass
    assert failure.value.code == "release_lock_held"


def test_missing_current_bundle_artifact_fails_before_backup(tmp_path: Path) -> None:
    installation = Installation(tmp_path)
    installation.seed_running_release()
    artifact = (
        installation.workflow.store.bundle_dir(PREVIOUS_RELEASE_ID)
        / "artifacts"
        / "build.json"
    )
    artifact.unlink()

    outcome = installation.workflow.apply(expect_current=PREVIOUS_RELEASE_ID)

    assert outcome.report["error"] == "bundle_artifact_missing"
    assert gate(outcome.report, "current_pointer_verified")["status"] == "failed"
    assert list(installation.layout["backups"].iterdir()) == []


# ----------------------------------------------------------------------
# database backup and restored-copy-only candidate
# ----------------------------------------------------------------------
def test_backup_is_consistent_verified_and_outside_the_data_path(tmp_path: Path) -> None:
    installation = Installation(tmp_path)
    installation.seed_running_release()

    report = installation.workflow.apply(expect_current=PREVIOUS_RELEASE_ID).report

    backup_directories = sorted(installation.layout["backups"].iterdir())
    assert len(backup_directories) == 1
    backup = backup_directories[0] / "pre-release.sqlite3"
    receipt = backup_directories[0] / "pre-release.sqlite3.receipt.json"
    assert backup.is_file() and receipt.is_file()
    assert backup.stat().st_mode & 0o222 == 0
    assert receipt.stat().st_mode & 0o222 == 0
    assert report["backup"]["backup_sha256"] == _digest(backup)
    assert row_count(backup) == row_count(installation.database_path)
    connection = sqlite3.connect(f"file:{backup}?mode=ro", uri=True)
    try:
        assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
    finally:
        connection.close()


def test_missing_backup_root_is_created_protected_under_umask_zero(
    tmp_path: Path,
) -> None:
    installation = Installation(tmp_path)
    installation.seed_running_release()
    installation.layout["backups"].rmdir()
    previous_umask = os.umask(0o000)
    try:
        outcome = installation.workflow.apply(expect_current=PREVIOUS_RELEASE_ID)
    finally:
        os.umask(previous_umask)

    assert outcome.outcome == OUTCOME_SUCCEEDED
    assert stat.S_IMODE(installation.layout["backups"].stat().st_mode) == 0o750
    attempt = next(installation.layout["backups"].iterdir())
    assert stat.S_IMODE(attempt.stat().st_mode) == 0o750


def test_candidate_never_touches_the_live_database(tmp_path: Path) -> None:
    installation = Installation(tmp_path)
    installation.seed_running_release()
    before = _digest(installation.database_path)

    installation.workflow.apply(expect_current=PREVIOUS_RELEASE_ID)

    candidate_calls = [
        command
        for command in installation.host.calls
        if "-candidate-" in " ".join(command)
    ]
    assert candidate_calls
    data_directory = str(installation.layout["data"])
    for command in candidate_calls:
        assert all(data_directory not in argument for argument in command)
    assert _digest(installation.database_path) == before


def test_candidate_migration_failure_stops_before_cutover(tmp_path: Path) -> None:
    installation = Installation(tmp_path, image={"migration_ok": False})
    installation.seed_running_release()

    outcome = installation.workflow.apply(expect_current=PREVIOUS_RELEASE_ID)

    assert outcome.outcome == OUTCOME_FAILED
    assert outcome.report["error"] == "candidate_migration_failed"
    assert "cutover_service_stopped" not in gate_names(outcome.report)
    assert installation.host.containers["blockwart"].image == OLD_IMAGE
    assert installation.workflow.store.read_pointer(CURRENT_POINTER).release_id == (
        PREVIOUS_RELEASE_ID
    )


def test_timed_out_one_shot_candidate_is_removed_without_touching_unrelated(
    tmp_path: Path,
) -> None:
    installation = Installation(tmp_path, image={"migration_timeout": True})
    installation.seed_running_release()
    installation.host.start_container("unrelated-issue210-test", OLD_IMAGE)

    outcome = installation.workflow.apply(expect_current=PREVIOUS_RELEASE_ID)

    assert outcome.report["error"] == "candidate_migration_timeout"
    assert "unrelated-issue210-test" in installation.host.containers
    assert all(
        not name.endswith("-migration") for name in installation.host.containers
    )
    removals = [call for call in installation.host.calls if call[1:3] == ("rm", "--force")]
    assert any(call[-1].endswith("-migration") for call in removals)


def test_candidate_readiness_failure_stops_before_cutover(tmp_path: Path) -> None:
    installation = Installation(tmp_path, image={"candidate_readiness": "never"})
    installation.seed_running_release()

    outcome = installation.workflow.apply(expect_current=PREVIOUS_RELEASE_ID)

    assert outcome.report["error"] == "candidate_readiness_timeout"
    assert gate(outcome.report, "candidate_readiness")["status"] == "failed"
    assert installation.host.containers["blockwart"].image == OLD_IMAGE


def test_candidate_health_failure_stops_before_cutover(tmp_path: Path) -> None:
    installation = Installation(
        tmp_path, image={"candidate_health": (("unhealthy", "fresh"),)}
    )
    installation.seed_running_release()

    outcome = installation.workflow.apply(expect_current=PREVIOUS_RELEASE_ID)

    assert outcome.report["error"] == "candidate_health_unhealthy"
    assert gate(outcome.report, "candidate_readiness")["status"] == "passed"
    assert gate(outcome.report, "candidate_health")["status"] == "failed"
    assert installation.host.containers["blockwart"].image == OLD_IMAGE


def test_readiness_and_health_are_distinct_ordered_gates(tmp_path: Path) -> None:
    """A healthy status observed before readiness is the known race and is rejected."""
    installation = Installation(
        tmp_path, image={"candidate_health": (("healthy", "stale"),)}
    )
    installation.seed_running_release()

    outcome = installation.workflow.apply(expect_current=PREVIOUS_RELEASE_ID)
    names = gate_names(outcome.report)

    assert outcome.report["error"] == "candidate_health_stale"
    assert names.index("candidate_readiness") < names.index("candidate_health")
    assert gate(outcome.report, "candidate_readiness")["status"] == "passed"


def test_candidate_health_accepts_a_probe_finished_after_readiness(tmp_path: Path) -> None:
    installation = Installation(
        tmp_path,
        image={"candidate_health": (("healthy", "stale"), ("healthy", "fresh"))},
    )
    installation.seed_running_release()

    outcome = installation.workflow.apply(expect_current=PREVIOUS_RELEASE_ID)

    assert outcome.outcome == OUTCOME_SUCCEEDED
    assert gate(outcome.report, "candidate_health")["status"] == "passed"


def test_live_database_drift_after_candidate_preserves_new_writes_and_aborts(
    tmp_path: Path,
) -> None:
    installation = Installation(tmp_path)
    installation.seed_running_release()

    def write_after_candidate(_image_digest: str) -> None:
        connection = sqlite3.connect(installation.database_path)
        try:
            connection.execute("INSERT INTO catalog_objects VALUES ('concurrent-write')")
            connection.commit()
        finally:
            connection.close()

    installation.host.candidate_start_side_effect = write_after_candidate

    outcome = installation.workflow.apply(expect_current=PREVIOUS_RELEASE_ID)

    assert outcome.outcome == OUTCOME_ROLLED_BACK
    assert outcome.report["error"] == "stale_live_database"
    assert gate(outcome.report, "cutover_database_snapshot")["status"] == "failed"
    assert installation.host.containers["blockwart"].image == OLD_IMAGE
    assert row_count(installation.database_path) == 4
    backup_directory = next(installation.layout["backups"].iterdir())
    assert row_count(backup_directory / "cutover.sqlite3") == 4
    assert row_count(backup_directory / "failed.sqlite3") == 4


def _digest(path: Path) -> str:
    import hashlib

    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


# ----------------------------------------------------------------------
# post-cutover failure and automatic rollback
# ----------------------------------------------------------------------
def _migrating_installation(tmp_path: Path, **kwargs: Any) -> Installation:
    """A host whose new image migrates the live database as it starts."""
    installation = Installation(tmp_path, **kwargs)
    installation.seed_running_release()

    def migrate(image_digest: str) -> None:
        if image_digest != NEW_IMAGE:
            return
        connection = sqlite3.connect(installation.database_path)
        try:
            connection.execute("INSERT INTO catalog_objects VALUES ('migrated-object')")
            connection.commit()
        finally:
            connection.close()

    installation.host.service_start_side_effect = migrate
    return installation


@pytest.mark.parametrize(
    ("image_behaviour", "code", "failing_gate"),
    [
        ({"service_start_timeout": True}, "cutover_timeout", "cutover_service_started"),
        ({"service_start_ok": False}, "cutover_start_failed", "cutover_service_started"),
        ({"service_readiness": "never"}, "cutover_readiness_timeout", "cutover_readiness"),
        (
            {"service_health": (("unhealthy", "fresh"),)},
            "cutover_health_unhealthy",
            "cutover_health",
        ),
        (
            {"service_health": (("healthy", "stale"),)},
            "cutover_health_stale",
            "cutover_health",
        ),
        ({"service_check_ok": False}, "cutover_schema_check_failed", "cutover_schema"),
        ({"service_integrity_ok": False}, "cutover_integrity_failed", "cutover_integrity"),
    ],
)
def test_every_post_cutover_failure_restores_the_previous_pair(
    tmp_path: Path, image_behaviour: dict[str, Any], code: str, failing_gate: str
) -> None:
    installation = _migrating_installation(tmp_path, image=image_behaviour)
    pre_release_rows = row_count(installation.database_path)

    outcome = installation.workflow.apply(expect_current=PREVIOUS_RELEASE_ID)
    report = outcome.report
    validate(report, json_schema("report"))

    assert outcome.outcome == OUTCOME_ROLLED_BACK
    assert outcome.exit_code == EXIT_ROLLED_BACK
    assert report["error"] == code
    assert gate(report, failing_gate)["status"] == "failed"
    assert report["rollback"]["triggered_by"] == {"gate": failing_gate, "code": code}
    assert report["rollback"]["previous_release_id"] == PREVIOUS_RELEASE_ID
    assert report["rollback"]["previous_image_digest"] == OLD_IMAGE
    assert report["rollback"]["database_restored"] is True
    assert report["rollback"]["service_restored"] is True

    # the exact previous image serves again against the verified pre-release database
    assert installation.host.containers["blockwart"].image == OLD_IMAGE
    assert row_count(installation.database_path) == pre_release_rows
    for name in ("rollback_readiness", "rollback_health", "rollback_schema", "rollback_integrity"):
        assert gate(report, name)["status"] == "passed", name

    # the failed database is preserved next to its backup
    backup_directory = sorted(installation.layout["backups"].iterdir())[0]
    assert (backup_directory / "failed.sqlite3").is_file()
    expected_failed_rows = pre_release_rows + (
        0 if code in {"cutover_timeout", "cutover_start_failed"} else 1
    )
    assert row_count(backup_directory / "failed.sqlite3") == expected_failed_rows

    # pointers still describe the previous release
    store = installation.workflow.store
    assert store.read_pointer(CURRENT_POINTER).release_id == PREVIOUS_RELEASE_ID


def test_cutover_stop_timeout_rolls_back(tmp_path: Path) -> None:
    installation = _migrating_installation(tmp_path)
    installation.host.stop_timeout = True

    outcome = installation.workflow.apply(expect_current=PREVIOUS_RELEASE_ID)

    assert outcome.outcome == OUTCOME_ROLLED_BACK
    assert outcome.report["error"] == "cutover_timeout"
    assert gate(outcome.report, "cutover_service_stopped")["status"] == "failed"
    assert installation.host.containers["blockwart"].image == OLD_IMAGE


def test_pointer_commit_failure_after_cutover_restores_the_previous_release(
    tmp_path: Path,
) -> None:
    installation = _migrating_installation(tmp_path)
    store = installation.workflow.store
    original = store.write_pointers

    def refuse(*, current: Pointer | None, previous: Pointer | None) -> None:
        if current is not None and current.release_id == installation.workflow.release_id:
            raise ReleaseError("pointer_write_failed", gate="pointers_committed")
        original(current=current, previous=previous)

    store.write_pointers = refuse  # type: ignore[method-assign]

    outcome = installation.workflow.apply(expect_current=PREVIOUS_RELEASE_ID)

    assert outcome.outcome == OUTCOME_ROLLED_BACK
    assert outcome.report["error"] == "pointer_write_failed"
    assert installation.host.containers["blockwart"].image == OLD_IMAGE


def test_completion_report_failure_rolls_back_and_returns_redacted_evidence(
    tmp_path: Path,
) -> None:
    installation = _migrating_installation(tmp_path)

    def refuse_report(_name: str, _payload: Any) -> str:
        raise ReleaseError("report_storage_failed", gate="completion_report")

    installation.workflow.store.write_report = refuse_report  # type: ignore[method-assign]

    outcome = installation.workflow.apply(expect_current=PREVIOUS_RELEASE_ID)

    assert outcome.outcome == OUTCOME_ROLLED_BACK
    assert outcome.report["error"] == "completion_report_write_failed"
    assert {item["code"] for item in outcome.report["diagnostics"]} >= {
        "completion_report_write_failed",
        "report_not_persisted",
    }
    assert installation.host.containers["blockwart"].image == OLD_IMAGE


def test_failed_rollback_is_reported_fail_closed_without_destroying_evidence(
    tmp_path: Path,
) -> None:
    installation = _migrating_installation(tmp_path, image={"service_check_ok": False})
    installation.old_image.service_start_ok = False
    pre_release_rows = row_count(installation.database_path)

    outcome = installation.workflow.apply(expect_current=PREVIOUS_RELEASE_ID)
    report = outcome.report
    validate(report, json_schema("report"))

    assert outcome.outcome == OUTCOME_ROLLBACK_FAILED
    assert outcome.exit_code == EXIT_ROLLBACK_FAILED
    assert report["error"] == "rollback_start_failed"
    assert report["rollback"]["original_error"] == "cutover_schema_check_failed"
    assert report["rollback"]["rollback_error"]["gate"] == "rollback_service_started"
    assert report["rollback"]["database_restored"] is True

    backup_directory = sorted(installation.layout["backups"].iterdir())[0]
    backup = backup_directory / "pre-release.sqlite3"
    assert backup.is_file()
    assert (backup_directory / "failed.sqlite3").is_file()
    assert row_count(backup) == pre_release_rows
    assert row_count(backup_directory / "failed.sqlite3") == pre_release_rows + 1
    assert installation.workflow.store.read_pointer(CURRENT_POINTER).release_id == (
        PREVIOUS_RELEASE_ID
    )
    persisted = sorted(installation.workflow.store.reports_dir.iterdir())
    assert persisted, "a fail-closed rollback still writes its report"


def test_failed_rollback_verification_contains_the_unverified_service(
    tmp_path: Path,
) -> None:
    installation = _migrating_installation(
        tmp_path, image={"service_integrity_ok": False}
    )
    installation.old_image.service_readiness = "never"

    outcome = installation.workflow.apply(expect_current=PREVIOUS_RELEASE_ID)

    assert outcome.outcome == OUTCOME_ROLLBACK_FAILED
    assert outcome.report["error"] == "rollback_readiness_timeout"
    assert outcome.report["rollback"]["service_contained"] is True
    assert "blockwart" not in installation.host.containers
    assert gate(outcome.report, "rollback_readiness")["status"] == "failed"
    backup_directory = next(installation.layout["backups"].iterdir())
    assert (backup_directory / "failed.sqlite3").is_file()


def test_rollback_never_runs_a_database_downgrade(tmp_path: Path) -> None:
    installation = _migrating_installation(tmp_path, image={"service_integrity_ok": False})

    installation.workflow.apply(expect_current=PREVIOUS_RELEASE_ID)

    for command in installation.host.calls:
        assert "downgrade" not in command


# ----------------------------------------------------------------------
# stale state, hooks, retention
# ----------------------------------------------------------------------
def test_stale_current_expectation_fails_before_mutation(tmp_path: Path) -> None:
    installation = Installation(tmp_path)
    installation.seed_running_release()

    outcome = installation.workflow.apply(expect_current="some-other-release")

    assert outcome.report["error"] == "stale_current_pointer"
    assert gate(outcome.report, "current_pointer_verified")["status"] == "failed"
    assert list(installation.layout["backups"].iterdir()) == []


def test_expect_none_rejects_an_existing_current_release(tmp_path: Path) -> None:
    installation = Installation(tmp_path)
    installation.seed_running_release()

    outcome = installation.workflow.apply(expect_current="none")

    assert outcome.report["error"] == "stale_current_pointer"


def test_running_image_drift_from_the_current_pointer_fails_closed(tmp_path: Path) -> None:
    installation = Installation(tmp_path)
    installation.seed_running_release()
    installation.host.start_container("blockwart", NEW_IMAGE)

    outcome = installation.workflow.apply(expect_current=PREVIOUS_RELEASE_ID)

    assert outcome.report["error"] == "current_pointer_image_drift"
    assert list(installation.layout["backups"].iterdir()) == []


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("mounts", (("bind", "/wrong/data", "/data", True),)),
        ("published_ports", (("8000/tcp", "0.0.0.0", "8000"),)),
        ("restart_policy", "always"),
        ("environment", ("BLOCKWART_DATABASE_URL=sqlite:////wrong.sqlite3",)),
    ],
)
def test_actual_current_runtime_layout_drift_fails_before_mutation(
    tmp_path: Path, field: str, value: Any
) -> None:
    installation = Installation(tmp_path)
    installation.seed_running_release()
    setattr(installation.host.containers["blockwart"], field, value)

    outcome = installation.workflow.apply(expect_current=PREVIOUS_RELEASE_ID)

    assert outcome.report["error"] == "current_runtime_layout_drift"
    assert gate(outcome.report, "current_pointer_verified")["status"] == "failed"
    assert list(installation.layout["backups"].iterdir()) == []
    assert not any(call[1] == "build" for call in installation.host.calls if len(call) > 1)
    assert "/wrong" not in canonical_json_text(outcome.report)


def test_unmanaged_running_service_is_rejected(tmp_path: Path) -> None:
    installation = Installation(tmp_path)
    installation.host.start_container("blockwart", OLD_IMAGE)

    outcome = installation.workflow.apply(expect_current="none")

    assert outcome.report["error"] == "unmanaged_service_state"


def test_unsafe_permissions_and_symlinked_state_are_rejected(tmp_path: Path) -> None:
    installation = Installation(tmp_path)
    installation.layout["data"].chmod(0o770)

    outcome = installation.workflow.plan()

    assert outcome.report["error"] == "unsafe_data_directory"

    other = tmp_path / "other-state"
    other.mkdir(mode=0o750)
    installation.layout["state"].symlink_to(other, target_is_directory=True)
    with pytest.raises(ReleaseError) as failure:
        ReleaseWorkflow(installation.spec, runner=installation.host, clock=installation.clock)
    assert failure.value.code == "unsafe_state_root"


def test_hook_receives_only_allowlisted_non_secret_context(tmp_path: Path) -> None:
    hook = tmp_path / "verify.sh"
    hook.write_text("#!/bin/sh\n", encoding="utf-8")
    installation = Installation(
        tmp_path,
        spec={"hooks": [{"name": "post-verify", "argv": [str(hook), "--check"]}]},
    )
    installation.seed_running_release()

    outcome = installation.workflow.apply(expect_current=PREVIOUS_RELEASE_ID)

    assert outcome.outcome == OUTCOME_SUCCEEDED
    assert outcome.report["hooks"] == [
        {"name": "post-verify", "status": "passed", "code": None}
    ]
    assert installation.host.hook_contexts == [
        {
            "BLOCKWART_RELEASE_ID": installation.workflow.release_id,
            "BLOCKWART_RELEASE_SOURCE_COMMIT": COMMIT,
            "BLOCKWART_RELEASE_IMAGE_DIGEST": NEW_IMAGE,
            "BLOCKWART_RELEASE_MANIFEST_DIGEST": outcome.report["manifest_digest"],
            "BLOCKWART_RELEASE_SCHEMA_REVISION": SCHEMA_REVISION,
            "BLOCKWART_RELEASE_OUTCOME": "verified",
        }
    ]
    hook_call = [command for command in installation.host.calls if command[0] == str(hook)]
    assert hook_call == [(str(hook), "--check")]


@pytest.mark.parametrize(
    ("behaviour", "code"), [("fail", "hook_failed"), ("timeout", "hook_timeout")]
)
def test_hook_failure_rolls_back_before_the_pointers_move(
    tmp_path: Path, behaviour: str, code: str
) -> None:
    hook = tmp_path / "verify.sh"
    hook.write_text("#!/bin/sh\n", encoding="utf-8")
    installation = _migrating_installation(
        tmp_path,
        spec={"hooks": [{"name": "post-verify", "argv": [str(hook)], "timeout_seconds": 5}]},
    )
    installation.host.hook_results[str(hook)] = behaviour

    outcome = installation.workflow.apply(expect_current=PREVIOUS_RELEASE_ID)

    assert outcome.outcome == OUTCOME_ROLLED_BACK
    assert outcome.report["error"] == code
    assert outcome.report["hooks"] == [
        {"name": "post-verify", "status": "failed", "code": code}
    ]
    assert installation.host.containers["blockwart"].image == OLD_IMAGE
    assert installation.workflow.store.read_pointer(CURRENT_POINTER).release_id == (
        PREVIOUS_RELEASE_ID
    )


def test_retention_never_removes_the_active_or_rollback_release(tmp_path: Path) -> None:
    installation = Installation(tmp_path, spec={"state": {"retention": 2}})
    installation.seed_running_release()
    store = installation.workflow.store
    for index in range(4):
        stale = store.bundle_dir(f"stale-release-{index}")
        stale.mkdir(mode=0o750, parents=True)
        (stale / "manifest.json").write_text("{}", encoding="utf-8")

    report = installation.workflow.apply(expect_current=PREVIOUS_RELEASE_ID).report

    remaining = {path.name for path in store.releases_dir.iterdir()}
    assert installation.workflow.release_id in remaining
    assert PREVIOUS_RELEASE_ID in remaining
    assert report["retention"]["removed"]
    assert all(name.startswith("stale-release-") for name in report["retention"]["removed"])


def test_report_failure_restores_complete_pointer_pair_with_existing_bundles(
    tmp_path: Path,
) -> None:
    installation = Installation(tmp_path, spec={"state": {"retention": 2}})
    current = installation.seed_running_release()
    store = installation.workflow.store
    older_id = "bbbbbbbbbbbb-eeeeeeeeeeee"
    artifacts = {
        "build": {"release": older_id},
        "contract": {"release": older_id},
        "source": {"release": older_id},
    }
    manifest = {
        "manifest_version": 1,
        "release_id": older_id,
        "contract_digest": "e" * 64,
        "source": {"commit": "c" * 40, "tree": "e" * 40, "clean": True},
        "image": {
            "repository": "blockwart",
            "tag": f"blockwart:{older_id}",
            "digest": OLD_IMAGE,
            "runtime": "docker",
            "mode": "build",
            "build_revision": "c" * 40,
        },
        "schema": {
            "expected_revision": SCHEMA_REVISION,
            "packaged_revision": SCHEMA_REVISION,
        },
        "artifacts": [
            {"name": name, "sha256": json_artifact_digest(artifacts[name])}
            for name in ("build", "contract", "source")
        ],
    }
    record = store.write_bundle(older_id, manifest=manifest, artifacts=artifacts)
    older = Pointer(
        release_id=older_id,
        generation=1,
        manifest_digest=record.manifest_digest,
        image_digest=OLD_IMAGE,
        source_commit="c" * 40,
        schema_revision=SCHEMA_REVISION,
        runtime_layout_digest=runtime_layout_digest(
            installation.spec, build_revision="c" * 40
        ),
        updated_at="2026-07-01T00:00:00Z",
    )
    store.write_pointers(current=current, previous=older)
    store.append_history(
        {
            "generation": 1,
            "release_id": older_id,
            "image_digest": OLD_IMAGE,
            "manifest_digest": record.manifest_digest,
            "source_commit": "c" * 40,
            "outcome": OUTCOME_SUCCEEDED,
            "committed_at": older.updated_at,
        }
    )

    def refuse_report(_name: str, _payload: Any) -> str:
        raise ReleaseError("report_storage_failed", gate="completion_report")

    store.write_report = refuse_report  # type: ignore[method-assign]
    outcome = installation.workflow.apply(expect_current=PREVIOUS_RELEASE_ID)

    assert outcome.outcome == OUTCOME_ROLLED_BACK
    restored_current = store.read_pointer(CURRENT_POINTER)
    restored_previous = store.read_pointer(PREVIOUS_POINTER)
    assert restored_current == current
    assert restored_previous == older
    assert restored_current is not None and store.bundle_dir(restored_current.release_id).is_dir()
    assert restored_previous is not None and store.bundle_dir(restored_previous.release_id).is_dir()
