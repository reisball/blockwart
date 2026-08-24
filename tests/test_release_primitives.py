from __future__ import annotations

import os
import sqlite3
import subprocess
from pathlib import Path

import pytest

from blockwart.release.backup import (
    create_online_backup,
    prune_managed_backups,
    verify_backup,
)
from blockwart.release.canonical import require_secret_free
from blockwart.release.errors import ReleaseError
from blockwart.release.runtime import SubprocessCommandRunner
from blockwart.release.source import verify_source


def test_secret_shaped_output_is_rejected_without_echoing_the_value() -> None:
    with pytest.raises(ReleaseError) as failure:
        require_secret_free({"password": "omitted"}, code="unsafe_report_content")

    assert failure.value.code == "unsafe_report_content"
    assert str(failure.value) == "unsafe_report_content"


def _git(repository: Path, *argv: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repository), *argv],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def test_real_git_source_requires_exact_reachable_clean_commit(tmp_path: Path) -> None:
    repository = tmp_path / "source"
    repository.mkdir(mode=0o750)
    _git(repository, "init", "--quiet")
    _git(repository, "config", "user.name", "Release Test")
    _git(repository, "config", "user.email", "release@example.invalid")
    tracked = repository / "tracked.txt"
    tracked.write_text("committed\n", encoding="utf-8")
    _git(repository, "add", "tracked.txt")
    _git(repository, "commit", "--quiet", "-m", "test source")
    commit = _git(repository, "rev-parse", "HEAD")
    runner = SubprocessCommandRunner()

    evidence = verify_source(
        runner=runner,
        repository_root=repository,
        commit=commit,
        timeout_seconds=10,
    )

    assert evidence.commit == commit
    assert evidence.clean is True

    with pytest.raises(ReleaseError) as short_failure:
        verify_source(
            runner=runner,
            repository_root=repository,
            commit=commit[:12],
            timeout_seconds=10,
        )
    assert short_failure.value.code == "source_commit_not_exact_sha"

    tracked.write_text("dirty\n", encoding="utf-8")
    with pytest.raises(ReleaseError) as dirty_failure:
        verify_source(
            runner=runner,
            repository_root=repository,
            commit=commit,
            timeout_seconds=10,
        )
    assert dirty_failure.value.code == "source_tree_dirty"


def test_real_git_rejects_an_unreachable_commit_object(tmp_path: Path) -> None:
    repository = tmp_path / "source"
    repository.mkdir(mode=0o750)
    _git(repository, "init", "--quiet")
    _git(repository, "config", "user.name", "Release Test")
    _git(repository, "config", "user.email", "release@example.invalid")
    tracked = repository / "tracked.txt"
    tracked.write_text("committed\n", encoding="utf-8")
    _git(repository, "add", "tracked.txt")
    _git(repository, "commit", "--quiet", "-m", "reachable")
    tree = _git(repository, "rev-parse", "HEAD^{tree}")
    unreachable = _git(repository, "commit-tree", tree, "-m", "unreachable")

    with pytest.raises(ReleaseError) as failure:
        verify_source(
            runner=SubprocessCommandRunner(),
            repository_root=repository,
            commit=unreachable,
            timeout_seconds=10,
        )
    assert failure.value.code == "source_commit_unreachable"


def test_sqlite_online_backup_excludes_uncommitted_writes_and_verifies_receipt(
    tmp_path: Path,
) -> None:
    database = tmp_path / "live.sqlite3"
    backup = tmp_path / "backups" / "pre-release.sqlite3"
    backup.parent.mkdir(mode=0o750)
    writer = sqlite3.connect(database)
    writer.execute("PRAGMA journal_mode=WAL")
    writer.execute("CREATE TABLE records (id INTEGER PRIMARY KEY, value TEXT NOT NULL)")
    writer.execute("INSERT INTO records(value) VALUES ('committed')")
    writer.commit()
    database.chmod(0o640)
    writer.execute("BEGIN IMMEDIATE")
    writer.execute("INSERT INTO records(value) VALUES ('uncommitted')")
    try:
        receipt = create_online_backup(
            database_path=database,
            backup_path=backup,
            release_id="release-test",
            source_commit="a" * 40,
            created_at="2026-08-22T12:00:00Z",
        )
    finally:
        writer.rollback()
        writer.close()

    verify_backup(backup, receipt, gate="test")
    restored = sqlite3.connect(f"{backup.as_uri()}?mode=ro", uri=True)
    try:
        assert restored.execute("SELECT value FROM records ORDER BY id").fetchall() == [
            ("committed",)
        ]
    finally:
        restored.close()

    receipt_path = backup.with_name(f"{backup.name}.receipt.json")
    receipt_path.chmod(0o600)
    receipt_path.write_text("{}\n", encoding="utf-8")
    receipt_path.chmod(0o400)
    with pytest.raises(ReleaseError) as tampered:
        verify_backup(backup, receipt, gate="test")
    assert tampered.value.code == "invalid_backup_receipt"


def test_backup_retention_removes_only_old_managed_attempts(tmp_path: Path) -> None:
    database = tmp_path / "live.sqlite3"
    connection = sqlite3.connect(database)
    connection.execute("CREATE TABLE records (id INTEGER PRIMARY KEY)")
    connection.commit()
    connection.close()
    database.chmod(0o640)
    root = tmp_path / "backups"
    root.mkdir(mode=0o750)
    attempts: list[Path] = []
    for index in range(3):
        directory = root / f"release-{index}-20260822T12000{index}000000Z"
        directory.mkdir(mode=0o750)
        create_online_backup(
            database_path=database,
            backup_path=directory / "pre-release.sqlite3",
            release_id=f"release-{index}",
            source_commit="a" * 40,
            created_at=f"2026-08-22T12:00:0{index}Z",
        )
        os.utime(directory, ns=(index + 1, index + 1))
        attempts.append(directory)
    unrelated = root / "operator-owned"
    unrelated.mkdir(mode=0o750)

    removed = prune_managed_backups(
        root,
        retention=2,
        protected=(attempts[-1],),
    )

    assert removed == (attempts[0].name,)
    assert not attempts[0].exists()
    assert attempts[1].is_dir()
    assert attempts[2].is_dir()
    assert unrelated.is_dir()
