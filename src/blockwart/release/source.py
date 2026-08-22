from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from blockwart.release.canonical import is_commit_sha
from blockwart.release.errors import ReleaseError
from blockwart.release.runtime import CommandRunner

SOURCE_GATE = "source_verified"


@dataclass(frozen=True, slots=True)
class SourceEvidence:
    """Proof that the working tree matches exactly one immutable commit."""

    commit: str
    tree: str
    clean: bool

    def summary(self) -> dict[str, Any]:
        return {"commit": self.commit, "tree": self.tree, "clean": self.clean}


def verify_source(
    *,
    runner: CommandRunner,
    repository_root: Path,
    commit: str,
    timeout_seconds: int,
) -> SourceEvidence:
    """Reject every unsafe source state before the workflow mutates anything.

    Accepts only an exact full commit SHA whose object exists, is reachable
    from a ref, is checked out at ``HEAD``, and has no working-tree or index
    modification.
    """
    if not is_commit_sha(commit):
        raise ReleaseError("source_commit_not_exact_sha", gate=SOURCE_GATE)
    if not repository_root.is_dir() or repository_root.is_symlink():
        raise ReleaseError("source_root_missing", gate=SOURCE_GATE)

    def git(*arguments: str) -> tuple[bool, str]:
        result = runner.run(
            ("git", "-C", str(repository_root), "--no-pager", *arguments),
            timeout_seconds=timeout_seconds,
        )
        if result.timed_out:
            raise ReleaseError("source_command_timeout", gate=SOURCE_GATE)
        return result.ok, result.stdout.strip()

    ok, toplevel = git("rev-parse", "--show-toplevel")
    if not ok:
        raise ReleaseError("source_not_a_repository", gate=SOURCE_GATE)
    if toplevel != str(repository_root):
        raise ReleaseError("source_root_mismatch", gate=SOURCE_GATE)

    # A 40-character SHA that also names a DWIM ref is ambiguous and never accepted.
    ok, symbolic = git(
        "for-each-ref",
        "--count=2",
        "--format=%(refname)",
        f"refs/heads/{commit}",
        f"refs/tags/{commit}",
        f"refs/remotes/{commit}",
    )
    if not ok:
        raise ReleaseError("source_refs_unreadable", gate=SOURCE_GATE)
    if symbolic:
        raise ReleaseError("source_commit_ambiguous", gate=SOURCE_GATE)

    ok, object_type = git("cat-file", "-t", commit)
    if not ok:
        raise ReleaseError("source_commit_missing", gate=SOURCE_GATE)
    if object_type != "commit":
        raise ReleaseError("source_commit_not_a_commit", gate=SOURCE_GATE)

    ok, containing = git("for-each-ref", "--count=1", "--format=%(refname)", "--contains", commit)
    if not ok or not containing:
        raise ReleaseError("source_commit_unreachable", gate=SOURCE_GATE)

    ok, head = git("rev-parse", "HEAD")
    if not ok:
        raise ReleaseError("source_head_unreadable", gate=SOURCE_GATE)
    if head != commit:
        raise ReleaseError("source_ref_drift", gate=SOURCE_GATE)

    ok, status = git("status", "--porcelain=v1", "--untracked-files=normal")
    if not ok:
        raise ReleaseError("source_status_unreadable", gate=SOURCE_GATE)
    if status:
        raise ReleaseError("source_tree_dirty", gate=SOURCE_GATE)

    ok, tree = git("rev-parse", f"{commit}^{{tree}}")
    if not ok or not is_commit_sha(tree):
        raise ReleaseError("source_tree_unreadable", gate=SOURCE_GATE)

    return SourceEvidence(commit=commit, tree=tree, clean=True)
