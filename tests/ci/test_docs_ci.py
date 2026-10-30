"""Dependency-free routing proof, also executed by the lightweight docs job."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

CI_SCRIPTS = Path(__file__).resolve().parents[2] / "scripts" / "ci"
sys.path.insert(0, str(CI_SCRIPTS))

from check_docs import check_document  # noqa: E402
from classify_changes import PROSE_FILES, classify  # noqa: E402


class RepositoryCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.repo = Path(self.temporary.name)
        self.git("init", "--initial-branch=main")
        self.git("config", "user.email", "ci@example.invalid")
        self.git("config", "user.name", "CI fixture")
        self.git("config", "commit.gpgsign", "false")
        for name in (*PROSE_FILES, "README.md", "docs/contract.md", "src/runtime.py"):
            self.write(name, "Original prose\n")
        self.initial = self.commit()

    def git(self, *args: str) -> str:
        return subprocess.run(
            ["git", "-C", str(self.repo), *args], capture_output=True, check=True, text=True
        ).stdout.strip()

    def write(self, name: str, text: str) -> None:
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def commit(self) -> str:
        self.git("add", "--all")
        self.git("commit", "-m", "Synthetic CI fixture")
        return self.git("rev-parse", "HEAD")

    def push(self, head: str, base: str | None = None) -> str:
        return classify(self.repo, "push", {"before": base or self.initial, "after": head}).mode

    def pr(self, head: str, base: str | None = None) -> str:
        return classify(
            self.repo,
            "pull_request",
            {"pull_request": {"base": {"sha": base or self.initial}, "head": {"sha": head}}},
        ).mode

    def test_push_allowlist_is_exact_not_extension_or_directory_based(self) -> None:
        for name in (
            "CONTRIBUTING.md",
            "SECURITY.md",
            "README.md",
            "CHANGELOG.md",
            "docs/prose.md",
            "docs/agent-api.md",
            "src/runtime.py",
            "pyproject.toml",
            "requirements/dev.txt",
            "Dockerfile",
            ".dockerignore",
            ".github/workflows/ci.yml",
            ".gitea/workflows/ci.yml",
            "scripts/ci/classify_changes.py",
            "src/migrations/versions/change.py",
            "tests/contracts/openapi.json",
            "examples/agent-skill/blockwart/SKILL.md",
            "new.md",
            "docs/has\na-newline.md",
            "unknown\tfile.md",
        ):
            with self.subTest(name=name):
                self.git("reset", "--hard", self.initial)
                self.write(name, "Changed prose\n")
                head = self.commit()
                self.assertEqual(self.push(head), "docs" if name in PROSE_FILES else "full")

    def test_multi_commit_and_mixed_pushes_keep_full_proof(self) -> None:
        self.write("src/runtime.py", "runtime change\n")
        self.commit()
        self.write("CONTRIBUTING.md", "Only the latest commit is prose\n")
        head = self.commit()
        self.assertEqual(self.push(head), "full")
        self.assertEqual(self.pr(head), "full")

    def test_deletion_of_safe_prose_is_eligible(self) -> None:
        (self.repo / "SECURITY.md").unlink()
        head = self.commit()
        self.assertEqual(self.push(head), "docs")
        self.assertEqual(self.pr(head), "docs")

    def test_rename_checks_both_old_and_new_paths(self) -> None:
        self.git("mv", "SECURITY.md", "renamed.md")
        self.assertEqual(self.push(self.commit()), "full")
        self.git("reset", "--hard", self.initial)
        (self.repo / "SECURITY.md").unlink()
        self.git("mv", "src/runtime.py", "SECURITY.md")
        self.assertEqual(self.push(self.commit()), "full")

    def test_rename_between_allowlisted_paths_is_eligible(self) -> None:
        (self.repo / "CONTRIBUTING.md").unlink()
        self.git("mv", "SECURITY.md", "CONTRIBUTING.md")
        self.assertEqual(self.push(self.commit()), "docs")

    def test_symlink_and_executable_prose_are_not_eligible(self) -> None:
        path = self.repo / "SECURITY.md"
        path.unlink()
        path.symlink_to("README.md")
        self.assertEqual(self.push(self.commit()), "full")
        self.git("reset", "--hard", self.initial)
        path.chmod(0o755)
        self.assertEqual(self.push(self.commit()), "full")

    def test_pr_uses_merge_base_not_push_before_or_last_commit(self) -> None:
        self.git("checkout", "-b", "prose")
        self.write("CONTRIBUTING.md", "Prose branch\n")
        head = self.commit()
        self.git("checkout", "main")
        self.write("src/runtime.py", "Independent base-branch change\n")
        base = self.commit()
        self.git("checkout", "prose")
        self.assertEqual(self.pr(head, base), "docs")
        self.git("checkout", "main")
        self.git("merge", "--no-ff", "prose", "-m", "Synthetic PR merge")
        self.assertEqual(self.pr(head, base), "docs")

    def test_ambiguous_criss_cross_merge_bases_fall_back(self) -> None:
        self.write("CONTRIBUTING.md", "First side\n")
        first = self.commit()
        self.git("checkout", "--detach", self.initial)
        self.write("SECURITY.md", "Second side\n")
        second = self.commit()
        # Opposite merge-parent orders produce two incomparable common bases.
        first_merge = self.git(
            "commit-tree",
            first + "^{tree}",
            "-p",
            first,
            "-p",
            second,
            "-m",
            "Synthetic first merge",
        )
        second_merge = self.git(
            "commit-tree",
            second + "^{tree}",
            "-p",
            second,
            "-p",
            first,
            "-m",
            "Synthetic second merge",
        )
        self.git("checkout", "--detach", second_merge)
        self.assertEqual(self.pr(second_merge, first_merge), "full")

    def test_pr_also_checks_the_actual_merge_tree(self) -> None:
        self.git("checkout", "-b", "prose")
        self.write("CONTRIBUTING.md", "Prose branch\n")
        head = self.commit()
        self.git("checkout", "main")
        self.git("merge", "--no-ff", "--no-commit", "prose")
        self.write("src/runtime.py", "Unexpected merge-resolution change\n")
        self.commit()
        self.assertEqual(self.pr(head), "full")

    def test_missing_history_new_branch_empty_or_unknown_events_fall_back(self) -> None:
        self.write("SECURITY.md", "Prose change\n")
        head = self.commit()
        for event in (
            None,
            [],
            {},
            {"before": "0" * 40, "after": head},
            {"before": "a" * 40, "after": head},
            {"before": "HEAD~1", "after": head},
            {"before": self.initial, "after": "--help"},
            {"before": head, "after": head},
            {"before": self.initial, "after": self.initial},
        ):
            with self.subTest(event=event):
                self.assertEqual(classify(self.repo, "push", event).mode, "full")
        self.assertEqual(classify(self.repo, "workflow_dispatch", {}).mode, "full")
        self.assertEqual(classify(self.repo, "pull_request", {}).mode, "full")

    def test_shallow_clone_without_before_falls_back(self) -> None:
        self.write("SECURITY.md", "Prose change\n")
        head = self.commit()
        clone = self.repo / "shallow"
        self.git("clone", "--depth=1", self.repo.as_uri(), str(clone))
        self.assertEqual(
            classify(clone, "push", {"before": self.initial, "after": head}).mode, "full"
        )

    def test_non_fast_forward_push_and_unexpected_pr_checkout_fall_back(self) -> None:
        self.write("SECURITY.md", "First branch\n")
        old_head = self.commit()
        self.git("reset", "--hard", self.initial)
        self.write("CONTRIBUTING.md", "Replacement branch\n")
        head = self.commit()
        self.assertEqual(self.push(head, old_head), "full")
        self.assertEqual(self.pr(old_head), "full")
        self.git("checkout", "--orphan", "unrelated")
        self.write("CONTRIBUTING.md", "Unrelated history\n")
        unrelated = self.commit()
        self.assertEqual(self.pr(unrelated, head), "full")

    def test_cli_writes_only_a_validated_mode_and_handles_malformed_json(self) -> None:
        self.write("SECURITY.md", "Prose change\n")
        head = self.commit()
        event_path = self.repo / "event.json"
        output_path = self.repo / "output"
        for payload, expected in (
            (json.dumps({"before": self.initial, "after": head}), "docs"),
            ("malformed JSON", "full"),
        ):
            with self.subTest(payload=payload):
                event_path.write_text(payload)
                output_path.write_text("")
                result = subprocess.run(
                    [sys.executable, str(CI_SCRIPTS / "classify_changes.py")],
                    cwd=self.repo,
                    capture_output=True,
                    text=True,
                    env={
                        **os.environ,
                        "GITHUB_EVENT_PATH": str(event_path),
                        "GITHUB_EVENT_NAME": "push",
                        "GITHUB_OUTPUT": str(output_path),
                    },
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(output_path.read_text(), f"mode={expected}\n")


class ProseCheckCase(unittest.TestCase):
    def test_offline_checks_detect_real_prose_errors(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "SECURITY.md"
            (root / "target.md").write_text("Target\n")
            path.write_text(
                "# Policy\n\n[Local](target.md#fragment) and [Web](https://example.invalid)\n"
            )
            self.assertEqual(check_document(root, path.name), [])
            for content, error in (
                (b"bad \n", "trailing whitespace"),
                (b"bad", "end with a newline"),
                (b"\xff\n", "not UTF-8"),
                (b"<<<<<<< HEAD\n", "conflict marker"),
                (b"```bash\necho example\n", "unclosed fenced"),
                (b"[Broken](missing.md)\n", "missing/unsafe local link"),
                (b"[Outside](../outside.md)\n", "missing/unsafe local link"),
                (b"\n", "nonempty"),
            ):
                with self.subTest(error=error):
                    path.write_bytes(content)
                    messages = check_document(root, path.name)
                    self.assertTrue(any(error in message for message in messages))
            path.write_text("```markdown\n[Example](not-a-real-file.md)\n```\n")
            self.assertEqual(check_document(root, path.name), [])
            path.unlink()
            self.assertEqual(check_document(root, path.name), [])
            path.symlink_to("target.md")
            self.assertTrue(check_document(root, path.name))


if __name__ == "__main__":
    unittest.main()
