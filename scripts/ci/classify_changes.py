"""Conservative, dependency-free CI routing; unknown inputs always need full proof."""

from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

# Audited non-packaged prose, not a Markdown glob. README, docs/, examples and
# CHANGELOG (release evidence) deliberately remain on the full path.
PROSE_FILES = frozenset({"CONTRIBUTING.md", "SECURITY.md"})
SHA = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")


@dataclass(frozen=True)
class Classification:
    mode: str
    reason: str


def git(repo: Path, *args: str) -> bytes:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True).stdout


def commit(repo: Path, value: object) -> str:
    if not isinstance(value, str) or not SHA.fullmatch(value) or set(value) == {"0"}:
        raise ValueError("missing or invalid commit ID")
    resolved = git(repo, "rev-parse", "--verify", value + "^{commit}").decode().strip()
    if resolved != value:
        raise ValueError("commit did not resolve exactly")
    return value


def changed_paths(repo: Path, base: str, head: str) -> set[str]:
    # Disable rename detection: both old and new names must be eligible. NUL
    # separation also handles tabs/newlines without mistaking them for paths.
    raw = git(repo, "diff", "--no-ext-diff", "--no-renames", "--name-only", "-z", base, head)
    return {name.decode("utf-8") for name in raw.split(b"\0") if name}


def regular_or_absent(repo: Path, revision: str, path: str) -> bool:
    entry = git(repo, "ls-tree", "-z", revision, "--", path)
    return not entry or entry.startswith(b"100644 blob ")


def classify(repo: Path, event_name: str, event: object) -> Classification:
    try:
        if not isinstance(event, dict):
            raise ValueError("event is not an object")
        checkout = git(repo, "rev-parse", "HEAD").decode().strip()
        if event_name == "pull_request":
            pr = event["pull_request"]
            base = commit(repo, pr["base"]["sha"])
            head = commit(repo, pr["head"]["sha"])
            merge_bases = git(repo, "merge-base", "--all", base, head).decode().split()
            if len(merge_bases) != 1:
                raise ValueError("PR has no unique merge base")
            ranges = [(merge_bases[0], head)]
            if checkout != head:
                parents = git(repo, "show", "-s", "--format=%P", checkout).decode().split()
                if parents != [base, head]:
                    raise ValueError("checkout is neither PR head nor its expected merge")
                # Also cover the actual merge result, not only the PR branch.
                ranges.append((base, checkout))
        elif event_name == "push":
            base = commit(repo, event["before"])
            head = commit(repo, event["after"])
            if checkout != head:
                raise ValueError("checkout does not match push after")
            git(repo, "merge-base", "--is-ancestor", base, head)
            ranges = [(base, head)]
        else:
            raise ValueError("unsupported event")

        paths = set().union(*(changed_paths(repo, start, end) for start, end in ranges))
        if not paths:
            return Classification("full", "empty diff")
        if not paths <= PROSE_FILES:
            return Classification("full", "changes outside audited prose allowlist")
        for start, end in ranges:
            for path in paths:
                if not all(regular_or_absent(repo, revision, path) for revision in (start, end)):
                    return Classification("full", "non-regular prose file")
        return Classification("docs", "only audited, non-packaged prose changed")
    except (KeyError, TypeError, ValueError, OSError, subprocess.CalledProcessError):
        # Missing history (including shallow/new/force pushes), malformed events,
        # unexpected checkout shape or unavailable Git proof must never skip CI.
        return Classification("full", "reliable diff unavailable")


def main() -> None:
    try:
        event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    except (KeyError, OSError, ValueError):
        event = None
    result = classify(Path.cwd(), os.environ.get("GITHUB_EVENT_NAME", ""), event)
    print(f"CI path: {result.mode} ({result.reason})")
    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as output:
        output.write(f"mode={result.mode}\n")


if __name__ == "__main__":
    main()
