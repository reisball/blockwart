"""Exercise the real stable-gate shell and required-job wiring."""

from __future__ import annotations

import itertools
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def workflow() -> dict:
    return yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())


def test_workflow_parity_and_proof_wiring() -> None:
    assert (ROOT / ".github/workflows/ci.yml").read_bytes() == (
        ROOT / ".gitea/workflows/ci.yml"
    ).read_bytes()
    config = workflow()
    # PyYAML's YAML 1.1 loader treats the Actions "on" key as boolean True.
    triggers = config.get("on", config.get(True))
    assert triggers == {"pull_request": None, "push": {"branches": ["main"]}}
    assert config["permissions"] == {"contents": "read"}
    jobs = config["jobs"]
    assert set(jobs) == {"classify", "docs", "full", "verify"}
    assert jobs["classify"]["steps"][0]["with"]["fetch-depth"] == 0
    assert jobs["classify"]["outputs"] == {"mode": "${{ steps.changes.outputs.mode }}"}
    for name in ("docs", "full"):
        assert jobs[name]["needs"] == "classify"
        assert jobs[name]["if"] == f"needs.classify.outputs.mode == '{name}'"
    assert "services" not in jobs["docs"]
    assert jobs["full"]["services"]["postgres"]["image"] == "postgres:16"
    assert jobs["full"]["timeout-minutes"] == 60
    commands = "\n".join(step.get("run", "") for step in jobs["docs"]["steps"])
    assert "check_docs.py" in commands
    assert "unittest discover -s tests/ci" in commands
    assert "cmp .gitea/workflows/ci.yml .github/workflows/ci.yml" in commands
    for heavyweight in ("pip install", "pytest", "docker", "package-smoke", "container-smoke"):
        assert heavyweight not in commands
    gate = jobs["verify"]
    assert gate["if"] == "always()"
    assert set(gate["needs"]) == {"classify", "docs", "full"}
    assert gate["steps"][0]["env"] == {
        "CLASSIFY_RESULT": "${{ needs.classify.result }}",
        "MODE": "${{ needs.classify.outputs.mode }}",
        "DOCS_RESULT": "${{ needs.docs.result }}",
        "FULL_RESULT": "${{ needs.full.result }}",
    }


def test_required_verify_fails_closed_for_every_job_outcome() -> None:
    shell = workflow()["jobs"]["verify"]["steps"][0]["run"]
    outcomes = ("success", "failure", "cancelled", "skipped", "")
    for mode, classifier, docs, full in itertools.product(
        ("docs", "full", "", "unknown"), outcomes, outcomes, outcomes
    ):
        result = subprocess.run(
            ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", shell],
            env={
                **os.environ,
                "MODE": mode,
                "CLASSIFY_RESULT": classifier,
                "DOCS_RESULT": docs,
                "FULL_RESULT": full,
            },
            capture_output=True,
        )
        expected = classifier == "success" and (
            (mode == "docs" and docs == "success" and full == "skipped")
            or (mode == "full" and full == "success" and docs == "skipped")
        )
        assert (result.returncode == 0) == expected, (mode, classifier, docs, full)


def test_real_prose_only_push_runs_the_actual_lightweight_commands(tmp_path: Path) -> None:
    # Execute the workflow's real shell in a disposable repository. Neither an
    # application install, PostgreSQL nor Docker is needed for this proof.
    inputs = [
        ".github/workflows/ci.yml",
        ".gitea/workflows/ci.yml",
        "CONTRIBUTING.md",
        "SECURITY.md",
        "docs/ci.md",
        "docs/security.md",
    ]
    inputs += [
        str(path.relative_to(ROOT))
        for directory in ("scripts/ci", "tests/ci")
        for path in (ROOT / directory).glob("*.py")
    ]
    for name in inputs:
        destination = tmp_path / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / name, destination)

    def git(*args: str) -> str:
        return subprocess.run(
            ["git", *args], cwd=tmp_path, check=True, capture_output=True, text=True
        ).stdout.strip()

    git("init", "--initial-branch=main")
    git("config", "user.email", "ci@example.invalid")
    git("config", "user.name", "CI fixture")
    git("config", "commit.gpgsign", "false")
    git("add", ".")
    git("commit", "-m", "Synthetic baseline")
    before = git("rev-parse", "HEAD")
    contributing = tmp_path / "CONTRIBUTING.md"
    contributing.write_text(contributing.read_text() + "\nProse-only CI acceptance example.\n")
    git("add", "CONTRIBUTING.md")
    git("commit", "-m", "Synthetic prose-only change")
    after = git("rev-parse", "HEAD")
    event = tmp_path / "event.json"
    event.write_text(json.dumps({"before": before, "after": after}))
    output = tmp_path / "output"
    classifier = subprocess.run(
        [sys.executable, str(tmp_path / "scripts/ci/classify_changes.py")],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_EVENT_PATH": str(event),
            "GITHUB_OUTPUT": str(output),
        },
    )
    assert classifier.returncode == 0, classifier.stderr
    assert output.read_text() == "mode=docs\n"
    docs_command = workflow()["jobs"]["docs"]["steps"][-1]["run"]
    # Make the workflow's `python` resolve to this test's known Python 3.12.
    bin_directory = tmp_path / "bin"
    bin_directory.mkdir()
    (bin_directory / "python").symlink_to(sys.executable)
    proof = subprocess.run(
        ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", docs_command],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        env={**os.environ, "PATH": f"{bin_directory}:{os.environ['PATH']}"},
    )
    assert proof.returncode == 0, proof.stdout + proof.stderr
    assert "Audited prose:" in proof.stdout
    assert "test_pr_uses_merge_base_not_push_before_or_last_commit" in proof.stderr
    assert "\nOK\n" in proof.stderr
