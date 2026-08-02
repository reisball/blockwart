from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import threading
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

MODULE_PATH = Path(__file__).parents[1] / "scripts" / "migration" / "export_gitea.py"
MODULE_SPEC = importlib.util.spec_from_file_location("blockwart_export_gitea", MODULE_PATH)
assert MODULE_SPEC is not None and MODULE_SPEC.loader is not None
export_gitea = importlib.util.module_from_spec(MODULE_SPEC)
sys.modules[MODULE_SPEC.name] = export_gitea
MODULE_SPEC.loader.exec_module(export_gitea)

TOKEN = b"gitea-test-token-exact-6c32c0fdb04d"
FIXED_TIME = datetime(2026, 8, 2, 12, 34, 56, tzinfo=UTC)
REPOSITORY = "services/blockwart"


class FakeGiteaState:
    def __init__(self) -> None:
        self.origin = ""
        self.auth_status: int | None = None
        self.total_overrides: dict[str, int] = {}
        self.duplicate_issue_id = False
        self.mutate_confirmation = False
        self.mutate_pull_subresources = False
        self.unavailable_pull_evidence = False
        self.redirect_asset = False
        self.issue_index_cycles = 0
        self.pull_commit_cycles = 0
        self.labels = [
            {"id": number, "name": f"label-{number}", "color": "abcdef"}
            for number in range(1, 52)
        ]

    @property
    def first_asset(self) -> dict[str, object]:
        return {
            "id": 7001,
            "uuid": "asset-issue-1",
            "name": "issue.png",
            "browser_download_url": f"{self.origin}/assets/asset-issue-1",
        }

    @property
    def second_asset(self) -> dict[str, object]:
        return {
            "id": 7002,
            "uuid": "asset-comment-2",
            "name": "comment.txt",
            "browser_download_url": f"{self.origin}/assets/asset-comment-2",
        }

    def issue(self, number: int) -> dict[str, object]:
        labels = [self.labels[0]] if number == 1 else []
        issue: dict[str, object] = {
            "id": 1000 + number,
            "number": number,
            "title": f"Issue {number}",
            "state": "open" if number % 2 else "closed",
            "labels": labels,
            "updated_at": "2026-08-02T00:00:00Z",
        }
        if number == 1:
            issue["assets"] = [self.first_asset]
        return issue

    def issue_indexes(self) -> list[dict[str, object]]:
        items = [self.issue(number) for number in range(1, 86)]
        for item in items:
            item.pop("assets", None)
        if self.duplicate_issue_id:
            items[1]["id"] = items[0]["id"]
        if self.mutate_confirmation and self.issue_index_cycles >= 2:
            items[0]["title"] = "Issue 1 changed concurrently"
        return items

    def pull(self) -> dict[str, object]:
        return {
            "id": 2087,
            "number": 87,
            "title": "Historical pull request",
            "state": "closed",
            "merged": True,
            "merged_at": "2026-08-01T00:00:00Z",
            "mergeable": True,
            "merge_commit_sha": "b" * 40,
            "base": {"ref": "main", "sha": "a" * 40},
            "head": {"ref": "feature", "sha": "c" * 40},
            "labels": [],
            "updated_at": "2026-08-01T00:00:00Z",
        }

    def issue_detail(self, number: int) -> dict[str, object]:
        if number == 87:
            return {
                "id": 3087,
                "number": 87,
                "title": "Historical pull request",
                "state": "closed",
                "labels": [],
            }
        return self.issue(number)

    def comments(self, number: int) -> list[dict[str, object]]:
        if number == 1:
            return [{"id": 9001, "body": "issue comment", "assets": []}]
        if number == 2:
            return [
                {
                    "id": 9002,
                    "body": "comment attachment",
                    "assets": [self.second_asset],
                }
            ]
        return []

    def global_comments(self) -> list[dict[str, object]]:
        return [
            {
                **comment,
                "issue_url": f"{self.origin}/api/v1/repos/{REPOSITORY}/issues/{number}",
            }
            for number in (1, 2)
            for comment in self.comments(number)
        ]

    def assets(self, number: int) -> list[dict[str, object]]:
        if number == 1:
            return [self.first_asset]
        if number == 2:
            return [self.second_asset]
        return []


class _FakeGiteaHandler(BaseHTTPRequestHandler):
    server: FakeGiteaServer

    def log_message(self, format: str, *args: object) -> None:
        del format, args

    def _send_json(
        self,
        payload: object,
        *,
        total_key: str | None = None,
        total_count: int | None = None,
    ) -> None:
        raw = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        if total_key is not None:
            total = self.server.state.total_overrides.get(total_key, total_count)
            assert total is not None
            self.send_header("X-Total-Count", str(total))
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _send_list(self, values: list[object], *, total_key: str | None = None) -> None:
        query = parse_qs(urlsplit(self.path).query)
        page = int(query.get("page", ["1"])[0])
        limit = int(query.get("limit", ["50"])[0])
        start = (page - 1) * limit
        self._send_json(
            values[start : start + limit],
            total_key=total_key,
            total_count=len(values),
        )

    def do_GET(self) -> None:  # noqa: N802
        state = self.server.state
        if self.headers.get("Authorization") != f"token {TOKEN.decode()}":
            self.send_error(401)
            return
        if state.auth_status is not None:
            self.send_error(state.auth_status)
            return
        parsed = urlsplit(self.path)
        path = parsed.path
        if path == "/redirect":
            self.send_response(302)
            self.send_header("Location", f"{state.origin}/assets/asset-issue-1")
            self.end_headers()
            return
        if path.startswith("/assets/"):
            if state.redirect_asset:
                self.send_response(302)
                self.send_header("Location", f"{state.origin}/assets/final")
                self.end_headers()
                return
            payloads = {
                "/assets/asset-issue-1": b"issue-asset-bytes",
                "/assets/asset-comment-2": b"comment-asset-bytes",
            }
            payload = payloads.get(path)
            if payload is None:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return

        root = f"/api/v1/repos/{REPOSITORY}"
        if path == f"{root}/labels":
            self._send_list(state.labels, total_key="labels")
            return
        if path == f"{root}/issues" and parse_qs(parsed.query).get("type") == ["issues"]:
            query = parse_qs(parsed.query)
            if query.get("page", ["1"]) == ["1"]:
                state.issue_index_cycles += 1
            self._send_list(state.issue_indexes(), total_key="issues")
            return
        if path == f"{root}/pulls":
            self._send_list([state.pull()], total_key="pull_requests")
            return
        if path == f"{root}/issues/comments":
            self._send_list(state.global_comments(), total_key="comments")
            return

        relative = path.removeprefix(root)
        parts = [part for part in relative.split("/") if part]
        if len(parts) == 2 and parts[0] == "issues" and parts[1].isdigit():
            self._send_json(state.issue_detail(int(parts[1])))
            return
        if (
            len(parts) == 3
            and parts[0] == "issues"
            and parts[1].isdigit()
            and parts[2] == "comments"
        ):
            self._send_list(state.comments(int(parts[1])))
            return
        if (
            len(parts) == 3
            and parts[0] == "issues"
            and parts[1].isdigit()
            and parts[2] == "assets"
        ):
            self._send_list(state.assets(int(parts[1])))
            return
        if path == f"{root}/pulls/87":
            self._send_json(state.pull())
            return
        if path == f"{root}/pulls/87/commits":
            if state.unavailable_pull_evidence:
                self.send_error(404)
                return
            state.pull_commit_cycles += 1
            commit_sha = (
                "e" * 40
                if state.mutate_pull_subresources and state.pull_commit_cycles >= 2
                else "d" * 40
            )
            self._send_list([{"sha": commit_sha}])
            return
        if path == f"{root}/pulls/87/files":
            if state.unavailable_pull_evidence:
                self.send_error(404)
                return
            self._send_list([{"filename": "README.md", "status": "modified"}])
            return
        if path == f"{root}/pulls/87/reviews":
            if state.unavailable_pull_evidence:
                self.send_error(404)
                return
            self._send_list([{"id": 501, "state": "APPROVED"}])
            return
        if path == f"{root}/pulls/87/reviews/501/comments":
            self._send_list([{"id": 601, "body": "review note"}])
            return
        if path == f"{root}/commits/{'c' * 40}/status":
            if state.unavailable_pull_evidence:
                self.send_error(404)
                return
            self._send_json({"state": "success", "sha": "c" * 40})
            return
        if path in {f"{root}/pulls/87.diff", f"{root}/pulls/87.patch"}:
            if state.unavailable_pull_evidence:
                self.send_error(404)
                return
            payload = b"diff --git a/README.md b/README.md\n"
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        self.send_error(404)


class FakeGiteaServer(ThreadingHTTPServer):
    def __init__(self, state: FakeGiteaState) -> None:
        super().__init__(("127.0.0.1", 0), _FakeGiteaHandler)
        self.state = state


@contextlib.contextmanager
def fake_gitea(state: FakeGiteaState | None = None):
    state = state or FakeGiteaState()
    server = FakeGiteaServer(state)
    state.origin = f"http://127.0.0.1:{server.server_port}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield state, state.origin
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.fixture(scope="session")
def git_repository(tmp_path_factory: pytest.TempPathFactory) -> Path:
    repository = tmp_path_factory.mktemp("migration-git")
    subprocess.run(["git", "init", "-q", "-b", "main", repository], check=True)
    subprocess.run(["git", "-C", repository, "config", "user.name", "Test"], check=True)
    subprocess.run(
        ["git", "-C", repository, "config", "user.email", "test@example.invalid"],
        check=True,
    )
    (repository / "common.txt").write_text("common\n")
    subprocess.run(["git", "-C", repository, "add", "common.txt"], check=True)
    subprocess.run(["git", "-C", repository, "commit", "-q", "-m", "common"], check=True)
    subprocess.run(["git", "-C", repository, "branch", "task-070"], check=True)
    (repository / "main.txt").write_text("main\n")
    subprocess.run(["git", "-C", repository, "add", "main.txt"], check=True)
    subprocess.run(["git", "-C", repository, "commit", "-q", "-m", "main"], check=True)
    subprocess.run(["git", "-C", repository, "switch", "-q", "task-070"], check=True)
    (repository / "archive.txt").write_text("archive\n")
    subprocess.run(["git", "-C", repository, "add", "archive.txt"], check=True)
    subprocess.run(["git", "-C", repository, "commit", "-q", "-m", "archive"], check=True)
    subprocess.run(["git", "-C", repository, "switch", "-q", "main"], check=True)
    return repository


def _reconciliation(path: Path, state: FakeGiteaState) -> Path:
    counts = {
        "issues": 85,
        "pull_requests": 1,
        "comments": len(state.global_comments()),
        "labels": len(state.labels),
        "assets": 2,
    }
    path.write_text(
        json.dumps(
            {
                key: {"count": value, "explanation": "Offline fixture differs from baseline."}
                for key, value in counts.items()
            }
        )
    )
    return path


def _export(
    temporary: Path,
    git_repository: Path,
    state: FakeGiteaState,
    origin: str,
) -> Path:
    return export_gitea.export_snapshot(
        base_url=origin,
        repository=REPOSITORY,
        destination_root=temporary / "exports" / "github-migration",
        git_repository=git_repository,
        main_ref="refs/heads/main",
        archive_ref="refs/heads/task-070",
        reconciliation_path=_reconciliation(temporary / "reconciliation.json", state),
        token=TOKEN,
        now=FIXED_TIME,
    )


@pytest.fixture(scope="session")
def exported_snapshot(
    tmp_path_factory: pytest.TempPathFactory,
    git_repository: Path,
) -> Path:
    temporary = tmp_path_factory.mktemp("migration-export")
    with fake_gitea() as (state, origin):
        snapshot = _export(temporary, git_repository, state, origin)
    return snapshot


def _copy_snapshot(source: Path, destination: Path) -> Path:
    destination.mkdir()
    snapshot = destination / source.name
    shutil.copytree(source, snapshot, copy_function=shutil.copy2)
    return snapshot


def _reseal(snapshot: Path, relative: str) -> None:
    manifest_path = snapshot / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    target = snapshot / relative
    for entry in manifest["file_inventory"]:
        if entry["path"] == relative:
            entry["size"] = target.stat().st_size
            entry["sha256"] = hashlib.sha256(target.read_bytes()).hexdigest()
            break
    else:
        raise AssertionError(f"inventory entry not found: {relative}")
    manifest_path.write_bytes(export_gitea._canonical_json(manifest))
    (snapshot / "manifest.sha256").write_text(
        f"{hashlib.sha256(manifest_path.read_bytes()).hexdigest()}  manifest.json\n"
    )
    os.chmod(manifest_path, 0o600)
    os.chmod(snapshot / "manifest.sha256", 0o600)


def _write_manifest(snapshot: Path, manifest: dict[str, object]) -> None:
    manifest_path = snapshot / "manifest.json"
    manifest_path.write_bytes(export_gitea._canonical_json(manifest))
    (snapshot / "manifest.sha256").write_text(
        f"{hashlib.sha256(manifest_path.read_bytes()).hexdigest()}  manifest.json\n"
    )
    os.chmod(manifest_path, 0o600)
    os.chmod(snapshot / "manifest.sha256", 0o600)


def _reseal_inventory(snapshot: Path) -> None:
    manifest = json.loads((snapshot / "manifest.json").read_text())
    manifest["file_inventory"] = export_gitea._inventory(snapshot)
    _write_manifest(snapshot, manifest)


def test_export_multipage_number_plan_pr_assets_and_bundle(exported_snapshot: Path) -> None:
    manifest = export_gitea.validate_snapshot(exported_snapshot, TOKEN)
    assert manifest["api_scope"]["page_counts"]["initial.labels"] == {
        "pages": 2,
        "items": 51,
        "x_total_count": 51,
    }
    assert manifest["api_scope"]["page_counts"]["initial.issues"]["pages"] == 2
    plan = json.loads((exported_snapshot / "number-plan.json").read_text())
    assert [entry["number"] for entry in plan] == list(range(1, 88))
    assert plan[85]["number"] == 86 and plan[85]["type"] == "tombstone"
    assert plan[86]["number"] == 87 and plan[86]["type"] == "legacy-pr"
    assert "legacy-pr" in plan[86]["labels"]
    assert {mapping["uuid"] for mapping in manifest["asset_rewrite_mapping"]} == {
        "asset-issue-1",
        "asset-comment-2",
    }
    assert (exported_snapshot / "items" / "87" / "pull.diff").is_file()
    assert (exported_snapshot / "items" / "87" / "review-comments.json").is_file()
    assert TOKEN not in b"".join(
        path.read_bytes() for path in exported_snapshot.rglob("*") if path.is_file()
    )


def test_export_records_and_validates_unavailable_pr_evidence(
    tmp_path: Path,
    git_repository: Path,
) -> None:
    state = FakeGiteaState()
    state.unavailable_pull_evidence = True
    with fake_gitea(state) as (state, origin):
        snapshot = _export(tmp_path, git_repository, state, origin)
    manifest = export_gitea.validate_snapshot(snapshot, TOKEN)
    item_dir = snapshot / "items" / "87"
    assert json.loads((item_dir / "status.json").read_text()) == export_gitea.UNAVAILABLE_MARKER
    assert json.loads((item_dir / "diff.unavailable.json").read_text()) == (
        export_gitea.UNAVAILABLE_MARKER
    )
    assert json.loads((item_dir / "patch.unavailable.json").read_text()) == (
        export_gitea.UNAVAILABLE_MARKER
    )
    assert manifest["api_scope"]["page_counts"]["initial.pull.87.commits"]["pages"] == 0
    assert manifest["api_scope"]["endpoint_evidence"]["initial.pull.87.diff"] == {
        "path": f"repos/{REPOSITORY}/pulls/87.diff",
        "kind": "bytes",
        "available": False,
        "reason": "endpoint-unavailable",
    }


def test_pagination_count_mismatch_fails_closed(
    tmp_path: Path,
    git_repository: Path,
) -> None:
    state = FakeGiteaState()
    state.total_overrides["issues"] = 86
    with fake_gitea(state) as (state, origin):
        with pytest.raises(export_gitea.ExportError, match="X-Total-Count"):
            _export(tmp_path, git_repository, state, origin)


def test_duplicate_ids_fail_closed(tmp_path: Path, git_repository: Path) -> None:
    state = FakeGiteaState()
    state.duplicate_issue_id = True
    with fake_gitea(state) as (state, origin):
        with pytest.raises(export_gitea.ExportError, match="duplicate issue id"):
            _export(tmp_path, git_repository, state, origin)


def test_same_origin_guard_and_redirect_rejection() -> None:
    with fake_gitea() as (_state, origin):
        client = export_gitea.GiteaClient(origin, TOKEN)
        with pytest.raises(export_gitea.ExportError, match="cross-origin"):
            client.request_bytes("http://example.invalid/asset")
        with pytest.raises(export_gitea.ExportError, match="redirect"):
            client.request_bytes(f"{origin}/redirect")


@pytest.mark.parametrize("status", [401, 403])
def test_authentication_errors_are_safe(status: int) -> None:
    state = FakeGiteaState()
    state.auth_status = status
    with fake_gitea(state) as (_state, origin):
        client = export_gitea.GiteaClient(origin, TOKEN)
        with pytest.raises(export_gitea.ExportError) as caught:
            export_gitea._capture_indexes(client, REPOSITORY, prefix="test")
    assert str(status) in str(caught.value)
    assert TOKEN.decode() not in str(caught.value)


def test_mid_export_mutation_fails_closed(tmp_path: Path, git_repository: Path) -> None:
    state = FakeGiteaState()
    state.mutate_confirmation = True
    with fake_gitea(state) as (state, origin):
        with pytest.raises(export_gitea.ExportError, match="changed during export"):
            _export(tmp_path, git_repository, state, origin)


def test_mid_export_pull_subresource_mutation_fails_closed(
    tmp_path: Path,
    git_repository: Path,
) -> None:
    state = FakeGiteaState()
    state.mutate_pull_subresources = True
    with fake_gitea(state) as (state, origin):
        with pytest.raises(export_gitea.ExportError, match="item data changed"):
            _export(tmp_path, git_repository, state, origin)


def test_asset_redirect_fails_closed(tmp_path: Path, git_repository: Path) -> None:
    state = FakeGiteaState()
    state.redirect_asset = True
    with fake_gitea(state) as (state, origin):
        with pytest.raises(export_gitea.ExportError, match="redirect"):
            _export(tmp_path, git_repository, state, origin)


def test_asset_tampering_is_detected(exported_snapshot: Path, tmp_path: Path) -> None:
    snapshot = _copy_snapshot(exported_snapshot, tmp_path / "asset-tamper")
    asset = snapshot / "assets" / "asset-issue-1" / "issue.png"
    asset.write_bytes(b"tampered")
    os.chmod(asset, 0o600)
    with pytest.raises(export_gitea.ExportError, match="size/hash"):
        export_gitea.validate_snapshot(snapshot, TOKEN)


def test_resealed_asset_misbinding_is_detected(
    exported_snapshot: Path,
    tmp_path: Path,
) -> None:
    snapshot = _copy_snapshot(exported_snapshot, tmp_path / "asset-misbinding")
    manifest = json.loads((snapshot / "manifest.json").read_text())
    first, second = manifest["asset_rewrite_mapping"]
    for field in ("id", "name", "source_url", "path", "size", "sha256"):
        first[field], second[field] = second[field], first[field]
    _write_manifest(snapshot, manifest)
    with pytest.raises(export_gitea.ExportError, match="asset mapping"):
        export_gitea.validate_snapshot(snapshot, TOKEN)


def test_resealed_malformed_asset_endpoint_object_is_detected(
    exported_snapshot: Path,
    tmp_path: Path,
) -> None:
    snapshot = _copy_snapshot(exported_snapshot, tmp_path / "malformed-asset-object")
    relative = "items/1/assets.json"
    path = snapshot / relative
    assets = json.loads(path.read_text())
    del assets[0]["browser_download_url"]
    path.write_bytes(export_gitea._canonical_json(assets))
    os.chmod(path, 0o600)
    _reseal(snapshot, relative)
    with pytest.raises(export_gitea.ExportError, match="asset download URL"):
        export_gitea.validate_snapshot(snapshot, TOKEN)


def test_manifest_hash_tampering_is_detected(exported_snapshot: Path, tmp_path: Path) -> None:
    snapshot = _copy_snapshot(exported_snapshot, tmp_path / "manifest-tamper")
    manifest = json.loads((snapshot / "manifest.json").read_text())
    manifest["main_sha"] = "0" * 40
    (snapshot / "manifest.json").write_text(json.dumps(manifest))
    os.chmod(snapshot / "manifest.json", 0o600)
    with pytest.raises(export_gitea.ExportError, match="manifest checksum"):
        export_gitea.validate_snapshot(snapshot, TOKEN)


def test_resealed_false_main_sha_is_detected(
    exported_snapshot: Path,
    tmp_path: Path,
) -> None:
    snapshot = _copy_snapshot(exported_snapshot, tmp_path / "false-main")
    manifest = json.loads((snapshot / "manifest.json").read_text())
    manifest["refs"]["main"]["sha"] = "0" * 40
    _write_manifest(snapshot, manifest)
    with pytest.raises(export_gitea.ExportError, match="main SHA does not match"):
        export_gitea.validate_snapshot(snapshot, TOKEN)


@pytest.mark.parametrize("false_sha", ["A" * 40, "a" * 39])
def test_resealed_invalid_git_sha_syntax_is_detected(
    false_sha: str,
    exported_snapshot: Path,
    tmp_path: Path,
) -> None:
    snapshot = _copy_snapshot(exported_snapshot, tmp_path / f"invalid-sha-{len(false_sha)}")
    manifest = json.loads((snapshot / "manifest.json").read_text())
    manifest["refs"]["archive"]["sha"] = false_sha
    _write_manifest(snapshot, manifest)
    with pytest.raises(export_gitea.ExportError, match="full lowercase Git SHA"):
        export_gitea.validate_snapshot(snapshot, TOKEN)


def test_unsafe_permissions_are_detected(exported_snapshot: Path, tmp_path: Path) -> None:
    snapshot = _copy_snapshot(exported_snapshot, tmp_path / "permissions")
    os.chmod(snapshot / "api" / "issues.json", 0o644)
    with pytest.raises(export_gitea.ExportError, match="unsafe snapshot permissions"):
        export_gitea.validate_snapshot(snapshot, TOKEN)


@pytest.mark.parametrize("mutation", ["extra", "missing", "symlink"])
def test_extra_missing_and_symlink_files_are_rejected(
    mutation: str,
    exported_snapshot: Path,
    tmp_path: Path,
) -> None:
    snapshot = _copy_snapshot(exported_snapshot, tmp_path / mutation)
    if mutation == "extra":
        (snapshot / "extra.txt").write_text("unexpected")
        os.chmod(snapshot / "extra.txt", 0o600)
    elif mutation == "missing":
        (snapshot / "api" / "labels.json").unlink()
    else:
        (snapshot / "link").symlink_to("api/issues.json")
    with pytest.raises(export_gitea.ExportError):
        export_gitea.validate_snapshot(snapshot, TOKEN)


@pytest.mark.parametrize("kind", ["diff", "patch"])
@pytest.mark.parametrize("mutation", ["absent", "duplicate", "malformed-marker"])
def test_resealed_pr_diff_patch_representation_tampering_is_rejected(
    kind: str,
    mutation: str,
    exported_snapshot: Path,
    tmp_path: Path,
) -> None:
    snapshot = _copy_snapshot(
        exported_snapshot, tmp_path / f"{kind}-representation-{mutation}"
    )
    item_dir = snapshot / "items" / "87"
    payload = item_dir / f"pull.{kind}"
    marker = item_dir / f"{kind}.unavailable.json"
    if mutation == "absent":
        payload.unlink()
    elif mutation == "duplicate":
        marker.write_bytes(export_gitea._canonical_json(export_gitea.UNAVAILABLE_MARKER))
        os.chmod(marker, 0o600)
    else:
        payload.unlink()
        marker.write_bytes(export_gitea._canonical_json({"available": False}))
        os.chmod(marker, 0o600)
    _reseal_inventory(snapshot)
    with pytest.raises(export_gitea.ExportError, match="representation|marker"):
        export_gitea.validate_snapshot(snapshot, TOKEN)


@pytest.mark.parametrize(
    "relative",
    [
        "items/87/pull.json",
        "items/87/pull-metadata.json",
        "items/87/commits.json",
        "items/87/files.json",
        "items/87/reviews.json",
        "items/87/review-comments.json",
        "items/87/status.json",
    ],
)
def test_resealed_required_pr_evidence_deletion_is_rejected(
    relative: str,
    exported_snapshot: Path,
    tmp_path: Path,
) -> None:
    snapshot = _copy_snapshot(
        exported_snapshot, tmp_path / f"deleted-{Path(relative).name}"
    )
    (snapshot / relative).unlink()
    _reseal_inventory(snapshot)
    with pytest.raises(export_gitea.ExportError):
        export_gitea.validate_snapshot(snapshot, TOKEN)


@pytest.mark.parametrize("resource", ["commits", "files", "reviews", "review-comments"])
def test_resealed_duplicate_pr_resource_identities_are_rejected(
    resource: str,
    exported_snapshot: Path,
    tmp_path: Path,
) -> None:
    snapshot = _copy_snapshot(exported_snapshot, tmp_path / f"duplicate-{resource}")
    relative = f"items/87/{resource}.json"
    path = snapshot / relative
    payload = json.loads(path.read_text())
    if resource == "review-comments":
        payload["501"].append(dict(payload["501"][0]))
    else:
        payload.append(dict(payload[0]))
    path.write_bytes(export_gitea._canonical_json(payload))
    os.chmod(path, 0o600)
    _reseal(snapshot, relative)
    with pytest.raises(export_gitea.ExportError, match="duplicate"):
        export_gitea.validate_snapshot(snapshot, TOKEN)


def test_resealed_pr_status_semantic_tampering_is_rejected(
    exported_snapshot: Path,
    tmp_path: Path,
) -> None:
    snapshot = _copy_snapshot(exported_snapshot, tmp_path / "status-semantic-tamper")
    relative = "items/87/status.json"
    path = snapshot / relative
    status = json.loads(path.read_text())
    status["sha"] = "f" * 40
    path.write_bytes(export_gitea._canonical_json(status))
    os.chmod(path, 0o600)
    _reseal(snapshot, relative)
    with pytest.raises(export_gitea.ExportError, match="status payload"):
        export_gitea.validate_snapshot(snapshot, TOKEN)


def test_resealed_pr_endpoint_count_evidence_tampering_is_rejected(
    exported_snapshot: Path,
    tmp_path: Path,
) -> None:
    snapshot = _copy_snapshot(exported_snapshot, tmp_path / "endpoint-evidence-tamper")
    manifest = json.loads((snapshot / "manifest.json").read_text())
    del manifest["api_scope"]["page_counts"]["confirmation.pull.87.files"]
    _write_manifest(snapshot, manifest)
    with pytest.raises(export_gitea.ExportError, match="page count|key set"):
        export_gitea.validate_snapshot(snapshot, TOKEN)


@pytest.mark.parametrize(
    ("field", "value"),
    [("state", "open"), ("reason", ""), ("reason", "Different reservation")],
)
def test_resealed_modified_tombstone_is_rejected(
    field: str,
    value: str,
    exported_snapshot: Path,
    tmp_path: Path,
) -> None:
    snapshot = _copy_snapshot(exported_snapshot, tmp_path / f"tombstone-{field}-{len(value)}")
    plan_path = snapshot / "number-plan.json"
    plan = json.loads(plan_path.read_text())
    plan[85][field] = value
    plan_path.write_bytes(export_gitea._canonical_json(plan))
    os.chmod(plan_path, 0o600)
    _reseal(snapshot, "number-plan.json")
    with pytest.raises(export_gitea.ExportError, match="tombstone"):
        export_gitea.validate_snapshot(snapshot, TOKEN)


def test_extra_empty_directory_is_rejected(
    exported_snapshot: Path,
    tmp_path: Path,
) -> None:
    snapshot = _copy_snapshot(exported_snapshot, tmp_path / "empty-directory")
    extra = snapshot / "unmanifested-empty-directory"
    extra.mkdir(mode=0o700)
    with pytest.raises(export_gitea.ExportError, match="directory set mismatch"):
        export_gitea.validate_snapshot(snapshot, TOKEN)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="mkfifo is unavailable")
def test_mode_0600_fifo_is_rejected(
    exported_snapshot: Path,
    tmp_path: Path,
) -> None:
    snapshot = _copy_snapshot(exported_snapshot, tmp_path / "fifo")
    fifo = snapshot / "unexpected.fifo"
    os.mkfifo(fifo, mode=0o600)
    os.chmod(fifo, 0o600)
    with pytest.raises(export_gitea.ExportError, match="special filesystem object"):
        export_gitea.validate_snapshot(snapshot, TOKEN)


def test_preexisting_final_destination_is_never_overwritten(
    tmp_path: Path,
    git_repository: Path,
) -> None:
    main_sha = subprocess.run(
        ["git", "-C", git_repository, "rev-parse", "refs/heads/main"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    final = (
        tmp_path
        / "exports"
        / "github-migration"
        / f"20260802T123456Z-{main_sha[:12]}"
    )
    final.mkdir(parents=True)
    os.chmod(final.parent, 0o700)
    marker = final / "marker"
    marker.write_text("preserve")
    with fake_gitea() as (state, origin):
        with pytest.raises(export_gitea.ExportError, match="already exists"):
            _export(tmp_path, git_repository, state, origin)
    assert marker.read_text() == "preserve"


def test_exact_token_absence_check_cannot_be_bypassed_by_rehashing(
    exported_snapshot: Path,
    tmp_path: Path,
) -> None:
    snapshot = _copy_snapshot(exported_snapshot, tmp_path / "token")
    diff = snapshot / "items" / "87" / "pull.diff"
    diff.write_bytes(diff.read_bytes() + TOKEN + b"\n")
    os.chmod(diff, 0o600)
    _reseal(snapshot, "items/87/pull.diff")
    with pytest.raises(export_gitea.ExportError, match="exact token") as caught:
        export_gitea.validate_snapshot(snapshot, TOKEN)
    assert TOKEN.decode() not in str(caught.value)


def test_reconciliation_delta_requires_explanation(tmp_path: Path) -> None:
    payload = {
        key: {"count": value, "explanation": ""}
        for key, value in {
            "issues": 85,
            "pull_requests": 1,
            "comments": 2,
            "labels": 51,
            "assets": 2,
        }.items()
    }
    path = tmp_path / "reconciliation.json"
    path.write_text(json.dumps(payload))
    with pytest.raises(export_gitea.ExportError, match="requires an explanation"):
        export_gitea._load_reconciliation(
            path,
            {key: entry["count"] for key, entry in payload.items()},
        )
