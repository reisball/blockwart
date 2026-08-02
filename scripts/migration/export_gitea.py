#!/usr/bin/env python3
"""Create and validate a protected, offline Gitea migration snapshot.

The only secret input is a Gitea token read from stdin. The exporter deliberately
uses only the Python standard library so it can be audited and run before the
application dependency environment is installed.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

FORMAT_VERSION = 1
PER_PAGE = 50
TOMBSTONE_NUMBER = 86
BASELINE_COUNTS = {
    "issues": 72,
    "pull_requests": 37,
    "comments": 292,
    "labels": 47,
    "assets": 7,
}
MAIN_BUNDLE_REF = "refs/heads/main"
ARCHIVE_BUNDLE_REF = "refs/heads/archive/gitea-task-070-drilldown-fix"
DEFAULT_MAIN_REF = "origin/main"
DEFAULT_ARCHIVE_REF = "origin/task-070-drilldown-fix"
COUNT_KEYS = tuple(BASELINE_COUNTS)


class ExportError(RuntimeError):
    """A safe-to-display, fail-closed export or validation error."""


class NotFoundError(ExportError):
    """An optional Gitea endpoint is unavailable."""


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        del req, fp, code, msg, headers, newurl
        return None


def _origin(url: str) -> tuple[str, str, int]:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ExportError("source URL must use http or https and include a host")
    if parsed.username is not None or parsed.password is not None:
        raise ExportError("source URL must not contain credentials")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return parsed.scheme.lower(), parsed.hostname.lower(), port


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    ).encode() + b"\n"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_bytes(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    os.chmod(path, 0o600)


def _write_json(path: Path, value: Any) -> None:
    _write_bytes(path, _canonical_json(value))


def _json_from_path(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ExportError(f"invalid JSON file: {path.name}") from exc


def _run_git(repository: Path, *arguments: str) -> str:
    try:
        completed = subprocess.run(
            ["git", "-C", str(repository), *arguments],
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:
        raise ExportError("git is required for migration bundle validation") from exc
    except subprocess.CalledProcessError as exc:
        command = " ".join(arguments[:2])
        raise ExportError(f"git command failed: {command}") from exc
    return completed.stdout.strip()


def _resolve_refs(
    repository: Path,
    main_ref: str,
    archive_ref: str,
) -> dict[str, str]:
    main_sha = _run_git(
        repository,
        "rev-parse",
        "--verify",
        "--end-of-options",
        f"{main_ref}^{{commit}}",
    )
    archive_sha = _run_git(
        repository,
        "rev-parse",
        "--verify",
        "--end-of-options",
        f"{archive_ref}^{{commit}}",
    )
    merge_base = _run_git(repository, "merge-base", main_sha, archive_sha)
    for label, value in {
        "main": main_sha,
        "archive": archive_sha,
        "merge base": merge_base,
    }.items():
        if not re.fullmatch(r"[0-9a-f]{40}", value):
            raise ExportError(f"resolved {label} is not a full Git SHA-1")
    return {"main": main_sha, "archive": archive_sha, "merge_base": merge_base}


class GiteaClient:
    def __init__(self, base_url: str, token: bytes) -> None:
        parsed = urllib.parse.urlsplit(base_url)
        if parsed.query or parsed.fragment:
            raise ExportError("source base URL must not contain a query or fragment")
        if parsed.path not in {"", "/"}:
            raise ExportError("source base URL must be the Gitea origin root")
        self.base_url = base_url.rstrip("/")
        self.api_url = f"{self.base_url}/api/v1"
        self.origin = _origin(self.base_url)
        try:
            token_text = token.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ExportError("stdin token must be valid UTF-8") from exc
        if not token_text or "\n" in token_text or "\r" in token_text:
            raise ExportError("stdin must contain one non-empty token line")
        self._authorization = f"token {token_text}"
        self._opener = urllib.request.build_opener(_RejectRedirects())
        self.page_counts: dict[str, dict[str, int | None]] = {}
        self.unavailable_endpoints: list[str] = []

    def _url(self, path_or_url: str) -> str:
        if urllib.parse.urlsplit(path_or_url).scheme:
            url = path_or_url
        else:
            url = f"{self.api_url}/{path_or_url.lstrip('/')}"
        if _origin(url) != self.origin:
            raise ExportError("refusing a cross-origin Gitea request")
        return url

    def request_bytes(
        self,
        path_or_url: str,
        *,
        accept: str = "application/json",
        optional: bool = False,
    ) -> tuple[bytes, Mapping[str, str]] | None:
        url = self._url(path_or_url)
        request = urllib.request.Request(
            url,
            headers={"Accept": accept, "Authorization": self._authorization},
            method="GET",
        )
        try:
            with self._opener.open(request, timeout=30) as response:
                final_url = response.geturl()
                if final_url != url:
                    raise ExportError("unexpected redirect from Gitea")
                if _origin(final_url) != self.origin:
                    raise ExportError("refusing a cross-origin Gitea response")
                return response.read(), response.headers
        except urllib.error.HTTPError as exc:
            if 300 <= exc.code < 400:
                raise ExportError("unexpected redirect from Gitea") from None
            if exc.code in {401, 403}:
                raise ExportError(
                    f"Gitea authentication or authorization failed (HTTP {exc.code})"
                ) from None
            if exc.code == 404 and optional:
                return None
            raise ExportError(f"Gitea request failed (HTTP {exc.code})") from None
        except urllib.error.URLError as exc:
            raise ExportError("Gitea request failed before a complete response") from exc

    def get_json(self, path: str, *, optional: bool = False) -> Any:
        response = self.request_bytes(path, optional=optional)
        if response is None:
            raise NotFoundError("optional Gitea endpoint is unavailable")
        payload, _headers = response
        try:
            return json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ExportError("Gitea returned invalid JSON") from exc

    def paginate(
        self,
        path: str,
        *,
        params: Mapping[str, str] | None,
        key: str,
        require_total: bool,
        optional: bool = False,
    ) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        expected_total: int | None = None
        page = 1
        pages_read = 0
        while True:
            query = dict(params or {})
            query.update({"page": str(page), "limit": str(PER_PAGE)})
            request_path = f"{path}?{urllib.parse.urlencode(query)}"
            response = self.request_bytes(request_path, optional=optional and page == 1)
            if response is None:
                self.unavailable_endpoints.append(path)
                self.page_counts[key] = {"pages": 0, "items": 0, "x_total_count": None}
                return []
            raw, headers = response
            try:
                payload = json.loads(raw)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ExportError("Gitea returned invalid paginated JSON") from exc
            if not isinstance(payload, list) or not all(isinstance(item, dict) for item in payload):
                raise ExportError("Gitea paginated endpoint did not return an object list")
            header_value = headers.get("X-Total-Count")
            if header_value is not None:
                try:
                    page_total = int(header_value)
                except ValueError as exc:
                    raise ExportError("Gitea returned an invalid X-Total-Count") from exc
                if page_total < 0:
                    raise ExportError("Gitea returned a negative X-Total-Count")
                if expected_total is None:
                    expected_total = page_total
                elif page_total != expected_total:
                    raise ExportError("X-Total-Count changed during pagination")
            elif require_total:
                raise ExportError("Gitea response omitted required X-Total-Count")
            items.extend(payload)
            pages_read += 1
            if expected_total is not None:
                if len(items) > expected_total:
                    raise ExportError("paginated result exceeded X-Total-Count")
                if len(items) == expected_total:
                    break
                if not payload:
                    raise ExportError("paginated result ended before X-Total-Count")
            elif len(payload) < PER_PAGE:
                break
            page += 1
            if page > 100_000:
                raise ExportError("pagination safety limit exceeded")
        if require_total and expected_total != len(items):
            raise ExportError("paginated result does not match X-Total-Count")
        self.page_counts[key] = {
            "pages": pages_read,
            "items": len(items),
            "x_total_count": expected_total,
        }
        return items


def _as_int(value: Any, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ExportError(f"{label} must be an integer")
    return value


def _unique(items: Sequence[Mapping[str, Any]], field: str, label: str) -> set[int]:
    values: set[int] = set()
    for item in items:
        value = _as_int(item.get(field), label=f"{label} {field}")
        if value in values:
            raise ExportError(f"duplicate {label} {field}: {value}")
        values.add(value)
    return values


def _sort_index(items: list[dict[str, Any]], field: str) -> list[dict[str, Any]]:
    return sorted(items, key=lambda item: _as_int(item.get(field), label=field))


def _capture_indexes(
    client: GiteaClient,
    repository: str,
    *,
    prefix: str,
) -> dict[str, list[dict[str, Any]]]:
    root = f"repos/{repository}"
    labels = client.paginate(
        f"{root}/labels",
        params=None,
        key=f"{prefix}.labels",
        require_total=True,
    )
    issues = client.paginate(
        f"{root}/issues",
        params={"state": "all", "type": "issues"},
        key=f"{prefix}.issues",
        require_total=True,
    )
    pulls = client.paginate(
        f"{root}/pulls",
        params={"state": "all"},
        key=f"{prefix}.pull_requests",
        require_total=True,
    )
    comments = client.paginate(
        f"{root}/issues/comments",
        params=None,
        key=f"{prefix}.comments",
        require_total=True,
    )
    _unique(labels, "id", "label")
    _unique(issues, "id", "issue")
    _unique(pulls, "id", "pull request")
    _unique(comments, "id", "comment")
    issue_numbers = _unique(issues, "number", "issue")
    pull_numbers = _unique(pulls, "number", "pull request")
    overlap = issue_numbers & pull_numbers
    if overlap:
        raise ExportError(f"issue and pull request numbers overlap: {min(overlap)}")
    return {
        "labels": _sort_index(labels, "id"),
        "issues": _sort_index(issues, "number"),
        "pull_requests": _sort_index(pulls, "number"),
        "comments": _sort_index(comments, "id"),
    }


def _safe_component(value: str, *, label: str) -> str:
    if not value or value in {".", ".."}:
        raise ExportError(f"invalid {label}")
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value)
    if cleaned in {"", ".", ".."}:
        raise ExportError(f"invalid {label}")
    return cleaned[:180]


def _asset_candidates(value: Any) -> Iterable[dict[str, Any]]:
    if isinstance(value, dict):
        if "uuid" in value and "browser_download_url" in value:
            yield value
        for nested in value.values():
            yield from _asset_candidates(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _asset_candidates(nested)


def _asset_uuid(asset: Mapping[str, Any]) -> str:
    value = asset.get("uuid")
    if not isinstance(value, str):
        raise ExportError("asset UUID must be a string")
    return _safe_component(value, label="asset UUID")


def _asset_url(asset: Mapping[str, Any]) -> str:
    value = asset.get("browser_download_url")
    if not isinstance(value, str) or not value:
        raise ExportError("asset download URL is missing")
    parsed = urllib.parse.urlsplit(value)
    if (
        parsed.query
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ExportError("asset download URL must not contain credentials, query, or fragment")
    return value


def _asset_name(asset: Mapping[str, Any]) -> str:
    value = asset.get("name")
    if not isinstance(value, str) or not value:
        value = "attachment"
    return _safe_component(Path(value).name, label="asset filename")


def _record_assets(
    client: GiteaClient,
    snapshot: Path,
    values: Iterable[Any],
    assets: dict[str, dict[str, Any]],
) -> list[str]:
    referenced: set[str] = set()
    for value in values:
        for asset in _asset_candidates(value):
            asset_uuid = _asset_uuid(asset)
            source_url = _asset_url(asset)
            filename = _asset_name(asset)
            relative_path = f"assets/{asset_uuid}/{filename}"
            existing = assets.get(asset_uuid)
            if existing is not None:
                if existing["source_url"] != source_url or existing["path"] != relative_path:
                    raise ExportError(f"conflicting duplicate asset UUID: {asset_uuid}")
            else:
                response = client.request_bytes(source_url, accept="application/octet-stream")
                if response is None:  # pragma: no cover - non-optional request
                    raise ExportError("asset download unexpectedly unavailable")
                payload, _headers = response
                _write_bytes(snapshot / relative_path, payload)
                assets[asset_uuid] = {
                    "uuid": asset_uuid,
                    "source_url": source_url,
                    "path": relative_path,
                    "github_url": None,
                    "size": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                }
            referenced.add(asset_uuid)
    return sorted(referenced)


def _extract_labels(issue: Mapping[str, Any]) -> list[str]:
    labels = issue.get("labels", [])
    if not isinstance(labels, list):
        raise ExportError("issue labels must be a list")
    names: list[str] = []
    for label in labels:
        if not isinstance(label, dict) or not isinstance(label.get("name"), str):
            raise ExportError("issue label is invalid")
        names.append(label["name"])
    return sorted(set(names))


def _pull_metadata(pull: Mapping[str, Any]) -> dict[str, Any]:
    base = pull.get("base") if isinstance(pull.get("base"), dict) else {}
    head = pull.get("head") if isinstance(pull.get("head"), dict) else {}
    return {
        "state": pull.get("state"),
        "merged": pull.get("merged"),
        "merged_at": pull.get("merged_at"),
        "mergeable": pull.get("mergeable"),
        "merge_commit_sha": pull.get("merge_commit_sha"),
        "base_ref": base.get("ref"),
        "base_sha": base.get("sha"),
        "head_ref": head.get("ref"),
        "head_sha": head.get("sha"),
    }


def _optional_json(client: GiteaClient, path: str) -> Any | None:
    try:
        return client.get_json(path, optional=True)
    except NotFoundError:
        client.unavailable_endpoints.append(path)
        return None


def _optional_bytes(client: GiteaClient, path: str, *, accept: str) -> bytes | None:
    response = client.request_bytes(path, accept=accept, optional=True)
    if response is None:
        client.unavailable_endpoints.append(path)
        return None
    return response[0]


def _capture_items(
    client: GiteaClient,
    repository: str,
    indexes: Mapping[str, list[dict[str, Any]]],
    snapshot: Path,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    root = f"repos/{repository}"
    assets: dict[str, dict[str, Any]] = {}
    plan: list[dict[str, Any]] = []
    per_item_comment_ids: set[int] = set()

    combined: list[tuple[str, dict[str, Any]]] = [
        *(("issue", issue) for issue in indexes["issues"]),
        *(("pull_request", pull) for pull in indexes["pull_requests"]),
    ]
    combined.sort(key=lambda pair: _as_int(pair[1].get("number"), label="item number"))

    for item_type, index_item in combined:
        number = _as_int(index_item.get("number"), label="item number")
        item_dir = snapshot / "items" / str(number)
        issue_detail = client.get_json(f"{root}/issues/{number}")
        if not isinstance(issue_detail, dict):
            raise ExportError("issue detail is not an object")
        if _as_int(issue_detail.get("number"), label="issue detail number") != number:
            raise ExportError("issue detail number changed during export")
        comments = client.paginate(
            f"{root}/issues/{number}/comments",
            params=None,
            key=f"item.{number}.comments",
            require_total=False,
        )
        comment_ids = _unique(comments, "id", f"item {number} comment")
        overlap = per_item_comment_ids & comment_ids
        if overlap:
            raise ExportError(f"comment appears under multiple items: {min(overlap)}")
        per_item_comment_ids.update(comment_ids)
        item_assets = client.paginate(
            f"{root}/issues/{number}/assets",
            params=None,
            key=f"item.{number}.assets",
            require_total=False,
            optional=True,
        )
        _unique(item_assets, "id", f"item {number} asset") if item_assets else set()
        _write_json(item_dir / "issue.json", issue_detail)
        _write_json(item_dir / "comments.json", comments)
        _write_json(item_dir / "assets.json", item_assets)
        asset_ids = _record_assets(
            client,
            snapshot,
            (issue_detail, comments, item_assets),
            assets,
        )

        if item_type == "issue":
            plan.append(
                {
                    "number": number,
                    "type": "issue",
                    "state": issue_detail.get("state"),
                    "labels": _extract_labels(issue_detail),
                    "comment_ids": sorted(comment_ids),
                    "asset_uuids": asset_ids,
                }
            )
            continue

        pull_detail = client.get_json(f"{root}/pulls/{number}")
        if not isinstance(pull_detail, dict):
            raise ExportError("pull request detail is not an object")
        if _as_int(pull_detail.get("number"), label="pull detail number") != number:
            raise ExportError("pull request detail number changed during export")
        if pull_detail.get("state") != "closed":
            raise ExportError(f"pull request {number} is still open")
        commits = client.paginate(
            f"{root}/pulls/{number}/commits",
            params=None,
            key=f"pull.{number}.commits",
            require_total=False,
            optional=True,
        )
        files = client.paginate(
            f"{root}/pulls/{number}/files",
            params=None,
            key=f"pull.{number}.files",
            require_total=False,
            optional=True,
        )
        reviews = client.paginate(
            f"{root}/pulls/{number}/reviews",
            params=None,
            key=f"pull.{number}.reviews",
            require_total=False,
            optional=True,
        )
        if reviews:
            _unique(reviews, "id", f"pull {number} review")
        review_comments: dict[str, list[dict[str, Any]]] = {}
        for review in reviews:
            review_id = _as_int(review.get("id"), label="review id")
            review_comments[str(review_id)] = client.paginate(
                f"{root}/pulls/{number}/reviews/{review_id}/comments",
                params=None,
                key=f"pull.{number}.review.{review_id}.comments",
                require_total=False,
                optional=True,
            )
        metadata = _pull_metadata(pull_detail)
        head_sha = metadata.get("head_sha")
        status_payload = None
        if isinstance(head_sha, str) and head_sha:
            status_payload = _optional_json(client, f"{root}/commits/{head_sha}/status")
        diff = _optional_bytes(
            client,
            f"{root}/pulls/{number}.diff",
            accept="application/vnd.git-lfs+json, text/plain",
        )
        patch = _optional_bytes(
            client,
            f"{root}/pulls/{number}.patch",
            accept="application/vnd.git-lfs+json, text/plain",
        )
        _write_json(item_dir / "pull.json", pull_detail)
        _write_json(item_dir / "pull-metadata.json", metadata)
        _write_json(item_dir / "commits.json", commits)
        _write_json(item_dir / "files.json", files)
        _write_json(item_dir / "reviews.json", reviews)
        _write_json(item_dir / "review-comments.json", review_comments)
        _write_json(item_dir / "status.json", status_payload)
        if diff is None:
            _write_json(item_dir / "diff.unavailable.json", {"available": False})
        else:
            _write_bytes(item_dir / "pull.diff", diff)
        if patch is None:
            _write_json(item_dir / "patch.unavailable.json", {"available": False})
        else:
            _write_bytes(item_dir / "pull.patch", patch)
        pull_asset_ids = _record_assets(
            client,
            snapshot,
            (pull_detail, commits, files, reviews, review_comments, status_payload),
            assets,
        )
        plan.append(
            {
                "number": number,
                "type": "legacy-pr",
                "state": "closed",
                "labels": sorted(set([*_extract_labels(issue_detail), "legacy-pr"])),
                "comment_ids": sorted(comment_ids),
                "asset_uuids": sorted(set(asset_ids) | set(pull_asset_ids)),
                "pull": metadata,
            }
        )

    global_comment_ids = _unique(indexes["comments"], "id", "global comment")
    if per_item_comment_ids != global_comment_ids:
        missing = sorted(global_comment_ids - per_item_comment_ids)
        extra = sorted(per_item_comment_ids - global_comment_ids)
        detail = f"missing={missing[:3]} extra={extra[:3]}"
        raise ExportError(f"global/per-item comment reconciliation failed ({detail})")

    numbers = {entry["number"] for entry in plan}
    if TOMBSTONE_NUMBER in numbers:
        raise ExportError(f"reserved tombstone number {TOMBSTONE_NUMBER} already exists")
    if not numbers:
        raise ExportError("cannot create a number plan without issues or pull requests")
    expected_numbers = set(range(1, max(numbers | {TOMBSTONE_NUMBER}) + 1))
    if numbers | {TOMBSTONE_NUMBER} != expected_numbers:
        missing = sorted(expected_numbers - numbers - {TOMBSTONE_NUMBER})
        raise ExportError(f"number plan is not contiguous; missing {missing[:10]}")
    plan.append(
        {
            "number": TOMBSTONE_NUMBER,
            "type": "tombstone",
            "state": "closed",
            "labels": [],
            "comment_ids": [],
            "asset_uuids": [],
            "reason": "Deleted Gitea item; reserve the historical number.",
        }
    )
    plan.sort(key=lambda entry: entry["number"])
    return plan, sorted(assets.values(), key=lambda asset: asset["uuid"])


def _load_reconciliation(path: Path, current: Mapping[str, int]) -> dict[str, Any]:
    payload = _json_from_path(path)
    if not isinstance(payload, dict) or set(payload) != set(COUNT_KEYS):
        raise ExportError(f"reconciliation must contain exactly: {', '.join(COUNT_KEYS)}")
    result: dict[str, Any] = {}
    for key in COUNT_KEYS:
        entry = payload[key]
        if not isinstance(entry, dict):
            raise ExportError(f"reconciliation entry {key} must be an object")
        expected = _as_int(entry.get("count"), label=f"reconciliation {key} count")
        explanation = entry.get("explanation", "")
        if not isinstance(explanation, str):
            raise ExportError(f"reconciliation explanation for {key} must be text")
        if expected != current[key]:
            raise ExportError(f"reconciliation count for {key} does not match export")
        delta = current[key] - BASELINE_COUNTS[key]
        if delta and not explanation.strip():
            raise ExportError(f"reconciliation delta for {key} requires an explanation")
        result[key] = {
            "baseline": BASELINE_COUNTS[key],
            "current": current[key],
            "delta": delta,
            "explanation": explanation.strip() or "No change from discovery baseline.",
        }
    return result


def _create_bundle(
    source_repository: Path,
    snapshot: Path,
    refs: Mapping[str, str],
) -> Path:
    bundle_path = snapshot / "repository.bundle"
    with tempfile.TemporaryDirectory(prefix=".bundle-", dir=snapshot) as temporary:
        bare = Path(temporary)
        _run_git(bare, "init", "--bare")
        _run_git(
            bare,
            "fetch",
            "--quiet",
            "--no-tags",
            str(source_repository.resolve()),
            f"{refs['main']}:{MAIN_BUNDLE_REF}",
            f"{refs['archive']}:{ARCHIVE_BUNDLE_REF}",
        )
        _run_git(
            bare,
            "bundle",
            "create",
            str(bundle_path),
            MAIN_BUNDLE_REF,
            ARCHIVE_BUNDLE_REF,
        )
    os.chmod(bundle_path, 0o600)
    return bundle_path


def _inventory(snapshot: Path) -> list[dict[str, Any]]:
    inventory: list[dict[str, Any]] = []
    for path in sorted(snapshot.rglob("*")):
        if path.is_symlink():
            raise ExportError("snapshot contains a symlink")
        if path.is_file():
            relative = path.relative_to(snapshot).as_posix()
            if relative in {"manifest.json", "manifest.sha256"}:
                continue
            inventory.append(
                {"path": relative, "size": path.stat().st_size, "sha256": _sha256(path)}
            )
    return inventory


def _rename_noreplace(source: Path, destination: Path) -> None:
    at_fdcwd = -100
    rename_noreplace = 1
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = libc.renameat2
    except AttributeError:
        raise ExportError("atomic no-replace rename is unavailable") from None
    result = renameat2(
        at_fdcwd,
        os.fsencode(source),
        at_fdcwd,
        os.fsencode(destination),
        rename_noreplace,
    )
    if result == 0:
        return
    error = ctypes.get_errno()
    if error == errno.EEXIST:
        raise ExportError("final export destination already exists")
    if error in {errno.ENOSYS, errno.EINVAL}:
        raise ExportError("atomic no-replace rename is unavailable")
    raise ExportError("atomic final export rename failed")


def _check_permissions(snapshot: Path) -> None:
    for path in (snapshot, *snapshot.rglob("*")):
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise ExportError("snapshot contains a symlink")
        expected = 0o700 if stat.S_ISDIR(metadata.st_mode) else 0o600
        if stat.S_IMODE(metadata.st_mode) != expected:
            relative = "." if path == snapshot else path.relative_to(snapshot).as_posix()
            raise ExportError(f"unsafe snapshot permissions: {relative}")


def _validate_bundle(snapshot: Path, manifest: Mapping[str, Any]) -> None:
    bundle = snapshot / "repository.bundle"
    refs = manifest.get("refs")
    if not isinstance(refs, dict):
        raise ExportError("manifest refs are invalid")
    main = refs.get("main")
    archive = refs.get("archive")
    if not isinstance(main, dict) or not isinstance(archive, dict):
        raise ExportError("manifest bundle refs are invalid")
    expected = {
        MAIN_BUNDLE_REF: main.get("sha"),
        ARCHIVE_BUNDLE_REF: archive.get("sha"),
    }
    listed: dict[str, str] = {}
    output = _run_git(snapshot, "bundle", "list-heads", str(bundle))
    for line in output.splitlines():
        try:
            sha, name = line.split(" ", 1)
        except ValueError as exc:
            raise ExportError("git bundle advertised an invalid ref") from exc
        listed[name] = sha
    if listed != expected:
        raise ExportError("git bundle refs do not match the manifest")
    with tempfile.TemporaryDirectory(prefix="blockwart-bundle-validation-") as temporary:
        bare = Path(temporary)
        _run_git(bare, "init", "--bare")
        _run_git(bare, "bundle", "verify", str(bundle))
        _run_git(
            bare,
            "fetch",
            "--quiet",
            str(bundle),
            f"{MAIN_BUNDLE_REF}:{MAIN_BUNDLE_REF}",
            f"{ARCHIVE_BUNDLE_REF}:{ARCHIVE_BUNDLE_REF}",
        )
        merge_base = _run_git(bare, "merge-base", MAIN_BUNDLE_REF, ARCHIVE_BUNDLE_REF)
        if merge_base != refs.get("merge_base"):
            raise ExportError("git bundle merge base does not match the manifest")


def _validate_data(snapshot: Path, manifest: Mapping[str, Any]) -> None:
    labels = _json_from_path(snapshot / "api" / "labels.json")
    issues = _json_from_path(snapshot / "api" / "issues.json")
    pulls = _json_from_path(snapshot / "api" / "pull-requests.json")
    comments = _json_from_path(snapshot / "api" / "comments.json")
    plan = _json_from_path(snapshot / "number-plan.json")
    if not all(isinstance(value, list) for value in (labels, issues, pulls, comments, plan)):
        raise ExportError("snapshot index or number plan is not a list")
    _unique(labels, "id", "label")
    _unique(issues, "id", "issue")
    _unique(pulls, "id", "pull request")
    global_comment_ids = _unique(comments, "id", "comment")
    issue_numbers = _unique(issues, "number", "issue")
    pull_numbers = _unique(pulls, "number", "pull request")
    if issue_numbers & pull_numbers:
        raise ExportError("snapshot issue and pull request numbers overlap")
    if TOMBSTONE_NUMBER in issue_numbers | pull_numbers:
        raise ExportError("snapshot overwrites the reserved tombstone")
    all_numbers = issue_numbers | pull_numbers | {TOMBSTONE_NUMBER}
    if all_numbers != set(range(1, max(all_numbers) + 1)):
        raise ExportError("snapshot number plan is not contiguous")
    plan_numbers = [_as_int(entry.get("number"), label="plan number") for entry in plan]
    if plan_numbers != list(range(1, max(all_numbers) + 1)):
        raise ExportError("number plan is not strictly ascending and contiguous")
    plan_by_number = {entry["number"]: entry for entry in plan}
    tombstone = plan_by_number.get(TOMBSTONE_NUMBER)
    if not isinstance(tombstone, dict) or tombstone.get("type") != "tombstone":
        raise ExportError("number plan tombstone is missing")

    per_item_comments: set[int] = set()
    referenced_assets: set[str] = set()
    issue_index = {item["number"]: item for item in issues}
    pull_index = {item["number"]: item for item in pulls}
    for number in sorted(issue_numbers | pull_numbers):
        item_dir = snapshot / "items" / str(number)
        detail = _json_from_path(item_dir / "issue.json")
        item_comments = _json_from_path(item_dir / "comments.json")
        item_assets = _json_from_path(item_dir / "assets.json")
        if not isinstance(detail, dict) or not isinstance(item_comments, list):
            raise ExportError(f"item {number} data is invalid")
        if not isinstance(item_assets, list):
            raise ExportError(f"item {number} asset index is invalid")
        if _as_int(detail.get("number"), label="item detail number") != number:
            raise ExportError(f"item {number} detail number does not match")
        if number in issue_index and detail.get("id") != issue_index[number].get("id"):
            raise ExportError(f"issue {number} detail ID does not match its index")
        comment_ids = _unique(item_comments, "id", f"item {number} comment")
        if per_item_comments & comment_ids:
            raise ExportError("a comment is stored under more than one item")
        per_item_comments.update(comment_ids)
        if item_assets:
            _unique(item_assets, "id", f"item {number} asset")
        asset_sources: list[Any] = [detail, item_comments, item_assets]
        entry = plan_by_number[number]
        if sorted(comment_ids) != entry.get("comment_ids"):
            raise ExportError(f"item {number} comment plan does not match")
        if number in issue_index:
            if entry.get("type") != "issue" or entry.get("state") != detail.get("state"):
                raise ExportError(f"issue {number} plan does not preserve state")
            if entry.get("labels") != _extract_labels(detail):
                raise ExportError(f"issue {number} plan does not preserve labels")
        else:
            pull = _json_from_path(item_dir / "pull.json")
            metadata = _json_from_path(item_dir / "pull-metadata.json")
            if not isinstance(pull, dict) or not isinstance(metadata, dict):
                raise ExportError(f"pull request {number} data is invalid")
            if pull.get("state") != "closed" or entry.get("type") != "legacy-pr":
                raise ExportError(f"pull request {number} is not a closed legacy item")
            if pull.get("id") != pull_index[number].get("id"):
                raise ExportError(f"pull request {number} detail ID does not match its index")
            if entry.get("pull") != metadata or metadata != _pull_metadata(pull):
                raise ExportError(f"pull request {number} metadata does not match")
            if "legacy-pr" not in entry.get("labels", []):
                raise ExportError(f"pull request {number} lacks the legacy-pr label")
            asset_sources.extend(
                [
                    pull,
                    _json_from_path(item_dir / "commits.json"),
                    _json_from_path(item_dir / "files.json"),
                    _json_from_path(item_dir / "reviews.json"),
                    _json_from_path(item_dir / "review-comments.json"),
                    _json_from_path(item_dir / "status.json"),
                ]
            )
        planned_assets = entry.get("asset_uuids")
        if not isinstance(planned_assets, list):
            raise ExportError(f"item {number} asset plan is invalid")
        derived_assets = {
            _asset_uuid(asset) for source in asset_sources for asset in _asset_candidates(source)
        }
        if sorted(derived_assets) != planned_assets:
            raise ExportError(f"item {number} asset plan does not match its data")
        referenced_assets.update(derived_assets)
    if per_item_comments != global_comment_ids:
        raise ExportError("snapshot global/per-item comments do not reconcile")

    mappings = manifest.get("asset_rewrite_mapping")
    if not isinstance(mappings, list):
        raise ExportError("manifest asset mapping is invalid")
    mapping_ids: set[str] = set()
    source = manifest.get("source")
    if not isinstance(source, dict) or not isinstance(source.get("base_url"), str):
        raise ExportError("manifest source is invalid")
    source_origin = _origin(source["base_url"])
    for mapping in mappings:
        if not isinstance(mapping, dict):
            raise ExportError("manifest asset mapping entry is invalid")
        asset_uuid = _asset_uuid(mapping)
        if asset_uuid in mapping_ids:
            raise ExportError("manifest contains a duplicate asset UUID")
        mapping_ids.add(asset_uuid)
        source_url = mapping.get("source_url")
        if not isinstance(source_url, str) or _origin(source_url) != source_origin:
            raise ExportError("manifest asset URL is not on the source origin")
        relative = mapping.get("path")
        if not isinstance(relative, str) or not (snapshot / relative).is_file():
            raise ExportError("manifest asset file is missing")
        if mapping.get("size") != (snapshot / relative).stat().st_size:
            raise ExportError("manifest asset size does not match")
        if mapping.get("sha256") != _sha256(snapshot / relative):
            raise ExportError("manifest asset hash does not match")
        if mapping.get("github_url") is not None:
            raise ExportError("unimported asset mapping unexpectedly has a GitHub URL")
    if referenced_assets != mapping_ids:
        raise ExportError("asset references and manifest mapping do not reconcile")

    current = manifest.get("counts", {}).get("current")
    expected_counts = {
        "issues": len(issues),
        "pull_requests": len(pulls),
        "comments": len(comments),
        "labels": len(labels),
        "assets": len(mappings),
    }
    if current != expected_counts:
        raise ExportError("manifest current counts do not match snapshot data")
    page_counts = manifest.get("api_scope", {}).get("page_counts")
    if not isinstance(page_counts, dict):
        raise ExportError("manifest API page counts are missing")
    for key, count_key in {
        "initial.labels": "labels",
        "initial.issues": "issues",
        "initial.pull_requests": "pull_requests",
        "initial.comments": "comments",
        "confirmation.labels": "labels",
        "confirmation.issues": "issues",
        "confirmation.pull_requests": "pull_requests",
        "confirmation.comments": "comments",
    }.items():
        page_entry = page_counts.get(key)
        if not isinstance(page_entry, dict):
            raise ExportError(f"manifest API page count is missing: {key}")
        if page_entry.get("items") != expected_counts[count_key]:
            raise ExportError(f"manifest API item count does not match: {key}")
        if page_entry.get("x_total_count") != expected_counts[count_key]:
            raise ExportError(f"manifest API total count does not match: {key}")
    reconciliation = manifest.get("counts", {}).get("reconciliation")
    if not isinstance(reconciliation, dict):
        raise ExportError("manifest count reconciliation is missing")
    for key, count in expected_counts.items():
        entry = reconciliation.get(key)
        if not isinstance(entry, dict):
            raise ExportError(f"manifest reconciliation for {key} is missing")
        if entry.get("baseline") != BASELINE_COUNTS[key] or entry.get("current") != count:
            raise ExportError(f"manifest reconciliation for {key} is invalid")
        if entry.get("delta") != count - BASELINE_COUNTS[key]:
            raise ExportError(f"manifest reconciliation delta for {key} is invalid")
        if entry["delta"] and not str(entry.get("explanation", "")).strip():
            raise ExportError(f"manifest reconciliation for {key} is unexplained")


def validate_snapshot(snapshot: Path, token: bytes) -> dict[str, Any]:
    if snapshot.is_symlink():
        raise ExportError("snapshot directory must not be a symlink")
    snapshot = snapshot.resolve()
    if not snapshot.is_dir():
        raise ExportError("snapshot directory does not exist")
    _check_permissions(snapshot)
    manifest_path = snapshot / "manifest.json"
    sidecar_path = snapshot / "manifest.sha256"
    manifest = _json_from_path(manifest_path)
    if not isinstance(manifest, dict) or manifest.get("format_version") != FORMAT_VERSION:
        raise ExportError("unsupported or invalid manifest format")
    try:
        sidecar = sidecar_path.read_text(encoding="ascii")
    except (OSError, UnicodeDecodeError) as exc:
        raise ExportError("manifest checksum sidecar is invalid") from exc
    expected_sidecar = f"{_sha256(manifest_path)}  manifest.json\n"
    if sidecar != expected_sidecar:
        raise ExportError("manifest checksum does not match")
    inventory = manifest.get("file_inventory")
    if not isinstance(inventory, list):
        raise ExportError("manifest file inventory is invalid")
    expected_files = {"manifest.json", "manifest.sha256"}
    seen_inventory: set[str] = set()
    for entry in inventory:
        if not isinstance(entry, dict):
            raise ExportError("manifest inventory entry is invalid")
        relative = entry.get("path")
        if (
            not isinstance(relative, str)
            or relative.startswith("/")
            or ".." in Path(relative).parts
            or relative in seen_inventory
        ):
            raise ExportError("manifest inventory path is invalid or duplicated")
        seen_inventory.add(relative)
        expected_files.add(relative)
        path = snapshot / relative
        if not path.is_file() or path.is_symlink():
            raise ExportError(f"inventoried file is missing: {relative}")
        if path.stat().st_size != entry.get("size") or _sha256(path) != entry.get("sha256"):
            raise ExportError(f"inventoried file failed size/hash validation: {relative}")
    actual_files = {
        path.relative_to(snapshot).as_posix() for path in snapshot.rglob("*") if path.is_file()
    }
    if actual_files != expected_files:
        missing = sorted(expected_files - actual_files)
        extra = sorted(actual_files - expected_files)
        raise ExportError(f"snapshot file set mismatch: missing={missing[:3]} extra={extra[:3]}")
    if token:
        for relative in sorted(actual_files):
            if token in (snapshot / relative).read_bytes():
                raise ExportError(f"exact token found in snapshot file: {relative}")
    _validate_data(snapshot, manifest)
    _validate_bundle(snapshot, manifest)
    return manifest


def export_snapshot(
    *,
    base_url: str,
    repository: str,
    destination_root: Path,
    git_repository: Path,
    main_ref: str,
    archive_ref: str,
    reconciliation_path: Path,
    token: bytes,
    now: datetime | None = None,
) -> Path:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ExportError("repository must use owner/name form")
    if not token:
        raise ExportError("a non-empty token must be supplied through stdin")
    git_repository = git_repository.resolve()
    initial_refs = _resolve_refs(git_repository, main_ref, archive_ref)
    timestamp = (now or datetime.now(UTC)).astimezone(UTC).replace(microsecond=0)
    timestamp_text = timestamp.strftime("%Y%m%dT%H%M%SZ")
    final_name = f"{timestamp_text}-{initial_refs['main'][:12]}"
    destination_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    destination_metadata = destination_root.lstat()
    if stat.S_ISLNK(destination_metadata.st_mode):
        raise ExportError("destination root must not be a symlink")
    if not stat.S_ISDIR(destination_metadata.st_mode):
        raise ExportError("destination root is not a directory")
    if stat.S_IMODE(destination_metadata.st_mode) != 0o700:
        raise ExportError("destination root must use mode 0700")
    final_path = destination_root / final_name
    if final_path.exists() or final_path.is_symlink():
        raise ExportError("final export destination already exists")
    previous_umask = os.umask(0o077)
    staging: Path | None = destination_root / f".{final_name}.tmp-{uuid.uuid4().hex}"
    try:
        staging.mkdir(mode=0o700)
        client = GiteaClient(base_url, token)
        initial_indexes = _capture_indexes(client, repository, prefix="initial")
        _write_json(staging / "api" / "labels.json", initial_indexes["labels"])
        _write_json(staging / "api" / "issues.json", initial_indexes["issues"])
        _write_json(staging / "api" / "pull-requests.json", initial_indexes["pull_requests"])
        _write_json(staging / "api" / "comments.json", initial_indexes["comments"])
        number_plan, asset_mapping = _capture_items(
            client,
            repository,
            initial_indexes,
            staging,
        )
        _write_json(staging / "number-plan.json", number_plan)
        current_counts = {
            "issues": len(initial_indexes["issues"]),
            "pull_requests": len(initial_indexes["pull_requests"]),
            "comments": len(initial_indexes["comments"]),
            "labels": len(initial_indexes["labels"]),
            "assets": len(asset_mapping),
        }
        reconciliation = _load_reconciliation(reconciliation_path, current_counts)

        confirmed_indexes = _capture_indexes(client, repository, prefix="confirmation")
        if _canonical_json(initial_indexes) != _canonical_json(confirmed_indexes):
            raise ExportError("Gitea index changed during export")
        confirmed_refs = _resolve_refs(git_repository, main_ref, archive_ref)
        if confirmed_refs != initial_refs:
            raise ExportError("Git refs changed during export")
        _create_bundle(git_repository, staging, initial_refs)
        final_refs = _resolve_refs(git_repository, main_ref, archive_ref)
        if final_refs != initial_refs:
            raise ExportError("Git refs changed while creating the bundle")

        manifest: dict[str, Any] = {
            "format_version": FORMAT_VERSION,
            "source": {"base_url": base_url.rstrip("/"), "repository": repository},
            "exported_at": timestamp.isoformat().replace("+00:00", "Z"),
            "api_scope": {
                "page_counts": client.page_counts,
                "unavailable_endpoints": sorted(set(client.unavailable_endpoints)),
            },
            "main_sha": initial_refs["main"],
            "refs": {
                "main": {
                    "source_ref": main_ref,
                    "bundle_ref": MAIN_BUNDLE_REF,
                    "sha": initial_refs["main"],
                },
                "archive": {
                    "source_ref": archive_ref,
                    "bundle_ref": ARCHIVE_BUNDLE_REF,
                    "sha": initial_refs["archive"],
                    "github_ref": ARCHIVE_BUNDLE_REF,
                },
                "merge_base": initial_refs["merge_base"],
            },
            "counts": {
                "baseline": BASELINE_COUNTS,
                "current": current_counts,
                "reconciliation": reconciliation,
            },
            "asset_rewrite_mapping": asset_mapping,
            "number_plan": {
                "path": "number-plan.json",
                "minimum": 1,
                "maximum": number_plan[-1]["number"],
                "tombstone": TOMBSTONE_NUMBER,
                "strategy": "strictly ascending; stop on first destination number mismatch",
            },
        }
        manifest["file_inventory"] = _inventory(staging)
        _write_json(staging / "manifest.json", manifest)
        manifest_hash = _sha256(staging / "manifest.json")
        _write_bytes(
            staging / "manifest.sha256",
            f"{manifest_hash}  manifest.json\n".encode("ascii"),
        )
        validate_snapshot(staging, token)
        _rename_noreplace(staging, final_path)
        staging = None
        return final_path
    finally:
        os.umask(previous_umask)
        if staging is not None and staging.exists():
            shutil.rmtree(staging)


def _read_token() -> bytes:
    token = sys.stdin.buffer.readline().rstrip(b"\r\n")
    remainder = sys.stdin.buffer.read()
    if remainder.strip():
        raise ExportError("stdin must contain only one token line")
    if not token:
        raise ExportError("a non-empty token must be supplied through stdin")
    return token


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    export = subparsers.add_parser("export", help="create and validate a protected snapshot")
    export.add_argument("--base-url", required=True)
    export.add_argument("--repository", required=True)
    export.add_argument("--destination-root", type=Path, required=True)
    export.add_argument("--git-repository", type=Path, default=Path.cwd())
    export.add_argument("--main-ref", default=DEFAULT_MAIN_REF)
    export.add_argument("--archive-ref", default=DEFAULT_ARCHIVE_REF)
    export.add_argument("--reconciliation", type=Path, required=True)
    validate = subparsers.add_parser("validate", help="validate a snapshot without network access")
    validate.add_argument("snapshot", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        token = _read_token()
        if args.command == "export":
            path = export_snapshot(
                base_url=args.base_url,
                repository=args.repository,
                destination_root=args.destination_root,
                git_repository=args.git_repository,
                main_ref=args.main_ref,
                archive_ref=args.archive_ref,
                reconciliation_path=args.reconciliation,
                token=token,
            )
            print(f"export={path}")
        else:
            manifest = validate_snapshot(args.snapshot, token)
            print(f"validation=passed main_sha={manifest['main_sha']}")
        return 0
    except ExportError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
