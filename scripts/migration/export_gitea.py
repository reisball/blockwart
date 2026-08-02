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
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

FORMAT_VERSION = 2
SEMANTIC_PROJECTION_VERSION = 1
PER_PAGE = 50
TOMBSTONE_NUMBER = 86
TOMBSTONE_REASON = "Deleted Gitea item; reserve the historical number."
UNAVAILABLE_MARKER = {"available": False, "reason": "endpoint-unavailable"}
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
GIT_SHA_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")


class ExportError(RuntimeError):
    """A safe-to-display, fail-closed export or validation error."""


class NotFoundError(ExportError):
    """An optional Gitea endpoint is unavailable."""


@dataclass(frozen=True)
class ExportResult:
    """Final snapshot path and its non-secret external trust-root digest."""

    path: Path
    manifest_sha256: str


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
    try:
        parsed = urllib.parse.urlsplit(url)
        explicit_port = parsed.port
    except ValueError as exc:
        raise ExportError("source URL contains an invalid host or port") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ExportError("source URL must use http or https and include a host")
    if parsed.username is not None or parsed.password is not None:
        raise ExportError("source URL must not contain credentials")
    port = (
        explicit_port
        if explicit_port is not None
        else (443 if parsed.scheme == "https" else 80)
    )
    if port < 1:
        raise ExportError("source URL contains an invalid host or port")
    return parsed.scheme.lower(), parsed.hostname.lower(), port


def _canonical_gitea_base_url(url: str) -> str:
    scheme, hostname, port = _origin(url)
    parsed = urllib.parse.urlsplit(url)
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ExportError(
            "Gitea base URL must be an origin root without a path, query, or fragment"
        )
    host = f"[{hostname}]" if ":" in hostname else hostname
    default_port = 443 if scheme == "https" else 80
    netloc = host if port == default_port else f"{host}:{port}"
    return urllib.parse.urlunsplit((scheme, netloc, "", "", ""))


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


def _require_git_sha(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or GIT_SHA_RE.fullmatch(value) is None:
        raise ExportError(f"{label} must be a full lowercase Git SHA")
    return value


def _require_sha256(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ExportError(f"{label} must be a 64-character lowercase SHA-256")
    return value


def _payload_evidence(
    path: str,
    *,
    kind: str,
    payload: bytes | None,
) -> dict[str, Any]:
    if payload is None:
        return {
            "path": path,
            "kind": kind,
            "available": False,
            "reason": "endpoint-unavailable",
        }
    return {
        "path": path,
        "kind": kind,
        "available": True,
        "size": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }


def _json_evidence(path: str, payload: Any) -> dict[str, Any]:
    del payload
    return {"path": path, "kind": "json", "available": True}


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
    resolved = {
        "main": main_sha,
        "archive": archive_sha,
        "merge base": merge_base,
    }
    for label, value in resolved.items():
        _require_git_sha(value, label=f"resolved {label}")
    if len({len(value) for value in resolved.values()}) != 1:
        raise ExportError("resolved Git SHAs use inconsistent object formats")
    return {"main": main_sha, "archive": archive_sha, "merge_base": merge_base}


class GiteaClient:
    def __init__(self, base_url: str, token: bytes) -> None:
        self.base_url = _canonical_gitea_base_url(base_url)
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
        self.endpoint_evidence: dict[str, dict[str, Any]] = {}
        self.unavailable_endpoints: list[str] = []

    def record_endpoint(self, key: str, evidence: dict[str, Any]) -> None:
        if key in self.endpoint_evidence:
            raise ExportError(f"duplicate endpoint evidence key: {key}")
        self.endpoint_evidence[key] = evidence

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
        if not isinstance(item, Mapping):
            raise ExportError(f"{label} entry must be an object")
        value = _as_int(item.get(field), label=f"{label} {field}")
        if value in values:
            raise ExportError(f"duplicate {label} {field}: {value}")
        values.add(value)
    return values


def _unique_text(
    items: Sequence[Mapping[str, Any]],
    field: str,
    label: str,
    *,
    git_sha: bool = False,
) -> set[str]:
    values: set[str] = set()
    for item in items:
        if not isinstance(item, Mapping):
            raise ExportError(f"{label} entry must be an object")
        value = item.get(field)
        if not isinstance(value, str) or not value:
            raise ExportError(f"{label} {field} must be non-empty text")
        if git_sha:
            _require_git_sha(value, label=f"{label} {field}")
        if value in values:
            raise ExportError(f"duplicate {label} {field}: {value}")
        values.add(value)
    return values


def _sort_index(items: list[dict[str, Any]], field: str) -> list[dict[str, Any]]:
    return sorted(items, key=lambda item: _as_int(item.get(field), label=field))


def _project_known_object(
    value: Any,
    *,
    label: str,
    semantic_fields: set[str],
    ignored_fields: set[str],
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ExportError(f"{label} must be an object")
    unknown = set(value) - semantic_fields - ignored_fields
    if unknown:
        raise ExportError(f"{label} contains unclassified fields: {', '.join(sorted(unknown))}")
    return {field: value[field] for field in sorted(semantic_fields) if field in value}


def _project_optional_object(value: Any, projector: Any, *, label: str) -> Any:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise ExportError(f"{label} must be an object or null")
    return projector(value)


def _project_collection(
    values: Any,
    projector: Any,
    key: Any,
    *,
    label: str,
    preserve_order: bool = False,
) -> list[dict[str, Any]]:
    if values is None:
        values = []
    if not isinstance(values, list):
        raise ExportError(f"{label} must be a list")
    projected = [projector(value) for value in values]
    identities = [key(value) for value in projected]
    if len(set(identities)) != len(identities):
        raise ExportError(f"{label} contains duplicate semantic identities")
    if preserve_order:
        return projected
    pairs = sorted(zip(identities, projected, strict=True), key=lambda pair: pair[0])
    return [value for _identity, value in pairs]


def _project_user(value: Mapping[str, Any]) -> dict[str, Any]:
    return _project_known_object(
        value,
        label="user",
        semantic_fields={"id", "login", "login_name", "username", "full_name", "email"},
        ignored_fields={
            "active",
            "avatar_url",
            "created",
            "description",
            "followers_count",
            "following_count",
            "html_url",
            "is_admin",
            "language",
            "last_login",
            "location",
            "prohibit_login",
            "restricted",
            "source_id",
            "starred_repos_count",
            "visibility",
            "website",
        },
    )


def _user_key(value: Mapping[str, Any]) -> tuple[Any, Any]:
    identifier = value.get("id")
    login = value.get("login") or value.get("username")
    if identifier is None and not login:
        raise ExportError("user lacks a stable identity")
    return identifier is None, identifier if identifier is not None else login


def _project_label(value: Mapping[str, Any]) -> dict[str, Any]:
    return _project_known_object(
        value,
        label="label",
        semantic_fields={"id", "name", "color", "description", "exclusive", "is_archived"},
        ignored_fields={"url"},
    )


def _project_asset(value: Mapping[str, Any]) -> dict[str, Any]:
    projected = _project_known_object(
        value,
        label="asset",
        semantic_fields={
            "id",
            "uuid",
            "name",
            "browser_download_url",
            "size",
            "created_at",
            "uploader",
        },
        ignored_fields={"download_count"},
    )
    if "uploader" in projected:
        projected["uploader"] = _project_optional_object(
            projected["uploader"], _project_user, label="asset uploader"
        )
    return projected


def _asset_projection_key(value: Mapping[str, Any]) -> tuple[Any, ...]:
    asset_uuid = value.get("uuid")
    asset_id = value.get("id")
    if not asset_uuid and asset_id is None:
        raise ExportError("asset lacks a stable identity")
    return (asset_uuid is None, asset_uuid if asset_uuid is not None else asset_id)


def _project_milestone(value: Mapping[str, Any]) -> dict[str, Any]:
    projected = _project_known_object(
        value,
        label="milestone",
        semantic_fields={
            "id",
            "title",
            "description",
            "state",
            "created_at",
            "updated_at",
            "closed_at",
            "due_on",
            "due_date",
            "creator",
        },
        ignored_fields={"open_issues", "closed_issues", "url", "html_url"},
    )
    if "creator" in projected:
        projected["creator"] = _project_optional_object(
            projected["creator"], _project_user, label="milestone creator"
        )
    return projected


_REPOSITORY_FIELDS = {
    "allow_fast_forward_only_merge",
    "allow_manual_merge",
    "allow_merge_commits",
    "allow_rebase",
    "allow_rebase_explicit",
    "allow_rebase_update",
    "allow_squash_merge",
    "archived",
    "archived_at",
    "autodetect_manual_merge",
    "avatar_url",
    "clone_url",
    "created_at",
    "default_allow_maintainer_edit",
    "default_branch",
    "default_delete_branch_after_merge",
    "default_merge_style",
    "description",
    "empty",
    "fork",
    "forks_count",
    "full_name",
    "has_actions",
    "has_code",
    "has_issues",
    "has_packages",
    "has_projects",
    "has_pull_requests",
    "has_releases",
    "has_wiki",
    "html_url",
    "id",
    "ignore_whitespace_conflicts",
    "internal",
    "internal_tracker",
    "language",
    "languages_url",
    "licenses",
    "link",
    "mirror",
    "mirror_interval",
    "mirror_updated",
    "name",
    "object_format_name",
    "open_issues_count",
    "open_pr_counter",
    "original_url",
    "owner",
    "permissions",
    "private",
    "projects_mode",
    "release_counter",
    "size",
    "ssh_url",
    "stars_count",
    "template",
    "topics",
    "updated_at",
    "url",
    "watchers_count",
    "website",
}


def _project_repository(value: Mapping[str, Any]) -> dict[str, Any]:
    projected = _project_known_object(
        value,
        label="repository",
        semantic_fields={"id", "name", "full_name", "owner"},
        ignored_fields=_REPOSITORY_FIELDS - {"id", "name", "full_name", "owner"},
    )
    if "owner" in projected:
        owner = projected["owner"]
        if isinstance(owner, Mapping):
            projected["owner"] = _project_user(owner)
        elif owner is not None and not isinstance(owner, str):
            raise ExportError("repository owner must be an object, text, or null")
    return projected


def _project_pull_reference(value: Mapping[str, Any]) -> dict[str, Any]:
    projected = _project_known_object(
        value,
        label="pull reference",
        semantic_fields={"ref", "sha", "repo_id", "repo"},
        ignored_fields={"label"},
    )
    if "repo" in projected:
        projected["repo"] = _project_optional_object(
            projected["repo"], _project_repository, label="pull reference repository"
        )
    return projected


def _project_team(value: Mapping[str, Any]) -> dict[str, Any]:
    return _project_known_object(
        value,
        label="review team",
        semantic_fields={"id", "name", "description"},
        ignored_fields={
            "can_create_org_repo",
            "includes_all_repositories",
            "permission",
            "units",
            "units_map",
            "organization",
        },
    )


def _project_pull_request_marker(value: Mapping[str, Any]) -> dict[str, Any]:
    return _project_known_object(
        value,
        label="issue pull-request marker",
        semantic_fields={"merged", "merged_at", "draft"},
        ignored_fields={"html_url", "diff_url", "patch_url"},
    )


def _project_issue(value: Mapping[str, Any]) -> dict[str, Any]:
    projected = _project_known_object(
        value,
        label="issue",
        semantic_fields={
            "id",
            "number",
            "title",
            "body",
            "state",
            "is_locked",
            "created_at",
            "updated_at",
            "closed_at",
            "due_date",
            "original_author",
            "original_author_id",
            "pin_order",
            "ref",
            "time_estimate",
            "user",
            "labels",
            "assignee",
            "assignees",
            "milestone",
            "assets",
            "repository",
            "pull_request",
        },
        ignored_fields={"comments", "html_url", "url"},
    )
    if "user" in projected:
        projected["user"] = _project_optional_object(
            projected["user"], _project_user, label="issue user"
        )
    if "assignee" in projected:
        projected["assignee"] = _project_optional_object(
            projected["assignee"], _project_user, label="issue assignee"
        )
    if "assignees" in projected:
        projected["assignees"] = _project_collection(
            projected["assignees"], _project_user, _user_key, label="issue assignees"
        )
    if "labels" in projected:
        projected["labels"] = _project_collection(
            projected["labels"],
            _project_label,
            lambda item: _as_int(item.get("id"), label="label id"),
            label="issue labels",
        )
    if "milestone" in projected:
        projected["milestone"] = _project_optional_object(
            projected["milestone"], _project_milestone, label="issue milestone"
        )
    if "assets" in projected:
        projected["assets"] = _project_collection(
            projected["assets"], _project_asset, _asset_projection_key, label="issue assets"
        )
    if "repository" in projected:
        projected["repository"] = _project_optional_object(
            projected["repository"], _project_repository, label="issue repository"
        )
    if "pull_request" in projected:
        projected["pull_request"] = _project_optional_object(
            projected["pull_request"],
            _project_pull_request_marker,
            label="issue pull-request marker",
        )
    return projected


def _project_pull(value: Mapping[str, Any]) -> dict[str, Any]:
    projected = _project_known_object(
        value,
        label="pull request",
        semantic_fields={
            "id",
            "number",
            "title",
            "body",
            "state",
            "is_locked",
            "draft",
            "allow_maintainer_edit",
            "created_at",
            "updated_at",
            "closed_at",
            "due_date",
            "merged",
            "merged_at",
            "merge_commit_sha",
            "merge_base",
            "pin_order",
            "user",
            "merged_by",
            "labels",
            "assignee",
            "assignees",
            "milestone",
            "requested_reviewers",
            "requested_reviewers_teams",
            "base",
            "head",
        },
        ignored_fields={
            "additions",
            "changed_files",
            "comments",
            "deletions",
            "diff_url",
            "html_url",
            "mergeable",
            "patch_url",
            "url",
        },
    )
    for field in ("user", "merged_by", "assignee"):
        if field in projected:
            projected[field] = _project_optional_object(
                projected[field], _project_user, label=f"pull request {field}"
            )
    for field in ("assignees", "requested_reviewers"):
        if field in projected:
            projected[field] = _project_collection(
                projected[field], _project_user, _user_key, label=f"pull request {field}"
            )
    if "requested_reviewers_teams" in projected:
        projected["requested_reviewers_teams"] = _project_collection(
            projected["requested_reviewers_teams"],
            _project_team,
            lambda item: (_as_int(item.get("id"), label="review team id"), item.get("name")),
            label="pull request review teams",
        )
    if "labels" in projected:
        projected["labels"] = _project_collection(
            projected["labels"],
            _project_label,
            lambda item: _as_int(item.get("id"), label="label id"),
            label="pull request labels",
        )
    if "milestone" in projected:
        projected["milestone"] = _project_optional_object(
            projected["milestone"], _project_milestone, label="pull request milestone"
        )
    for field in ("base", "head"):
        if field in projected:
            projected[field] = _project_optional_object(
                projected[field], _project_pull_reference, label=f"pull request {field}"
            )
    return projected


def _comment_parent_association(
    value: Mapping[str, Any], *, required: bool
) -> dict[str, Any] | None:
    present = [
        (field, value.get(field))
        for field in ("issue_url", "pull_request_url")
        if value.get(field) is not None and value.get(field) != ""
    ]
    if len(present) > 1:
        raise ExportError("comment has conflicting issue and pull-request parents")
    if not present:
        if required:
            raise ExportError("comment lacks a parent association")
        return None

    field, url = present[0]
    if not isinstance(url, str):
        raise ExportError(f"comment {field} must be text or null")
    parsed = urllib.parse.urlsplit(url)
    if parsed.username is not None or parsed.password is not None:
        raise ExportError(f"comment {field} must not contain credentials")
    if parsed.query or parsed.fragment:
        raise ExportError(f"comment {field} must not contain a query or fragment")
    scheme, hostname, port = _origin(url)
    parts = [urllib.parse.unquote(part) for part in parsed.path.split("/") if part]
    if len(parts) < 4:
        raise ExportError(f"comment {field} is not a canonical repository item URL")
    owner, repository, path_kind, number_text = parts[-4:]
    expected_path_kind = "issues" if field == "issue_url" else "pulls"
    if path_kind != expected_path_kind or not number_text.isdigit():
        raise ExportError(f"comment {field} has an invalid parent kind or number")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", owner) or not re.fullmatch(
        r"[A-Za-z0-9_.-]+", repository
    ):
        raise ExportError(f"comment {field} has an invalid repository identity")
    host = f"[{hostname}]" if ":" in hostname else hostname
    default_port = 443 if scheme == "https" else 80
    origin = f"{scheme}://{host}" if port == default_port else f"{scheme}://{host}:{port}"
    return {
        "kind": "issue" if field == "issue_url" else "pull_request",
        "origin": origin,
        "repository": f"{owner}/{repository}",
        "number": int(number_text),
    }


def _project_comment(
    value: Mapping[str, Any], *, require_parent: bool = False
) -> dict[str, Any]:
    parent = _comment_parent_association(value, required=require_parent)
    projected = _project_known_object(
        value,
        label="comment",
        semantic_fields={
            "id",
            "body",
            "created_at",
            "updated_at",
            "original_author",
            "original_author_id",
            "user",
            "assets",
        },
        ignored_fields={"html_url", "issue_url", "pull_request_url"},
    )
    if parent is not None:
        projected["parent"] = parent
    if "user" in projected:
        projected["user"] = _project_optional_object(
            projected["user"], _project_user, label="comment user"
        )
    if "assets" in projected:
        projected["assets"] = _project_collection(
            projected["assets"], _project_asset, _asset_projection_key, label="comment assets"
        )
    return projected


def _reconcile_comment_parents(
    global_comments: Sequence[Mapping[str, Any]],
    per_item_comments: Mapping[int, Mapping[str, Any]],
    expected_parents: Mapping[int, Mapping[str, Any]],
) -> None:
    global_comment_ids = _unique(global_comments, "id", "global comment")
    expected_comment_ids = set(expected_parents)
    per_item_comment_ids = set(per_item_comments)
    if expected_comment_ids != global_comment_ids or (
        expected_comment_ids != per_item_comment_ids
    ):
        missing = sorted(global_comment_ids - expected_comment_ids)
        extra = sorted(expected_comment_ids - global_comment_ids)
        detail = f"missing={missing[:3]} extra={extra[:3]}"
        raise ExportError(f"global/per-item comment reconciliation failed ({detail})")

    global_comments_by_id = {
        _as_int(comment.get("id"), label="global comment id"): comment
        for comment in global_comments
    }
    for comment_id in sorted(global_comments_by_id):
        global_comment = global_comments_by_id[comment_id]
        per_item_comment = per_item_comments[comment_id]
        expected_parent = expected_parents[comment_id]
        global_parent = _comment_parent_association(global_comment, required=True)
        per_item_parent = _comment_parent_association(per_item_comment, required=True)
        if global_parent != expected_parent or per_item_parent != expected_parent:
            raise ExportError(
                f"comment {comment_id} parent association does not match captured item"
            )
        if _project_comment(global_comment, require_parent=True) != _project_comment(
            per_item_comment, require_parent=True
        ):
            raise ExportError(
                f"comment {comment_id} global/per-item semantic content differs"
            )


def _chronological_key(value: Mapping[str, Any]) -> tuple[str, int]:
    timestamp = value.get("submitted_at") or value.get("created_at") or ""
    if not isinstance(timestamp, str):
        raise ExportError("chronological item timestamp must be text")
    return timestamp, _as_int(value.get("id"), label="chronological item id")


def _project_commit_signature(value: Mapping[str, Any], *, label: str) -> dict[str, Any]:
    return _project_known_object(
        value,
        label=label,
        semantic_fields={"name", "email", "date"},
        ignored_fields=set(),
    )


def _project_commit_payload(value: Mapping[str, Any]) -> dict[str, Any]:
    projected = _project_known_object(
        value,
        label="commit payload",
        semantic_fields={"author", "committer", "message", "tree"},
        ignored_fields={"url", "verification"},
    )
    for field in ("author", "committer"):
        if field in projected:
            projected[field] = _project_optional_object(
                projected[field],
                lambda item, field=field: _project_commit_signature(
                    item, label=f"commit {field}"
                ),
                label=f"commit {field}",
            )
    if "tree" in projected:
        projected["tree"] = _project_known_object(
            projected["tree"],
            label="commit tree",
            semantic_fields={"sha"},
            ignored_fields={"url", "created"},
        )
    return projected


def _project_commit(value: Mapping[str, Any]) -> dict[str, Any]:
    projected = _project_known_object(
        value,
        label="pull request commit",
        semantic_fields={"sha", "created", "author", "committer", "commit", "parents"},
        ignored_fields={"files", "html_url", "stats", "url"},
    )
    for field in ("author", "committer"):
        if field in projected:
            projected[field] = _project_optional_object(
                projected[field], _project_user, label=f"commit API {field}"
            )
    if "commit" in projected:
        projected["commit"] = _project_optional_object(
            projected["commit"], _project_commit_payload, label="commit payload"
        )
    if "parents" in projected:
        projected["parents"] = _project_collection(
            projected["parents"],
            lambda item: _project_known_object(
                item,
                label="commit parent",
                semantic_fields={"sha"},
                ignored_fields={"created", "url"},
            ),
            lambda item: item.get("sha"),
            label="commit parents",
            preserve_order=True,
        )
    return projected


def _project_file(value: Mapping[str, Any]) -> dict[str, Any]:
    return _project_known_object(
        value,
        label="pull request file",
        semantic_fields={
            "filename",
            "previous_filename",
            "status",
            "additions",
            "deletions",
            "changes",
        },
        ignored_fields={"contents_url", "html_url", "raw_url", "blob_url", "patch", "sha"},
    )


def _project_review(value: Mapping[str, Any]) -> dict[str, Any]:
    projected = _project_known_object(
        value,
        label="pull request review",
        semantic_fields={
            "id",
            "body",
            "state",
            "commit_id",
            "submitted_at",
            "created_at",
            "updated_at",
            "user",
            "team",
            "official",
            "dismissed",
            "dismissal_message",
        },
        ignored_fields={"comments_count", "html_url", "pull_request_url", "stale"},
    )
    if "user" in projected:
        projected["user"] = _project_optional_object(
            projected["user"], _project_user, label="review user"
        )
    if "team" in projected:
        projected["team"] = _project_optional_object(
            projected["team"], _project_team, label="review team"
        )
    return projected


def _project_review_comment(value: Mapping[str, Any]) -> dict[str, Any]:
    projected = _project_known_object(
        value,
        label="pull request review comment",
        semantic_fields={
            "id",
            "body",
            "path",
            "position",
            "original_position",
            "commit_id",
            "original_commit_id",
            "diff_hunk",
            "pull_request_review_id",
            "created_at",
            "updated_at",
            "resolvable",
            "resolved",
            "user",
            "resolver",
        },
        ignored_fields={"html_url", "pull_request_url", "links"},
    )
    for field in ("user", "resolver"):
        if field in projected:
            projected[field] = _project_optional_object(
                projected[field], _project_user, label=f"review comment {field}"
            )
    return projected


def _project_commit_status(value: Mapping[str, Any]) -> dict[str, Any]:
    projected = _project_known_object(
        value,
        label="commit status",
        semantic_fields={
            "id",
            "status",
            "state",
            "context",
            "description",
            "target_url",
            "created_at",
            "updated_at",
            "creator",
        },
        ignored_fields={"url"},
    )
    if "creator" in projected:
        projected["creator"] = _project_optional_object(
            projected["creator"], _project_user, label="commit status creator"
        )
    return projected


def _project_status(value: Any) -> Any:
    if value == UNAVAILABLE_MARKER:
        return dict(UNAVAILABLE_MARKER)
    projected = _project_known_object(
        value,
        label="combined commit status",
        semantic_fields={"sha", "state", "statuses"},
        ignored_fields={"commit_url", "repository", "total_count", "url"},
    )
    if "statuses" in projected:
        projected["statuses"] = _project_collection(
            projected["statuses"],
            _project_commit_status,
            lambda item: (item.get("context"), item.get("id")),
            label="commit statuses",
        )
    return projected


def _project_indexes(
    indexes: Mapping[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    if set(indexes) != {"labels", "issues", "pull_requests", "comments"}:
        raise ExportError("index projection input is incomplete")
    labels = _project_collection(
        indexes["labels"],
        _project_label,
        lambda item: _as_int(item.get("id"), label="label id"),
        label="label index",
    )
    issues = _project_collection(
        indexes["issues"],
        _project_issue,
        lambda item: _as_int(item.get("number"), label="issue number"),
        label="issue index",
    )
    pulls = _project_collection(
        indexes["pull_requests"],
        _project_pull,
        lambda item: _as_int(item.get("number"), label="pull request number"),
        label="pull request index",
    )
    comments = _project_collection(
        indexes["comments"],
        lambda item: _project_comment(item, require_parent=True),
        lambda item: _as_int(item.get("id"), label="comment id"),
        label="global comment index",
    )
    return {
        "version": SEMANTIC_PROJECTION_VERSION,
        "labels": labels,
        "issues": issues,
        "pull_requests": pulls,
        "comments": comments,
    }


def _semantic_digest(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


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
    safe_value = _safe_component(value, label="asset UUID")
    if safe_value != value:
        raise ExportError("asset UUID is not canonical")
    return value


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


def _canonical_same_origin_url(
    value: str,
    expected_origin: tuple[str, str, int],
) -> str:
    source_url = _asset_url({"browser_download_url": value})
    if _origin(source_url) != expected_origin:
        raise ExportError("asset URL is not on the source origin")
    parsed = urllib.parse.urlsplit(source_url)
    scheme, hostname, port = expected_origin
    host = f"[{hostname}]" if ":" in hostname else hostname
    default_port = 443 if scheme == "https" else 80
    netloc = host if port == default_port else f"{host}:{port}"
    return urllib.parse.urlunsplit((scheme, netloc, parsed.path or "/", "", ""))


def _asset_identity(
    asset: Mapping[str, Any],
    source_origin: tuple[str, str, int],
) -> dict[str, Any]:
    asset_id = _as_int(asset.get("id"), label="asset id")
    if asset_id < 1:
        raise ExportError("asset id must be positive")
    asset_uuid = _asset_uuid(asset)
    raw_name = asset.get("name")
    if not isinstance(raw_name, str) or not raw_name:
        raw_name = "attachment"
    filename = _asset_name(asset)
    return {
        "id": asset_id,
        "uuid": asset_uuid,
        "name": raw_name,
        "source_url": _canonical_same_origin_url(_asset_url(asset), source_origin),
        "path": f"assets/{asset_uuid}/{filename}",
    }


def _merge_asset_identity(
    assets: dict[str, dict[str, Any]],
    identity: dict[str, Any],
) -> bool:
    asset_uuid = identity["uuid"]
    existing = assets.get(asset_uuid)
    if existing is not None:
        canonical_existing = {key: existing[key] for key in identity}
        if canonical_existing != identity:
            raise ExportError(f"conflicting duplicate asset UUID: {asset_uuid}")
        return False
    for other in assets.values():
        if other["path"] == identity["path"]:
            raise ExportError(f"duplicate asset path: {identity['path']}")
        if other["id"] == identity["id"]:
            raise ExportError(f"duplicate asset id: {identity['id']}")
    assets[asset_uuid] = dict(identity)
    return True


def _record_assets(
    client: GiteaClient,
    snapshot: Path,
    values: Iterable[Any],
    assets: dict[str, dict[str, Any]],
) -> list[str]:
    referenced: set[str] = set()
    for value in values:
        for asset in _asset_candidates(value):
            identity = _asset_identity(asset, client.origin)
            asset_uuid = identity["uuid"]
            if _merge_asset_identity(assets, identity):
                response = client.request_bytes(
                    identity["source_url"], accept="application/octet-stream"
                )
                if response is None:  # pragma: no cover - non-optional request
                    raise ExportError("asset download unexpectedly unavailable")
                payload, _headers = response
                _write_bytes(snapshot / identity["path"], payload)
                assets[asset_uuid].update(
                    {
                    "github_url": None,
                    "size": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    }
                )
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
        "merge_commit_sha": pull.get("merge_commit_sha"),
        "base_ref": base.get("ref"),
        "base_sha": base.get("sha"),
        "head_ref": head.get("ref"),
        "head_sha": head.get("sha"),
    }


def _optional_json(client: GiteaClient, path: str, *, key: str) -> Any:
    try:
        payload = client.get_json(path, optional=True)
    except NotFoundError:
        client.unavailable_endpoints.append(path)
        client.record_endpoint(key, _payload_evidence(path, kind="json", payload=None))
        return dict(UNAVAILABLE_MARKER)
    client.record_endpoint(key, _json_evidence(path, payload))
    return payload


def _optional_bytes(
    client: GiteaClient,
    path: str,
    *,
    accept: str,
    key: str,
) -> bytes | None:
    response = client.request_bytes(path, accept=accept, optional=True)
    if response is None:
        client.unavailable_endpoints.append(path)
        client.record_endpoint(key, _payload_evidence(path, kind="bytes", payload=None))
        return None
    payload = response[0]
    client.record_endpoint(key, _payload_evidence(path, kind="bytes", payload=payload))
    return payload


def _capture_items(
    client: GiteaClient,
    repository: str,
    indexes: Mapping[str, list[dict[str, Any]]],
    snapshot: Path,
    *,
    prefix: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    root = f"repos/{repository}"
    assets: dict[str, dict[str, Any]] = {}
    plan: list[dict[str, Any]] = []
    per_item_comments: dict[int, dict[str, Any]] = {}
    per_item_comment_parents: dict[int, dict[str, Any]] = {}

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
        client.record_endpoint(
            f"{prefix}.item.{number}.issue",
            _json_evidence(f"{root}/issues/{number}", issue_detail),
        )
        if _as_int(issue_detail.get("number"), label="issue detail number") != number:
            raise ExportError("issue detail number changed during export")
        comments = client.paginate(
            f"{root}/issues/{number}/comments",
            params=None,
            key=f"{prefix}.item.{number}.comments",
            require_total=False,
        )
        comment_ids = _unique(comments, "id", f"item {number} comment")
        overlap = set(per_item_comments) & comment_ids
        if overlap:
            raise ExportError(f"comment appears under multiple items: {min(overlap)}")
        for comment in comments:
            comment_id = _as_int(comment.get("id"), label=f"item {number} comment id")
            per_item_comments[comment_id] = comment
            per_item_comment_parents[comment_id] = {
                "kind": item_type,
                "origin": client.base_url,
                "repository": repository,
                "number": number,
            }
        item_assets = client.paginate(
            f"{root}/issues/{number}/assets",
            params=None,
            key=f"{prefix}.item.{number}.assets",
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
        client.record_endpoint(
            f"{prefix}.pull.{number}.detail",
            _json_evidence(f"{root}/pulls/{number}", pull_detail),
        )
        if _as_int(pull_detail.get("number"), label="pull detail number") != number:
            raise ExportError("pull request detail number changed during export")
        if pull_detail.get("state") != "closed":
            raise ExportError(f"pull request {number} is still open")
        commits = client.paginate(
            f"{root}/pulls/{number}/commits",
            params=None,
            key=f"{prefix}.pull.{number}.commits",
            require_total=False,
            optional=True,
        )
        files = client.paginate(
            f"{root}/pulls/{number}/files",
            params=None,
            key=f"{prefix}.pull.{number}.files",
            require_total=False,
            optional=True,
        )
        reviews = client.paginate(
            f"{root}/pulls/{number}/reviews",
            params=None,
            key=f"{prefix}.pull.{number}.reviews",
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
                key=f"{prefix}.pull.{number}.review.{review_id}.comments",
                require_total=False,
                optional=True,
            )
        metadata = _pull_metadata(pull_detail)
        head_sha = metadata.get("head_sha")
        _require_git_sha(head_sha, label=f"pull request {number} head SHA")
        status_payload = _optional_json(
            client,
            f"{root}/commits/{head_sha}/status",
            key=f"{prefix}.pull.{number}.status",
        )
        diff = _optional_bytes(
            client,
            f"{root}/pulls/{number}.diff",
            accept="application/vnd.git-lfs+json, text/plain",
            key=f"{prefix}.pull.{number}.diff",
        )
        patch = _optional_bytes(
            client,
            f"{root}/pulls/{number}.patch",
            accept="application/vnd.git-lfs+json, text/plain",
            key=f"{prefix}.pull.{number}.patch",
        )
        _write_json(item_dir / "pull.json", pull_detail)
        _write_json(item_dir / "pull-metadata.json", metadata)
        _write_json(item_dir / "commits.json", commits)
        _write_json(item_dir / "files.json", files)
        _write_json(item_dir / "reviews.json", reviews)
        _write_json(item_dir / "review-comments.json", review_comments)
        _write_json(item_dir / "status.json", status_payload)
        if diff is None:
            _write_json(item_dir / "diff.unavailable.json", UNAVAILABLE_MARKER)
        else:
            _write_bytes(item_dir / "pull.diff", diff)
        if patch is None:
            _write_json(item_dir / "patch.unavailable.json", UNAVAILABLE_MARKER)
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

    _reconcile_comment_parents(
        indexes["comments"], per_item_comments, per_item_comment_parents
    )

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
            "reason": TOMBSTONE_REASON,
        }
    )
    plan.sort(key=lambda entry: entry["number"])
    return plan, sorted(assets.values(), key=lambda asset: asset["uuid"])


def _captured_payload_inventory(snapshot: Path) -> list[dict[str, Any]]:
    inventory: list[dict[str, Any]] = []
    for root_name in ("assets", "items"):
        root = snapshot / root_name
        if not root.exists():
            continue
        for path in sorted(root.rglob("*")):
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not (
                stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)
            ):
                raise ExportError("captured payload contains a special filesystem object")
            if stat.S_ISREG(metadata.st_mode):
                inventory.append(
                    {
                        "path": path.relative_to(snapshot).as_posix(),
                        "size": metadata.st_size,
                        "sha256": _sha256(path),
                    }
                )
    return inventory


def _captured_payload_proof(snapshot: Path) -> dict[str, Any]:
    inventory = _captured_payload_inventory(snapshot)
    return {
        "algorithm": "sha256",
        "file_count": len(inventory),
        "sha256": hashlib.sha256(_canonical_json(inventory)).hexdigest(),
    }


def _project_optional_binary(
    item_dir: Path,
    *,
    payload_name: str,
    marker_name: str,
    label: str,
) -> dict[str, Any]:
    payload = _optional_representation(
        item_dir,
        payload_name=payload_name,
        marker_name=marker_name,
        label=label,
    )
    if payload is None:
        return dict(UNAVAILABLE_MARKER)
    return {
        "available": True,
        "size": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }


def _project_captured_items(
    snapshot: Path,
    indexes: Mapping[str, list[dict[str, Any]]],
    number_plan: list[dict[str, Any]],
    asset_mapping: list[dict[str, Any]],
) -> dict[str, Any]:
    issue_numbers = {
        _as_int(item.get("number"), label="issue number") for item in indexes["issues"]
    }
    pull_numbers = {
        _as_int(item.get("number"), label="pull request number")
        for item in indexes["pull_requests"]
    }
    if issue_numbers & pull_numbers:
        raise ExportError("item projection contains overlapping issue and pull numbers")

    items: list[dict[str, Any]] = []
    for number in sorted(issue_numbers | pull_numbers):
        item_dir = snapshot / "items" / str(number)
        detail = _json_from_path(item_dir / "issue.json")
        comments = _require_object_list(
            _json_from_path(item_dir / "comments.json"),
            label=f"item {number} comments",
        )
        assets = _require_object_list(
            _json_from_path(item_dir / "assets.json"),
            label=f"item {number} assets",
        )
        entry: dict[str, Any] = {
            "number": number,
            "issue": _project_issue(detail),
            "comments": _project_collection(
                comments,
                _project_comment,
                _chronological_key,
                label=f"item {number} comments",
            ),
            "assets": _project_collection(
                assets,
                _project_asset,
                _asset_projection_key,
                label=f"item {number} assets",
            ),
        }
        if number in pull_numbers:
            pull = _json_from_path(item_dir / "pull.json")
            metadata = _json_from_path(item_dir / "pull-metadata.json")
            commits = _require_object_list(
                _json_from_path(item_dir / "commits.json"),
                label=f"pull request {number} commits",
            )
            files = _require_object_list(
                _json_from_path(item_dir / "files.json"),
                label=f"pull request {number} files",
            )
            reviews = _require_object_list(
                _json_from_path(item_dir / "reviews.json"),
                label=f"pull request {number} reviews",
            )
            review_comments = _json_from_path(item_dir / "review-comments.json")
            if not isinstance(review_comments, dict):
                raise ExportError(f"pull request {number} review comments must be an object")
            projected_review_comments: dict[str, Any] = {}
            for review_id, values in sorted(review_comments.items()):
                if not isinstance(review_id, str) or not review_id.isdigit():
                    raise ExportError("review-comment map key must be a numeric review ID")
                projected_review_comments[review_id] = _project_collection(
                    values,
                    _project_review_comment,
                    _chronological_key,
                    label=f"pull request {number} review {review_id} comments",
                )
            status_payload = _json_from_path(item_dir / "status.json")
            entry.update(
                {
                    "pull": _project_pull(pull),
                    "pull_metadata": metadata,
                    "commits": _project_collection(
                        commits,
                        _project_commit,
                        lambda item: item.get("sha"),
                        label=f"pull request {number} commits",
                        preserve_order=True,
                    ),
                    "files": _project_collection(
                        files,
                        _project_file,
                        lambda item: item.get("filename"),
                        label=f"pull request {number} files",
                    ),
                    "reviews": _project_collection(
                        reviews,
                        _project_review,
                        _chronological_key,
                        label=f"pull request {number} reviews",
                    ),
                    "review_comments": projected_review_comments,
                    "status": _project_status(status_payload),
                    "diff": _project_optional_binary(
                        item_dir,
                        payload_name="pull.diff",
                        marker_name="diff.unavailable.json",
                        label=f"{number} diff",
                    ),
                    "patch": _project_optional_binary(
                        item_dir,
                        payload_name="pull.patch",
                        marker_name="patch.unavailable.json",
                        label=f"{number} patch",
                    ),
                }
            )
        items.append(entry)

    asset_files = [
        item
        for item in _captured_payload_inventory(snapshot)
        if item["path"].startswith("assets/")
    ]
    return {
        "version": SEMANTIC_PROJECTION_VERSION,
        "items": items,
        "number_plan": number_plan,
        "asset_mapping": asset_mapping,
        "asset_files": asset_files,
    }


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
            str(bundle_path.resolve()),
            MAIN_BUNDLE_REF,
            ARCHIVE_BUNDLE_REF,
        )
    os.chmod(bundle_path, 0o600)
    return bundle_path


def _inventory(snapshot: Path) -> list[dict[str, Any]]:
    inventory: list[dict[str, Any]] = []
    for path in sorted(snapshot.rglob("*")):
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise ExportError("snapshot contains a symlink")
        if stat.S_ISREG(metadata.st_mode):
            relative = path.relative_to(snapshot).as_posix()
            if relative in {"manifest.json", "manifest.sha256"}:
                continue
            inventory.append(
                {"path": relative, "size": metadata.st_size, "sha256": _sha256(path)}
            )
        elif not stat.S_ISDIR(metadata.st_mode):
            raise ExportError("snapshot contains a special filesystem object")
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
        if stat.S_ISDIR(metadata.st_mode):
            expected = 0o700
        elif stat.S_ISREG(metadata.st_mode):
            expected = 0o600
        else:
            relative = "." if path == snapshot else path.relative_to(snapshot).as_posix()
            raise ExportError(f"snapshot contains a special filesystem object: {relative}")
        if stat.S_IMODE(metadata.st_mode) != expected:
            relative = "." if path == snapshot else path.relative_to(snapshot).as_posix()
            raise ExportError(f"unsafe snapshot permissions: {relative}")


def _validate_bundle(snapshot: Path, manifest: Mapping[str, Any]) -> None:
    bundle = snapshot / "repository.bundle"
    refs = manifest.get("refs")
    if not isinstance(refs, dict) or set(refs) != {"main", "archive", "merge_base"}:
        raise ExportError("manifest refs are invalid")
    main = refs.get("main")
    archive = refs.get("archive")
    if not isinstance(main, dict) or not isinstance(archive, dict):
        raise ExportError("manifest bundle refs are invalid")
    if set(main) != {"source_ref", "bundle_ref", "sha"} or set(archive) != {
        "source_ref",
        "bundle_ref",
        "sha",
        "github_ref",
    }:
        raise ExportError("manifest bundle ref schema is invalid")
    main_sha = _require_git_sha(main.get("sha"), label="manifest main ref SHA")
    archive_sha = _require_git_sha(archive.get("sha"), label="manifest archive ref SHA")
    merge_base = _require_git_sha(refs.get("merge_base"), label="manifest merge-base SHA")
    top_main_sha = _require_git_sha(manifest.get("main_sha"), label="manifest main SHA")
    if len({len(main_sha), len(archive_sha), len(merge_base)}) != 1:
        raise ExportError("manifest refs use inconsistent Git object formats")
    if top_main_sha != main_sha:
        raise ExportError("manifest main SHA does not match refs.main.sha")
    if main.get("bundle_ref") != MAIN_BUNDLE_REF:
        raise ExportError("manifest main bundle ref is invalid")
    if archive.get("bundle_ref") != ARCHIVE_BUNDLE_REF:
        raise ExportError("manifest archive bundle ref is invalid")
    if archive.get("github_ref") != ARCHIVE_BUNDLE_REF:
        raise ExportError("manifest archive GitHub ref is invalid")
    if not all(
        isinstance(ref.get("source_ref"), str) and ref["source_ref"]
        for ref in (main, archive)
    ):
        raise ExportError("manifest source refs are invalid")
    expected = {
        MAIN_BUNDLE_REF: main_sha,
        ARCHIVE_BUNDLE_REF: archive_sha,
    }
    listed: dict[str, str] = {}
    output = _run_git(snapshot, "bundle", "list-heads", str(bundle))
    for line in output.splitlines():
        try:
            sha, name = line.split(" ", 1)
        except ValueError as exc:
            raise ExportError("git bundle advertised an invalid ref") from exc
        _require_git_sha(sha, label="git bundle advertised SHA")
        if name in listed:
            raise ExportError("git bundle advertised a duplicate ref")
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
        actual_merge_base = _run_git(
            bare, "merge-base", MAIN_BUNDLE_REF, ARCHIVE_BUNDLE_REF
        )
        _require_git_sha(actual_merge_base, label="git bundle merge-base SHA")
        if actual_merge_base != merge_base:
            raise ExportError("git bundle merge base does not match the manifest")


def _require_object_list(value: Any, *, label: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ExportError(f"{label} must be an object list")
    return value


def _check_page_count(
    page_counts: Mapping[str, Any],
    expected_keys: set[str],
    key: str,
    count: int,
    *,
    require_total: bool = False,
    required_endpoint: bool = False,
) -> dict[str, Any]:
    expected_keys.add(key)
    entry = page_counts.get(key)
    if not isinstance(entry, dict) or set(entry) != {"pages", "items", "x_total_count"}:
        raise ExportError(f"manifest API page count is invalid: {key}")
    pages = _as_int(entry.get("pages"), label=f"{key} pages")
    items = _as_int(entry.get("items"), label=f"{key} items")
    total = entry.get("x_total_count")
    if total is not None:
        total = _as_int(total, label=f"{key} X-Total-Count")
    if pages < 0 or items < 0 or (total is not None and total < 0):
        raise ExportError(f"manifest API page count is negative: {key}")
    if items != count:
        raise ExportError(f"manifest API item count does not match: {key}")
    if require_total and total != count:
        raise ExportError(f"manifest API total count does not match: {key}")
    if required_endpoint and pages < 1:
        raise ExportError(f"required API endpoint was unavailable: {key}")
    if pages == 0 and (items != 0 or total is not None):
        raise ExportError(f"unavailable API endpoint has inconsistent counts: {key}")
    if pages > 0 and total is not None and total != count:
        raise ExportError(f"manifest API total count does not match: {key}")
    return entry


def _check_endpoint_evidence(
    endpoint_evidence: Mapping[str, Any],
    expected_keys: set[str],
    key: str,
    path: str,
    *,
    kind: str,
    payload: bytes | None,
) -> None:
    expected_keys.add(key)
    expected = (
        _json_evidence(path, payload)
        if kind == "json" and payload is not None
        else _payload_evidence(path, kind=kind, payload=payload)
    )
    if endpoint_evidence.get(key) != expected:
        raise ExportError(f"manifest endpoint evidence does not match: {key}")


def _optional_representation(
    item_dir: Path,
    *,
    payload_name: str,
    marker_name: str,
    label: str,
) -> bytes | None:
    payload_path = item_dir / payload_name
    marker_path = item_dir / marker_name
    payload_exists = payload_path.exists()
    marker_exists = marker_path.exists()
    if payload_exists == marker_exists:
        raise ExportError(f"pull request {label} must have exactly one representation")
    if payload_exists:
        payload = payload_path.read_bytes()
        if not payload:
            raise ExportError(f"pull request {label} payload is empty")
        return payload
    if _json_from_path(marker_path) != UNAVAILABLE_MARKER:
        raise ExportError(f"pull request {label} unavailable marker is invalid")
    return None


def _validate_data(snapshot: Path, manifest: Mapping[str, Any]) -> set[str]:
    source = manifest.get("source")
    if not isinstance(source, dict) or set(source) != {"base_url", "repository"}:
        raise ExportError("manifest source is invalid")
    base_url = source.get("base_url")
    repository = source.get("repository")
    if not isinstance(base_url, str) or not isinstance(repository, str):
        raise ExportError("manifest source is invalid")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ExportError("manifest repository is invalid")
    canonical_base_url = _canonical_gitea_base_url(base_url)
    if base_url != canonical_base_url:
        raise ExportError("manifest Gitea base URL is not canonical")
    source_origin = _origin(canonical_base_url)
    root = f"repos/{repository}"
    semantic_files = {
        "manifest.json",
        "manifest.sha256",
        "repository.bundle",
        "number-plan.json",
        "api/labels.json",
        "api/issues.json",
        "api/pull-requests.json",
        "api/comments.json",
    }

    api_scope = manifest.get("api_scope")
    if not isinstance(api_scope, dict) or set(api_scope) != {
        "page_counts",
        "endpoint_evidence",
        "unavailable_endpoints",
    }:
        raise ExportError("manifest API scope is invalid")
    page_counts = api_scope.get("page_counts")
    endpoint_evidence = api_scope.get("endpoint_evidence")
    unavailable_endpoints = api_scope.get("unavailable_endpoints")
    if not isinstance(page_counts, dict) or not isinstance(endpoint_evidence, dict):
        raise ExportError("manifest API evidence is invalid")
    if not isinstance(unavailable_endpoints, list) or not all(
        isinstance(path, str) for path in unavailable_endpoints
    ):
        raise ExportError("manifest unavailable endpoint list is invalid")

    labels = _require_object_list(
        _json_from_path(snapshot / "api" / "labels.json"), label="label index"
    )
    issues = _require_object_list(
        _json_from_path(snapshot / "api" / "issues.json"), label="issue index"
    )
    pulls = _require_object_list(
        _json_from_path(snapshot / "api" / "pull-requests.json"),
        label="pull request index",
    )
    comments = _require_object_list(
        _json_from_path(snapshot / "api" / "comments.json"), label="comment index"
    )
    plan = _require_object_list(
        _json_from_path(snapshot / "number-plan.json"), label="number plan"
    )
    _unique(labels, "id", "label")
    _unique(issues, "id", "issue")
    _unique(pulls, "id", "pull request")
    _unique(comments, "id", "comment")
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
    canonical_tombstone = {
        "number": TOMBSTONE_NUMBER,
        "type": "tombstone",
        "state": "closed",
        "labels": [],
        "comment_ids": [],
        "asset_uuids": [],
        "reason": TOMBSTONE_REASON,
    }
    if plan_by_number.get(TOMBSTONE_NUMBER) != canonical_tombstone:
        raise ExportError("number plan tombstone is not canonical")
    expected_number_plan = {
        "path": "number-plan.json",
        "minimum": 1,
        "maximum": max(all_numbers),
        "tombstone": TOMBSTONE_NUMBER,
        "strategy": "strictly ascending; stop on first destination number mismatch",
    }
    if manifest.get("number_plan") != expected_number_plan:
        raise ExportError("manifest number plan metadata is invalid")

    expected_page_keys: set[str] = set()
    expected_endpoint_keys: set[str] = set()
    expected_unavailable: set[str] = set()

    def check_page_pair(
        suffix: str,
        count: int,
        *,
        path: str,
        require_total: bool = False,
        required_endpoint: bool = False,
    ) -> None:
        entries = [
            _check_page_count(
                page_counts,
                expected_page_keys,
                f"{prefix}.{suffix}",
                count,
                require_total=require_total,
                required_endpoint=required_endpoint,
            )
            for prefix in ("initial", "confirmation")
        ]
        if entries[0] != entries[1]:
            raise ExportError(f"API page evidence changed during export: {suffix}")
        if entries[0]["pages"] == 0:
            expected_unavailable.add(path)

    expected_counts_without_assets = {
        "issues": len(issues),
        "pull_requests": len(pulls),
        "comments": len(comments),
        "labels": len(labels),
    }
    for suffix, count_key, path in (
        ("labels", "labels", f"{root}/labels"),
        ("issues", "issues", f"{root}/issues"),
        ("pull_requests", "pull_requests", f"{root}/pulls"),
        ("comments", "comments", f"{root}/issues/comments"),
    ):
        check_page_pair(
            suffix,
            expected_counts_without_assets[count_key],
            path=path,
            require_total=True,
            required_endpoint=True,
        )

    per_item_comments: dict[int, dict[str, Any]] = {}
    per_item_comment_parents: dict[int, dict[str, Any]] = {}
    canonical_assets: dict[str, dict[str, Any]] = {}
    issue_index = {item["number"]: item for item in issues}
    pull_index = {item["number"]: item for item in pulls}
    for number in sorted(issue_numbers | pull_numbers):
        item_dir = snapshot / "items" / str(number)
        item_prefix = f"items/{number}"
        semantic_files.update(
            {
                f"{item_prefix}/issue.json",
                f"{item_prefix}/comments.json",
                f"{item_prefix}/assets.json",
            }
        )
        detail = _json_from_path(item_dir / "issue.json")
        item_comments = _require_object_list(
            _json_from_path(item_dir / "comments.json"),
            label=f"item {number} comments",
        )
        item_assets = _require_object_list(
            _json_from_path(item_dir / "assets.json"),
            label=f"item {number} assets",
        )
        if not isinstance(detail, dict):
            raise ExportError(f"item {number} detail is invalid")
        if _as_int(detail.get("number"), label="item detail number") != number:
            raise ExportError(f"item {number} detail number does not match")
        issue_path = f"{root}/issues/{number}"
        for prefix in ("initial", "confirmation"):
            _check_endpoint_evidence(
                endpoint_evidence,
                expected_endpoint_keys,
                f"{prefix}.item.{number}.issue",
                issue_path,
                kind="json",
                payload=_canonical_json(detail),
            )
        comment_ids = _unique(item_comments, "id", f"item {number} comment")
        if set(per_item_comments) & comment_ids:
            raise ExportError("a comment is stored under more than one item")
        parent_kind = "issue" if number in issue_index else "pull_request"
        for comment in item_comments:
            comment_id = _as_int(comment.get("id"), label=f"item {number} comment id")
            per_item_comments[comment_id] = comment
            per_item_comment_parents[comment_id] = {
                "kind": parent_kind,
                "origin": base_url,
                "repository": repository,
                "number": number,
            }
        _unique(item_assets, "id", f"item {number} asset")
        for item_asset in item_assets:
            _asset_identity(item_asset, source_origin)
        check_page_pair(
            f"item.{number}.comments",
            len(item_comments),
            path=f"{issue_path}/comments",
            required_endpoint=True,
        )
        check_page_pair(
            f"item.{number}.assets",
            len(item_assets),
            path=f"{issue_path}/assets",
        )

        asset_sources: list[Any] = [detail, item_comments, item_assets]
        if number in issue_index:
            if detail.get("id") != issue_index[number].get("id"):
                raise ExportError(f"issue {number} detail ID does not match its index")
            if detail.get("state") not in {"open", "closed"}:
                raise ExportError(f"issue {number} has an invalid state")
            expected_entry: dict[str, Any] = {
                "number": number,
                "type": "issue",
                "state": detail["state"],
                "labels": _extract_labels(detail),
                "comment_ids": sorted(comment_ids),
            }
        else:
            semantic_files.update(
                {
                    f"{item_prefix}/pull.json",
                    f"{item_prefix}/pull-metadata.json",
                    f"{item_prefix}/commits.json",
                    f"{item_prefix}/files.json",
                    f"{item_prefix}/reviews.json",
                    f"{item_prefix}/review-comments.json",
                    f"{item_prefix}/status.json",
                }
            )
            pull = _json_from_path(item_dir / "pull.json")
            metadata = _json_from_path(item_dir / "pull-metadata.json")
            commits = _require_object_list(
                _json_from_path(item_dir / "commits.json"),
                label=f"pull request {number} commits",
            )
            files = _require_object_list(
                _json_from_path(item_dir / "files.json"),
                label=f"pull request {number} files",
            )
            reviews = _require_object_list(
                _json_from_path(item_dir / "reviews.json"),
                label=f"pull request {number} reviews",
            )
            review_comments = _json_from_path(item_dir / "review-comments.json")
            status_payload = _json_from_path(item_dir / "status.json")
            if not isinstance(pull, dict) or not isinstance(metadata, dict):
                raise ExportError(f"pull request {number} data is invalid")
            if pull.get("state") != "closed":
                raise ExportError(f"pull request {number} is not a closed legacy item")
            if pull.get("id") != pull_index[number].get("id"):
                raise ExportError(f"pull request {number} detail ID does not match its index")
            if _as_int(pull.get("number"), label="pull request number") != number:
                raise ExportError(f"pull request {number} detail number does not match")
            expected_metadata = _pull_metadata(pull)
            if metadata != expected_metadata or set(metadata) != {
                "state",
                "merged",
                "merged_at",
                "merge_commit_sha",
                "base_ref",
                "base_sha",
                "head_ref",
                "head_sha",
            }:
                raise ExportError(f"pull request {number} metadata does not match")
            if not isinstance(metadata.get("merged"), bool):
                raise ExportError(f"pull request {number} merge metadata is invalid")
            for field in ("base_ref", "head_ref"):
                if not isinstance(metadata.get(field), str) or not metadata[field]:
                    raise ExportError(f"pull request {number} {field} is invalid")
            for field in ("base_sha", "head_sha"):
                _require_git_sha(
                    metadata.get(field), label=f"pull request {number} {field}"
                )
            merge_commit_sha = metadata.get("merge_commit_sha")
            if merge_commit_sha is not None:
                _require_git_sha(
                    merge_commit_sha,
                    label=f"pull request {number} merge commit SHA",
                )

            _unique_text(
                commits, "sha", f"pull request {number} commit", git_sha=True
            )
            _unique_text(files, "filename", f"pull request {number} file")
            review_ids = _unique(reviews, "id", f"pull request {number} review")
            if not isinstance(review_comments, dict) or set(review_comments) != {
                str(review_id) for review_id in review_ids
            }:
                raise ExportError(f"pull request {number} review comments are incomplete")
            seen_review_comment_ids: set[int] = set()
            for review_id in sorted(review_ids):
                review_comment_list = _require_object_list(
                    review_comments[str(review_id)],
                    label=f"pull request {number} review {review_id} comments",
                )
                comment_identity = _unique(
                    review_comment_list,
                    "id",
                    f"pull request {number} review comment",
                )
                if seen_review_comment_ids & comment_identity:
                    raise ExportError(
                        f"pull request {number} contains a duplicate review comment ID"
                    )
                seen_review_comment_ids.update(comment_identity)

            head_sha = metadata["head_sha"]
            if status_payload == UNAVAILABLE_MARKER:
                status_bytes = None
            else:
                if (
                    not isinstance(status_payload, dict)
                    or not isinstance(status_payload.get("state"), str)
                    or status_payload.get("sha") != head_sha
                ):
                    raise ExportError(f"pull request {number} status payload is invalid")
                status_bytes = _canonical_json(status_payload)
            diff = _optional_representation(
                item_dir,
                payload_name="pull.diff",
                marker_name="diff.unavailable.json",
                label=f"{number} diff",
            )
            patch = _optional_representation(
                item_dir,
                payload_name="pull.patch",
                marker_name="patch.unavailable.json",
                label=f"{number} patch",
            )
            semantic_files.add(
                f"{item_prefix}/pull.diff"
                if diff is not None
                else f"{item_prefix}/diff.unavailable.json"
            )
            semantic_files.add(
                f"{item_prefix}/pull.patch"
                if patch is not None
                else f"{item_prefix}/patch.unavailable.json"
            )

            pull_path = f"{root}/pulls/{number}"
            for prefix in ("initial", "confirmation"):
                _check_endpoint_evidence(
                    endpoint_evidence,
                    expected_endpoint_keys,
                    f"{prefix}.pull.{number}.detail",
                    pull_path,
                    kind="json",
                    payload=_canonical_json(pull),
                )
                for suffix, path, kind, payload in (
                    ("status", f"{root}/commits/{head_sha}/status", "json", status_bytes),
                    ("diff", f"{pull_path}.diff", "bytes", diff),
                    ("patch", f"{pull_path}.patch", "bytes", patch),
                ):
                    _check_endpoint_evidence(
                        endpoint_evidence,
                        expected_endpoint_keys,
                        f"{prefix}.pull.{number}.{suffix}",
                        path,
                        kind=kind,
                        payload=payload,
                    )
            for path, payload in (
                (f"{root}/commits/{head_sha}/status", status_bytes),
                (f"{pull_path}.diff", diff),
                (f"{pull_path}.patch", patch),
            ):
                if payload is None:
                    expected_unavailable.add(path)

            for suffix, values, path in (
                ("commits", commits, f"{pull_path}/commits"),
                ("files", files, f"{pull_path}/files"),
                ("reviews", reviews, f"{pull_path}/reviews"),
            ):
                check_page_pair(
                    f"pull.{number}.{suffix}", len(values), path=path
                )
            for review_id in sorted(review_ids):
                check_page_pair(
                    f"pull.{number}.review.{review_id}.comments",
                    len(review_comments[str(review_id)]),
                    path=f"{pull_path}/reviews/{review_id}/comments",
                )

            expected_entry = {
                "number": number,
                "type": "legacy-pr",
                "state": "closed",
                "labels": sorted(set([*_extract_labels(detail), "legacy-pr"])),
                "comment_ids": sorted(comment_ids),
                "pull": metadata,
            }
            asset_sources.extend(
                [pull, commits, files, reviews, review_comments, status_payload]
            )

        item_asset_ids: set[str] = set()
        for asset_source in asset_sources:
            for asset in _asset_candidates(asset_source):
                identity = _asset_identity(asset, source_origin)
                _merge_asset_identity(canonical_assets, identity)
                item_asset_ids.add(identity["uuid"])
        expected_entry["asset_uuids"] = sorted(item_asset_ids)
        if plan_by_number[number] != expected_entry:
            raise ExportError(f"item {number} number plan does not match captured data")

    _reconcile_comment_parents(comments, per_item_comments, per_item_comment_parents)

    expected_mappings: list[dict[str, Any]] = []
    for identity in sorted(canonical_assets.values(), key=lambda item: item["uuid"]):
        asset_path = snapshot / identity["path"]
        if not asset_path.is_file() or asset_path.is_symlink():
            raise ExportError("canonical asset file is missing")
        expected_mappings.append(
            {
                **identity,
                "github_url": None,
                "size": asset_path.stat().st_size,
                "sha256": _sha256(asset_path),
            }
        )
        semantic_files.add(identity["path"])
    mappings = manifest.get("asset_rewrite_mapping")
    if mappings != expected_mappings:
        raise ExportError("manifest asset mapping does not match captured API objects")

    if set(page_counts) != expected_page_keys:
        raise ExportError("manifest API page evidence key set is incomplete or excessive")
    if set(endpoint_evidence) != expected_endpoint_keys:
        raise ExportError("manifest endpoint evidence key set is incomplete or excessive")
    if unavailable_endpoints != sorted(expected_unavailable):
        raise ExportError("manifest unavailable endpoint list does not reconcile")

    index_payload = {
        "labels": labels,
        "issues": issues,
        "pull_requests": pulls,
        "comments": comments,
    }
    index_digest = _semantic_digest(_project_indexes(index_payload))
    item_digest = _semantic_digest(
        _project_captured_items(snapshot, index_payload, plan, expected_mappings)
    )
    payload_proof = _captured_payload_proof(snapshot)
    expected_consistency = {
        "projection_version": SEMANTIC_PROJECTION_VERSION,
        "indexes": {
            "initial_sha256": index_digest,
            "confirmation_sha256": index_digest,
        },
        "items": {
            "initial_sha256": item_digest,
            "confirmation_sha256": item_digest,
        },
        "initial_raw_payload": payload_proof,
    }
    if manifest.get("capture_consistency") != expected_consistency:
        raise ExportError("manifest capture consistency proof is invalid")

    counts = manifest.get("counts")
    if not isinstance(counts, dict) or set(counts) != {
        "baseline",
        "current",
        "reconciliation",
    }:
        raise ExportError("manifest count evidence is invalid")
    expected_counts = {
        **expected_counts_without_assets,
        "assets": len(expected_mappings),
    }
    if counts.get("baseline") != BASELINE_COUNTS or counts.get("current") != expected_counts:
        raise ExportError("manifest current counts do not match snapshot data")
    reconciliation = counts.get("reconciliation")
    if not isinstance(reconciliation, dict) or set(reconciliation) != set(COUNT_KEYS):
        raise ExportError("manifest count reconciliation is invalid")
    for key, count in expected_counts.items():
        entry = reconciliation.get(key)
        if not isinstance(entry, dict) or set(entry) != {
            "baseline",
            "current",
            "delta",
            "explanation",
        }:
            raise ExportError(f"manifest reconciliation for {key} is invalid")
        if entry.get("baseline") != BASELINE_COUNTS[key] or entry.get("current") != count:
            raise ExportError(f"manifest reconciliation for {key} is invalid")
        if entry.get("delta") != count - BASELINE_COUNTS[key]:
            raise ExportError(f"manifest reconciliation delta for {key} is invalid")
        if entry["delta"] and not str(entry.get("explanation", "")).strip():
            raise ExportError(f"manifest reconciliation for {key} is unexplained")
    return semantic_files


def _validate_snapshot(
    snapshot: Path,
    token: bytes,
    *,
    expected_manifest_sha256: str,
    allow_staging_name: bool,
) -> dict[str, Any]:
    pinned_manifest_sha256 = _require_sha256(
        expected_manifest_sha256, label="expected manifest SHA-256"
    )
    if snapshot.is_symlink():
        raise ExportError("snapshot directory must not be a symlink")
    snapshot = snapshot.resolve()
    if not snapshot.is_dir():
        raise ExportError("snapshot directory does not exist")
    manifest_path = snapshot / "manifest.json"
    try:
        manifest_metadata = manifest_path.lstat()
    except OSError as exc:
        raise ExportError("manifest file does not exist") from exc
    if not stat.S_ISREG(manifest_metadata.st_mode):
        raise ExportError("manifest file is not a regular file")
    actual_manifest_sha256 = _sha256(manifest_path)
    if actual_manifest_sha256 != pinned_manifest_sha256:
        raise ExportError("manifest does not match the externally pinned SHA-256")
    _check_permissions(snapshot)
    sidecar_path = snapshot / "manifest.sha256"
    manifest = _json_from_path(manifest_path)
    if (
        not isinstance(manifest, dict)
        or manifest.get("format_version") != FORMAT_VERSION
        or set(manifest)
        != {
            "format_version",
            "source",
            "exported_at",
            "snapshot_name",
            "api_scope",
            "main_sha",
            "refs",
            "counts",
            "asset_rewrite_mapping",
            "number_plan",
            "capture_consistency",
            "file_inventory",
        }
    ):
        raise ExportError("unsupported or invalid manifest format")
    try:
        sidecar = sidecar_path.read_text(encoding="ascii")
    except (OSError, UnicodeDecodeError) as exc:
        raise ExportError("manifest checksum sidecar is invalid") from exc
    expected_sidecar = f"{actual_manifest_sha256}  manifest.json\n"
    if sidecar != expected_sidecar:
        raise ExportError("manifest checksum does not match")
    exported_at = manifest.get("exported_at")
    main_sha = _require_git_sha(manifest.get("main_sha"), label="manifest main SHA")
    if not isinstance(exported_at, str) or re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
        exported_at,
    ) is None:
        raise ExportError("manifest export time is invalid")
    try:
        parsed_time = datetime.strptime(exported_at, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=UTC
        )
    except ValueError as exc:
        raise ExportError("manifest export time is invalid") from exc
    expected_snapshot_name = (
        f"{parsed_time.strftime('%Y%m%dT%H%M%SZ')}-{main_sha[:12]}"
    )
    if manifest.get("snapshot_name") != expected_snapshot_name:
        raise ExportError("manifest snapshot name does not match time and main SHA")
    staging_pattern = re.fullmatch(
        rf"\.{re.escape(expected_snapshot_name)}\.tmp-[0-9a-f]{{32}}", snapshot.name
    )
    if snapshot.name != expected_snapshot_name and not (
        allow_staging_name and staging_pattern is not None
    ):
        raise ExportError("snapshot directory name does not match the manifest")
    inventory = manifest.get("file_inventory")
    if not isinstance(inventory, list):
        raise ExportError("manifest file inventory is invalid")
    inventory_paths: set[str] = set()
    for entry in inventory:
        if not isinstance(entry, dict) or set(entry) != {"path", "size", "sha256"}:
            raise ExportError("manifest inventory entry is invalid")
        relative = entry.get("path")
        size = entry.get("size")
        digest = entry.get("sha256")
        pure_path = PurePosixPath(relative) if isinstance(relative, str) else None
        if (
            not isinstance(relative, str)
            or relative.startswith("/")
            or "\\" in relative
            or pure_path is None
            or pure_path.as_posix() != relative
            or not pure_path.parts
            or any(part in {"", ".", ".."} for part in pure_path.parts)
            or relative in inventory_paths
            or isinstance(size, bool)
            or not isinstance(size, int)
            or size < 0
            or not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        ):
            raise ExportError("manifest inventory path is invalid or duplicated")
        inventory_paths.add(relative)
        path = snapshot / relative
        if not path.is_file() or path.is_symlink():
            raise ExportError(f"inventoried file is missing: {relative}")
        if path.stat().st_size != size or _sha256(path) != digest:
            raise ExportError(f"inventoried file failed size/hash validation: {relative}")
    actual_files = {
        path.relative_to(snapshot).as_posix() for path in snapshot.rglob("*") if path.is_file()
    }
    if token:
        for relative in sorted(actual_files):
            if token in (snapshot / relative).read_bytes():
                raise ExportError(f"exact token found in snapshot file: {relative}")
    semantic_files = _validate_data(snapshot, manifest)
    semantic_inventory = semantic_files - {"manifest.json", "manifest.sha256"}
    if inventory_paths != semantic_inventory:
        missing = sorted(semantic_inventory - inventory_paths)
        extra = sorted(inventory_paths - semantic_inventory)
        raise ExportError(
            f"manifest inventory semantic set mismatch: missing={missing[:3]} "
            f"extra={extra[:3]}"
        )
    if actual_files != semantic_files:
        missing = sorted(semantic_files - actual_files)
        extra = sorted(actual_files - semantic_files)
        raise ExportError(f"snapshot file set mismatch: missing={missing[:3]} extra={extra[:3]}")
    expected_dirs = {"."}
    for relative in semantic_files:
        parent = PurePosixPath(relative).parent
        while parent.as_posix() != ".":
            expected_dirs.add(parent.as_posix())
            parent = parent.parent
    actual_dirs = {
        path.relative_to(snapshot).as_posix()
        for path in snapshot.rglob("*")
        if path.is_dir() and not path.is_symlink()
    }
    actual_dirs.add(".")
    if actual_dirs != expected_dirs:
        missing = sorted(expected_dirs - actual_dirs)
        extra = sorted(actual_dirs - expected_dirs)
        raise ExportError(
            f"snapshot directory set mismatch: missing={missing[:3]} extra={extra[:3]}"
        )
    _validate_bundle(snapshot, manifest)
    return manifest


def validate_snapshot(
    snapshot: Path,
    token: bytes,
    *,
    expected_manifest_sha256: str,
) -> dict[str, Any]:
    """Validate a finalized snapshot against an externally held manifest digest."""

    return _validate_snapshot(
        snapshot,
        token,
        expected_manifest_sha256=expected_manifest_sha256,
        allow_staging_name=False,
    )


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
) -> ExportResult:
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
            prefix="initial",
        )
        initial_payload_proof = _captured_payload_proof(staging)
        _write_json(staging / "number-plan.json", number_plan)
        initial_index_projection = _project_indexes(initial_indexes)
        initial_item_projection = _project_captured_items(
            staging,
            initial_indexes,
            number_plan,
            asset_mapping,
        )
        initial_index_digest = _semantic_digest(initial_index_projection)
        initial_item_digest = _semantic_digest(initial_item_projection)
        current_counts = {
            "issues": len(initial_indexes["issues"]),
            "pull_requests": len(initial_indexes["pull_requests"]),
            "comments": len(initial_indexes["comments"]),
            "labels": len(initial_indexes["labels"]),
            "assets": len(asset_mapping),
        }
        reconciliation = _load_reconciliation(reconciliation_path, current_counts)

        confirmed_indexes = _capture_indexes(client, repository, prefix="confirmation")
        confirmed_index_projection = _project_indexes(confirmed_indexes)
        confirmed_index_digest = _semantic_digest(confirmed_index_projection)
        if initial_index_digest != confirmed_index_digest:
            raise ExportError("Gitea index changed during export")
        confirmation = staging / ".confirmation"
        confirmation.mkdir(mode=0o700)
        confirmed_plan, confirmed_asset_mapping = _capture_items(
            client,
            repository,
            confirmed_indexes,
            confirmation,
            prefix="confirmation",
        )
        confirmed_item_projection = _project_captured_items(
            confirmation,
            confirmed_indexes,
            confirmed_plan,
            confirmed_asset_mapping,
        )
        confirmed_item_digest = _semantic_digest(confirmed_item_projection)
        if initial_item_digest != confirmed_item_digest:
            raise ExportError("Gitea captured item data changed during export")
        shutil.rmtree(confirmation)
        confirmed_refs = _resolve_refs(git_repository, main_ref, archive_ref)
        if confirmed_refs != initial_refs:
            raise ExportError("Git refs changed during export")
        _create_bundle(git_repository, staging, initial_refs)
        final_refs = _resolve_refs(git_repository, main_ref, archive_ref)
        if final_refs != initial_refs:
            raise ExportError("Git refs changed while creating the bundle")

        manifest: dict[str, Any] = {
            "format_version": FORMAT_VERSION,
            "source": {"base_url": client.base_url, "repository": repository},
            "exported_at": timestamp.isoformat().replace("+00:00", "Z"),
            "snapshot_name": final_name,
            "api_scope": {
                "page_counts": client.page_counts,
                "endpoint_evidence": client.endpoint_evidence,
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
            "capture_consistency": {
                "projection_version": SEMANTIC_PROJECTION_VERSION,
                "indexes": {
                    "initial_sha256": initial_index_digest,
                    "confirmation_sha256": confirmed_index_digest,
                },
                "items": {
                    "initial_sha256": initial_item_digest,
                    "confirmation_sha256": confirmed_item_digest,
                },
                "initial_raw_payload": initial_payload_proof,
            },
        }
        manifest["file_inventory"] = _inventory(staging)
        _write_json(staging / "manifest.json", manifest)
        manifest_hash = _sha256(staging / "manifest.json")
        _write_bytes(
            staging / "manifest.sha256",
            f"{manifest_hash}  manifest.json\n".encode("ascii"),
        )
        _validate_snapshot(
            staging,
            token,
            expected_manifest_sha256=manifest_hash,
            allow_staging_name=True,
        )
        _rename_noreplace(staging, final_path)
        staging = None
        return ExportResult(path=final_path, manifest_sha256=manifest_hash)
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
    validate.add_argument(
        "--expected-manifest-sha256",
        required=True,
        help="externally pinned SHA-256 of manifest.json",
    )
    validate.add_argument("snapshot", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        token = _read_token()
        if args.command == "export":
            result = export_snapshot(
                base_url=args.base_url,
                repository=args.repository,
                destination_root=args.destination_root,
                git_repository=args.git_repository,
                main_ref=args.main_ref,
                archive_ref=args.archive_ref,
                reconciliation_path=args.reconciliation,
                token=token,
            )
            print(f"export={result.path}")
            print(f"manifest_sha256={result.manifest_sha256}")
        else:
            manifest = validate_snapshot(
                args.snapshot,
                token,
                expected_manifest_sha256=args.expected_manifest_sha256,
            )
            print(f"validation=passed main_sha={manifest['main_sha']}")
        return 0
    except ExportError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
