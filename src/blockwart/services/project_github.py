"""Opt-in, bounded GET-only GitHub observations; never writes external state.

Only api.github.com is contacted, redirects/proxies are disabled, and response
bodies, tokens and transport exception text never enter project events.
"""

from __future__ import annotations

import json
import re
import time
from datetime import UTC, datetime

from blockwart.config import Settings
from blockwart.domain.auth import Permission
from blockwart.domain.monitoring_policy import pin_address
from blockwart.domain.timestamps import format_rfc3339_utc
from blockwart.models import CatalogObject
from blockwart.services.commands import (
    CommandPreconditionFailed,
    CommandValidationFailed,
    authorize_object_command,
    refresh_write_context,
)
from blockwart.services.monitoring_gatus import _CREDENTIAL_UNREADABLE, _read_credential
from blockwart.services.project_workspace import _record, _visible_ref
from blockwart.services.read_access import ReadAccess
from blockwart.services.release_github import (
    _PUBLIC_HTTPS_POLICY,
    _GithubFailure,
    _header,
    _request,
    _resolve,
)

MAX_RESPONSE_BYTES = 512 * 1024


class ObservationError(Exception):
    pass


def _github_get(path, token, *, timeout):
    if not re.fullmatch(r"/[a-zA-Z0-9_./-]+", path) or "/../" in path:
        raise ObservationError("invalid_target")
    started = time.monotonic()
    try:
        addresses = _resolve("api.github.com", 443, timeout=timeout)
        if _PUBLIC_HTTPS_POLICY.check_target(scheme="https", port=443, addresses=addresses):
            raise ObservationError("policy_denied")
        pinned = pin_address(addresses)
        remaining = timeout - (time.monotonic() - started)
        if pinned is None or remaining <= 0:
            raise ObservationError("transport_failed")
        status, headers, body = _request(
            pinned=str(pinned),
            path=path,
            etag=None,
            connect_timeout=remaining,
            total_timeout=remaining,
            max_response_bytes=MAX_RESPONSE_BYTES,
            bearer_token=token,
        )
        if status != 200:
            code = (
                "rate_limited"
                if status == 429
                or (
                    status == 403
                    and (
                        _header(headers, "x-ratelimit-remaining") == "0"
                        or _header(headers, "retry-after")
                    )
                )
                else {
                    401: "authentication_failed",
                    403: "access_denied",
                    404: "not_found_or_concealed",
                }.get(status, "redirect_rejected" if 300 <= status < 400 else "upstream_failed")
            )
            raise ObservationError(code)
        data = json.loads(body)
        if not isinstance(data, dict):
            raise ObservationError("invalid_response")
        return data
    except _GithubFailure as exc:
        raise ObservationError(exc.code) from None
    except (TimeoutError, OSError):
        raise ObservationError("transport_failed") from None
    except (json.JSONDecodeError, UnicodeError):
        raise ObservationError("invalid_response") from None


def _credential(
    settings, session, context, repository, *, project_instance_id, repository_record_id
):
    ref = repository.get("credential_reference")
    if not ref:
        return None  # explicitly anonymous public-only access
    if not _visible_ref(session, ReadAccess(context.principal, context.policy), ref):
        raise ObservationError("credential_not_accessible")
    # Metadata readability is not authority to use a deployment credential.
    # Bind the operator's approval to the immutable project/repository instance,
    # numeric upstream repository and exact credential reference. No global-ref fallback.
    source = f"{project_instance_id}/{repository_record_id}/{repository['github_id']}/{ref}"
    filename = settings.project_github_credential_files.get(source)
    if not filename:
        raise ObservationError("credential_not_configured")
    # Visibility lookup may have opened a read transaction. Acquisition itself
    # must remain outside it; the next GET has its own current-authority gate.
    session.commit()
    try:
        token = _read_credential(filename, timeout=0.5)
    except TimeoutError:
        raise ObservationError("credential_unavailable") from None
    if token is _CREDENTIAL_UNREADABLE or not token:
        raise ObservationError("credential_unavailable")
    return token


def _current_sync_authority(session, context, project, item, credential_reference=None):
    """Short current-authority/source gate, committed before credential/network I/O."""
    current = refresh_write_context(session, context, object_id=project.id)
    authorize_object_command(session, current, object_id=project.id, permission=Permission.WRITE)
    live = session.get(CatalogObject, project.id)
    if live.instance_id != project.instance_id or live.revision != project.revision:
        raise CommandPreconditionFailed("Project changed during GitHub acquisition")
    if _record(session, live, item.id).version != item.version:
        raise CommandPreconditionFailed("Record changed during GitHub acquisition")
    if credential_reference and not _visible_ref(
        session, ReadAccess(current.principal, current.policy), credential_reference,
    ):
        raise ObservationError("credential_not_accessible")
    session.commit()
    return current


def sync_record(session, context, project, row):
    data = json.loads(row.data_json)
    if row.kind != "item" or data.get("item_type") != "task":
        raise CommandValidationFailed("GitHub observations belong to a task")
    refs = data.get("github_references", [])
    if not refs:
        raise CommandValidationFailed("Link GitHub references before requesting an observation")
    settings = Settings()
    deadline = time.monotonic() + 8.0
    observations = []
    metadata = {}
    for ref in refs:
        observed = {"reference": ref, "ok": False}
        try:
            context = _current_sync_authority(session, context, project, row)
            repo_row = _record(session, project, ref["repository_id"])
            repository = json.loads(repo_row.data_json)
            repository_version = repo_row.version
            repository_id = repo_row.id
            session.commit()
            if not settings.project_github_sync_enabled or not repository.get("sync_enabled"):
                raise ObservationError("sync_disabled")
            if not repository.get("github_id"):
                raise ObservationError("stable_repository_id_required")
            if time.monotonic() >= deadline:
                raise ObservationError("budget_exhausted")
            identity = ref["repository_id"]
            if identity not in metadata:
                context = _current_sync_authority(
                    session, context, project, row, repository.get("credential_reference"),
                )
                token = _credential(
                    settings,
                    session,
                    context,
                    repository,
                    project_instance_id=project.instance_id,
                    repository_record_id=repository_id,
                )
                session.commit()
                context = _current_sync_authority(
                    session, context, project, row, repository.get("credential_reference"),
                )
                meta = _github_get(
                    f"/repositories/{repository['github_id']}",
                    token,
                    timeout=max(0.1, min(3.0, deadline - time.monotonic())),
                )
                full_name = meta.get("full_name", "")
                if (
                    meta.get("id") != repository["github_id"]
                    or not isinstance(full_name, str)
                    or not re.fullmatch(r"[a-zA-Z0-9_.-]{1,100}/[a-zA-Z0-9_.-]{1,100}", full_name)
                ):
                    raise ObservationError("repository_identity_mismatch")
                metadata[identity] = (meta, token)
            meta, token = metadata[identity]
            if time.monotonic() >= deadline:
                raise ObservationError("budget_exhausted")
            suffix = {"issue": "issues", "pull": "pulls", "commit": "commits"}[ref["kind"]]
            object_key = ref.get("number") or ref.get("sha")
            context = _current_sync_authority(
                session, context, project, row, repository.get("credential_reference"),
            )
            result = _github_get(
                f"/repos/{meta['full_name']}/{suffix}/{object_key}",
                token,
                timeout=max(0.1, min(3.0, deadline - time.monotonic())),
            )
            if ref["kind"] in {"issue", "pull"} and (
                result.get("number") != ref["number"]
                or result.get("state") not in {"open", "closed"}
                or (ref["kind"] == "issue" and result.get("pull_request"))
            ):
                raise ObservationError("object_identity_mismatch")
            if ref["kind"] == "commit" and result.get("sha") != ref["sha"]:
                raise ObservationError("object_identity_mismatch")
            web_kind = "issues" if ref["kind"] == "issue" else ref["kind"]
            observed.update(
                ok=True,
                repository_record_version=repository_version,
                repository_github_id=meta["id"],
                repository_full_name=meta["full_name"],
                private=bool(meta.get("private")),
                state=result.get("state", "present"),
                merged=bool(result.get("merged", False)),
                url=f"https://github.com/{meta['full_name']}/{web_kind}/{object_key}",
            )
        except ObservationError as exc:
            session.rollback()
            observed["error"] = str(exc)
        observations.append(observed)
    return {
        "observed_at": format_rfc3339_utc(datetime.now(UTC)),
        "status_authority": data.get("status_authority", "local"),
        "leading_reference": data.get("leading_reference"),
        "observations": observations,
    }


def external_state(events, data):
    """Failures keep last success separately; closure never changes local status."""
    observations = [json.loads(e.data_json) for e in events if e.kind == "sync_github"]
    last = observations[-1] if observations else None
    leading = data.get("leading_reference")
    last_success = next(
        (o for o in reversed(observations) if all(item["ok"] for item in o["observations"])), None
    )
    current = next(
        (o for o in (last or {}).get("observations", []) if o["reference"] == leading), None
    )
    fresh = bool(
        last
        and (
            current and current["ok"]
            if data.get("status_authority") == "github"
            else all(o["ok"] for o in last["observations"])
        )
    )
    if last and [o["reference"] for o in last["observations"]] != data.get("github_references", []):
        fresh = False
    if fresh:
        age = (
            datetime.now(UTC) - datetime.fromisoformat(last["observed_at"].replace("Z", "+00:00"))
        ).total_seconds()
        fresh = age <= 900
    return {
        "last_attempt": last,
        "last_success": last_success,
        "fresh": fresh,
        "effective_status": ("done" if current["state"] == "closed" else "open")
        if data.get("status_authority") == "github" and current and current["ok"] and fresh
        else data.get("status")
        if data.get("status_authority", "local") == "local"
        else None,
    }
