"""The field-level boundary for existing credential-reference locators.

This does not change the stored schema. Metadata and protected content travel
through the same object and ordinary grants, but only the explicit content
capabilities authorize the top-level ``data.reference`` subtree.
"""
from __future__ import annotations

from collections.abc import Collection, Mapping
from copy import deepcopy
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from blockwart.domain.auth import Permission
from blockwart.models import AuditEvent
from blockwart.services.policy import PolicySnapshot

REFERENCE_KIND = "credential_reference"


def authorized_reference_data(
    kind: str,
    object_id: str,
    data: Mapping[str, Any],
    policy: PolicySnapshot,
) -> dict[str, Any]:
    """Return a detached read document, omitting protected content if denied."""
    result = dict(data)
    if kind == REFERENCE_KIND and not policy.can(Permission.READ_REFERENCE_CONTENT, object_id):
        result.pop("reference", None)
    return result


def reference_audit_details(details: Mapping[str, Any]) -> dict[str, Any]:
    """Project historical reference events for a metadata-only reader.

    Historical/legacy event shapes are not a second read channel. Only known
    control metadata and structured snapshots/changes are published; free-form
    legacy summaries cannot be classified safely and are replaced.
    """
    safe_keys = {
        "event", "version", "principal_id", "principal_login", "channel", "request_id",
        "old_revision", "new_revision", "object_ref", "service_ref", "link_path",
        "target_principal_id", "grant_id", "role", "scope", "creator_owner_grant",
        "affected_revisions", "old_label", "new_label", "catalog_authority",
    }
    result = {key: deepcopy(value) for key, value in details.items() if key in safe_keys}
    if details.get("event") == "legacy":
        result["legacy_summary"] = "Credential reference changed"
    for key in ("before", "after"):
        snapshot = details.get(key)
        if isinstance(snapshot, Mapping):
            projected = {
                name: deepcopy(value) for name, value in snapshot.items()
                if name in {"id", "kind", "label", "status", "lifecycle", "health", "summary"}
            }
            data = snapshot.get("data")
            if isinstance(data, Mapping):
                projected["data"] = _without_reference_branches(data)
            # Corrupt/legacy scalar data cannot be divided into field classes.
            # Omit it instead of treating an unknown document as metadata.
            result[key] = projected
    changes = details.get("changes")
    if isinstance(changes, list):
        projected_changes = []
        reference_changed = details.get("reference_content_replaced") is True
        for change in changes:
            if not isinstance(change, Mapping):
                continue
            field = change.get("field")
            if not isinstance(field, str):
                continue
            path = _audit_field_path(field)
            if _reference_path(path) or path in {"", "data", "object"}:
                reference_changed = True
            else:
                projected_changes.append({
                    name: _without_reference_branches(value)
                    for name, value in change.items()
                    if name in {"field", "value_change", "old", "new", "before", "after"}
                })
        if reference_changed:
            # One opaque intent, not the number/shape/equality of hidden leaves.
            projected_changes.append({"field": "reference", "value_change": False})
        result["changes"] = projected_changes
    return result


def _audit_field_path(field: str) -> str:
    return field.lstrip("/").replace("/", ".")


def _reference_path(path: str) -> bool:
    path = path.removeprefix("data.")
    return path == "reference" or path.startswith("reference.")


def _without_reference_branches(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {name: _without_reference_branches(item) for name, item in value.items()
                if name != "reference"}
    if isinstance(value, list):
        return [_without_reference_branches(item) for item in value]
    return deepcopy(value)


def _contains_reference_history(value: Any) -> bool:
    if isinstance(value, Mapping):
        return (
            value.get("kind") == REFERENCE_KIND
            or "reference" in value
            or any(_contains_reference_history(item) for item in value.values())
        )
    return isinstance(value, list) and any(_contains_reference_history(item) for item in value)


def reference_audit_requires_projection(
    kind: str, details: Mapping[str, Any], *, was_reference: bool = False,
) -> bool:
    """Classify historical fields even when old snapshots omit their own kind."""
    if kind == REFERENCE_KIND or _contains_reference_history(details):
        return True
    if str(details.get("object_ref", "")).startswith(f"{REFERENCE_KIND}:"):
        return True
    if was_reference and (
        details.get("event") == "legacy"
        or any(key in details for key in ("before", "after"))
    ):
        return True
    changes = details.get("changes")
    return isinstance(changes, list) and any(
        isinstance(change, Mapping)
        and isinstance(change.get("field"), str)
        and (_reference_path(_audit_field_path(change["field"]))
             or (was_reference and _audit_field_path(change["field"]) in {"", "data", "object"}))
        for change in changes
    )


def historical_reference_object_ids(session: Session, object_ids: Collection[str]) -> set[str]:
    """Conservatively classify only page candidates using immutable history.

    Conversion audit snapshots retain the prior kind, even when legacy events
    themselves lack classification. SQL filters by indexed object IDs and
    returns only distinct IDs, never loading a catalog/history into Python.
    A textual false positive only makes legacy rendering more restrictive.
    """
    if not object_ids:
        return set()
    return set(session.scalars(
        select(AuditEvent.object_id).where(
            AuditEvent.object_id.in_(object_ids),
            AuditEvent.details_json.contains(REFERENCE_KIND, autoescape=True),
        ).distinct()
    ).all())
