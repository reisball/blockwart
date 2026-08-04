from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from sqlalchemy.orm import Session

from blockwart.models import AuditEvent

AUDIT_DETAILS_VERSION = 1


def add_audit_event(
    session: Session,
    *,
    object_id: str | None,
    action: str,
    actor: str,
    details: Mapping[str, Any] | None = None,
) -> None:
    payload = {
        "event": action,
        "version": AUDIT_DETAILS_VERSION,
        **dict(details or {}),
    }
    session.add(
        AuditEvent(
            object_id=object_id,
            action=action,
            actor=actor,
            summary=action,
            details_json=json.dumps(
                payload,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ),
        )
    )


def load_audit_details(row: AuditEvent) -> dict[str, Any]:
    try:
        details = json.loads(row.details_json)
    except (TypeError, json.JSONDecodeError):
        details = None
    if (
        isinstance(details, dict)
        and details.get("version") == AUDIT_DETAILS_VERSION
        and isinstance(details.get("event"), str)
    ):
        return details
    return {
        "event": "legacy",
        "legacy_summary": row.summary,
        "version": AUDIT_DETAILS_VERSION,
    }


def render_audit_summary_english(
    action: str,
    details: Mapping[str, Any],
    *,
    legacy_summary: str,
) -> str:
    event = str(details.get("event") or action)
    if event == "legacy":
        original = details.get("legacy_summary")
        return original if isinstance(original, str) else legacy_summary
    if event in {"create", "delete", "seed_create", "seed_update"}:
        object_ref = _text(details.get("object_ref"))
        verbs = {
            "create": "Created",
            "delete": "Deleted",
            "seed_create": "Created from seed",
            "seed_update": "Updated from seed",
        }
        return f"{verbs[event]} {object_ref}".strip()
    if event == "update":
        changes = details.get("changes")
        if isinstance(changes, list):
            rendered = [
                _render_change(change)
                for change in changes
                if isinstance(change, Mapping)
            ]
            if rendered:
                return "; ".join(rendered)
        object_ref = _text(details.get("object_ref"))
        return f"Updated {object_ref}".strip()
    if event in {"grant_create", "grant_update", "grant_revoke"}:
        target = _text(
            details.get("target_principal_id")
            or details.get("principal_id")
        )
        verbs = {
            "grant_create": "Granted access to principal",
            "grant_update": "Changed access for principal",
            "grant_revoke": "Revoked access from principal",
        }
        return f"{verbs[event]} {target}".strip()
    if event == "comment_create":
        return "Added object comment"
    if event in {"relationship_create", "seed_relationship_create"}:
        prefix = "Created relationship"
        if event == "seed_relationship_create":
            prefix = "Created relationship from seed"
        triplet = " ".join(
            value
            for value in (
                _text(details.get("from_ref")),
                _text(details.get("relation_type")),
                _text(details.get("to_ref")),
            )
            if value
        )
        return f"{prefix} {triplet}".strip()
    if event == "placement_assign":
        return f"Assigned placement parent for {_text(details.get('child_ref'))}".strip()
    if event == "seed_skip_manual_override":
        return f"Preserved manual override for {_text(details.get('object_ref'))}".strip()
    if event == "interface_normalize":
        return (
            f"Normalized interface contract for {_text(details.get('object_ref'))} "
            f"({_text(details.get('diagnostic_count')) or '0'} diagnostics)"
        ).strip()
    if event == "placement_state_normalize":
        operation = _text(details.get("operation"))
        verb = (
            "Marked unassigned"
            if operation == "mark_unassigned"
            else "Cleared unassigned state"
        )
        return f"{verb} for {_text(details.get('object_ref'))}".strip()
    return action


def _render_change(change: Mapping[str, Any]) -> str:
    field = _text(change.get("field")) or "data"
    if change.get("value_change") is True:
        return (
            f"Changed {field} from {_display_value(change.get('old'))} "
            f"to {_display_value(change.get('new'))}"
        )
    return f"Changed {field}"


def _display_value(value: Any) -> str:
    text = _text(value)
    return text if text else "empty"


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""
