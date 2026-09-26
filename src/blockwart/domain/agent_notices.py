"""Vocabulary and payload contract for agent notice delivery (Issue #106).

Agent notices are a push channel for selected Blockwart events. The channel
is deliberately narrow:

- one versioned event format with a bounded, reviewed vocabulary;
- one fixed, data-minimized message template per event type; and
- safe, coarse error codes instead of transport or provider details.

Untrusted upstream text (release notes, titles, HTML/Markdown bodies) never
reaches this module. The only release-derived values that may appear in a
notice are the tag and normalized version strings that already passed the
release-monitoring URL-safe validators.
"""

from __future__ import annotations

from typing import Any

# The merged release-monitoring implementation publishes the attention reason
# ``release_update_available`` (see domain/attention.py). Issue #106 named the
# first event type ``service_release_update_available``; we follow the shipped
# vocabulary so events, attention reasons, and notices stay one language.
NOTICE_EVENT_TYPES = frozenset({"release_update_available"})

NOTICE_PAYLOAD_VERSION = 1

NOTICE_SCOPE_VALUES = frozenset({"object", "catalog"})

TRANSPORT_OPENCLAW_TEST_GATEWAY = "openclaw_test_gateway"
AGENT_NOTICE_TRANSPORTS = frozenset({TRANSPORT_OPENCLAW_TEST_GATEWAY})

DELIVERY_STATUS_VALUES = (
    "pending",
    "delivered",
    "failed",
    "suppressed",
    "expired",
    "acknowledged",
)

ATTEMPT_OUTCOME_VALUES = ("success", "timeout", "unavailable", "rate_limited")

# Safe, coarse failure codes. They intentionally carry no provider, URL,
# credential, prompt, session, or token material.
SAFE_ERROR_CODES = (
    "transport_timeout",
    "transport_unavailable",
    "rate_limited",
    "target_inactive",
    "principal_inactive",
    "subscription_revoked",
    "read_permission_lost",
    "ttl_expired",
    "attempt_limit_reached",
    "storm_suppressed",
)


def build_release_notice_message(label: str, latest_tag: str | None) -> str:
    """Render the fixed data-minimized message template.

    The template is the only free-form surface an agent ever sees. It is built
    exclusively from the visible object label and the already-validated tag;
    it never embeds release notes, bodies, URLs, or any upstream text.
    """
    version_part = f" (Tag {latest_tag})" if latest_tag else ""
    return f"Fuer Service '{label}' ist ein neues stabiles Release verfuegbar{version_part}."


def build_notice_payload(
    *,
    event_id: str,
    object_ref: str,
    object_label: str,
    latest_tag: str | None,
    back_reference_path: str,
) -> dict[str, Any]:
    """Build the minimal v1 notice payload.

    Keys are closed: consumers must not expect additional fields. Everything
    is derived from server-side validated state at delivery time.
    """
    return {
        "schema_version": NOTICE_PAYLOAD_VERSION,
        "event_type": "release_update_available",
        "event_id": event_id,
        "object_ref": object_ref,
        "message": build_release_notice_message(object_label, latest_tag),
        "blockwart_reference": back_reference_path,
    }
