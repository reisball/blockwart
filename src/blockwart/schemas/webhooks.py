"""Pydantic models for inbound webhook payloads."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class WebhookGatusIn(BaseModel):
    """Payload sent by a Gatus custom alert webhook.

    The receiver maps the Gatus endpoint identity (``source``, ``group``,
    ``endpoint``) to a Blockwart service through the service's
    ``data.gatus`` mapping document.  Alert text, error details, and
    response bodies are deliberately not persisted: the observation
    contract stores only a bounded, redacted state.
    """

    # Gatus sends the endpoint identity as separate fields.  ``endpoint``
    # is the human-readable name configured in the Gatus endpoint block;
    # ``group`` and ``source`` are optional grouping labels.
    endpoint: str = Field(min_length=1, max_length=255)
    group: str | None = Field(default=None, max_length=128)
    source: str | None = Field(default=None, max_length=128)

    # Gatus sends "TRIGGERED" when an alert fires and "RESOLVED" when it
    # clears.  The receiver translates these into observation states.
    alert: Literal["TRIGGERED", "RESOLVED"] = Field(
        description="Gatus alert state: TRIGGERED or RESOLVED",
    )

    # The timestamp Gatus observed the result.  Used for idempotency:
    # replays and out-of-order deliveries are rejected by the observation
    # seam's ``last_checked_at < excluded.last_checked_at`` guard.
    timestamp: str = Field(
        min_length=1,
        max_length=64,
        description="RFC 3339 timestamp of the Gatus check result",
    )

    # Optional bounded metadata.  The receiver extracts only http_status
    # and latency; error text is never persisted.
    http_status: int | None = Field(default=None, ge=100, le=599)
    latency_ms: int | None = Field(default=None, ge=0, le=600000)


class WebhookGatusOut(BaseModel):
    """Result of ingesting a Gatus alert as a service observation."""

    object_id: str
    provider: str = "gatus"
    state: str
    checked_at: str
    ingested: bool
