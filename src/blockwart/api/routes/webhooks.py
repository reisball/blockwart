"""Push-based monitoring webhook receivers.

The Gatus receiver is the first push provider on the #135 observation contract.
It converts a Gatus custom alert payload into a ``MonitoringObservation`` and
writes it through ``record_service_observation`` — the same ingestion seam the
built-in HTTP poller uses.  It never touches ``catalog_objects.health``,
appends no comments, and persists no alert descriptions or error text.

Service mapping is explicit and stable: each service that should receive Gatus
observations carries a ``data.gatus`` document with ``source``, ``group``, and
``endpoint`` fields.  The receiver matches the incoming payload against all
services and fails closed when zero or more than one *authorized* service
matches.

Concealment: target resolution runs against the caller's read access, so a
token without visibility over a mapping observes the same failure as a token
that names an unknown endpoint.  Zero authorized matches is a single 404; the
caller cannot distinguish "no mapping", "mapping exists but is hidden", or
"mapping exists but is not authorized".  Ambiguity is only ever measured over
authorized matches, never over hidden ones.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.api.errors import API_ERROR_RESPONSES
from blockwart.api.security import require_api_read_access
from blockwart.domain.auth import Permission
from blockwart.domain.monitoring import MonitoringObservation
from blockwart.models import CatalogObject
from blockwart.schemas.webhooks import WebhookGatusIn, WebhookGatusOut
from blockwart.services.monitoring import MonitoringSettings, record_service_observation
from blockwart.services.read_access import ReadAccess

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/v1/webhooks",
    tags=["api-v1-webhooks"],
    responses=API_ERROR_RESPONSES,
)

# The maximum skew a reported event timestamp may be ahead of the server's
# receive time. A far-future timestamp must not pin the observation row and
# starve later legitimate deliveries, so anything beyond this window is
# rejected as invalid rather than trusted.
_FUTURE_SKEW_SECONDS = 300


@router.post("/gatus", response_model=WebhookGatusOut)
def receive_gatus_webhook(
    payload: WebhookGatusIn,
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
) -> WebhookGatusOut:
    """Ingest one Gatus alert as a canonical service observation.

    The observation's ``checked_at`` (observed time) is the event timestamp
    when present, otherwise the server receive time. Storage ``updated_at`` is
    always the server receive time, so observed and received time are never
    conflated.

    Args:
        payload: The Gatus custom alert payload with endpoint identity,
            alert state, and optional check timestamp.
        request: The incoming FastAPI request.
        session: The database session for this request.
        access: Authenticated service-token read access with policy.

    Returns:
        The matched object id, observation state, observed time, and whether a
        write actually happened. ``ingested`` is truthful: a duplicate or
        stale replay that the conflict guard rejects reports False.

    Raises:
        HTTPException: 404 for no authorized match, 409 for ambiguous
            authorized matches, or 422 for an invalid or over-skewed future
            timestamp.
    """
    received_at = datetime.now(UTC)
    checked_at = _resolve_checked_at(payload.timestamp, received_at=received_at)

    candidates = _resolve_authorized_gatus_targets(
        session,
        access=access,
        source=payload.source,
        group=payload.group,
        endpoint=payload.endpoint,
    )

    if not candidates:
        # One uniform, concealment-safe failure. No branch distinguishes a
        # missing mapping from a hidden or unauthorized one.
        raise HTTPException(
            status_code=404,
            detail="No service matches this Gatus endpoint identity",
        )
    if len(candidates) > 1:
        logger.error(
            "gatus_webhook_error code=ambiguous_mapping endpoint=%s",
            _redacted(payload.endpoint),
        )
        raise HTTPException(
            status_code=409,
            detail="Multiple services match this Gatus endpoint identity",
        )

    catalog_object = candidates[0]

    observation = MonitoringObservation(
        provider="gatus",
        state=_gatus_alert_to_state(payload.alert),
        checked_at=checked_at,
        http_status=payload.http_status,
        latency_ms=payload.latency_ms,
    )

    settings = MonitoringSettings()
    record, written = record_service_observation(
        session,
        object_id=catalog_object.id,
        object_instance_id=catalog_object.instance_id,
        observation=observation,
        now=received_at,
        settings=settings,
        report_written=True,
    )

    session.commit()

    if record is None:
        logger.info(
            "gatus_webhook_info code=missing_instance object_id=%s",
            _redacted(catalog_object.id),
        )
    elif not written:
        logger.info(
            "gatus_webhook_info code=duplicate_or_stale object_id=%s",
            _redacted(catalog_object.id),
        )

    return WebhookGatusOut(
        object_id=catalog_object.id,
        provider="gatus",
        state=observation.state,
        checked_at=checked_at.isoformat(),
        ingested=written,
    )


def _gatus_alert_to_state(alert: str) -> str:
    """Translate a Gatus alert state into a monitoring observation state.

    Args:
        alert: The Gatus alert state (``TRIGGERED`` or ``RESOLVED``).

    Returns:
        The canonical monitoring state: ``down`` for TRIGGERED,
        ``healthy`` for RESOLVED.

    Raises:
        ValueError: If *alert* is neither ``TRIGGERED`` nor ``RESOLVED``.
    """
    if alert == "TRIGGERED":
        return "down"
    if alert == "RESOLVED":
        return "healthy"
    raise ValueError(f"unsupported Gatus alert state: {alert!r}")


def _parse_checked_at(value: str) -> datetime:
    """Parse an RFC 3339 timestamp into an aware UTC datetime.

    Args:
        value: The timestamp string from the Gatus payload.

    Returns:
        An aware UTC datetime.

    Raises:
        HTTPException: 422 if the timestamp is not a valid RFC 3339 string.
    """
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail="timestamp must be a valid RFC 3339 string",
        ) from None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _resolve_checked_at(payload_timestamp: str | None, *, received_at: datetime) -> datetime:
    """Resolve the observation's observed time.

    When a timestamp is present it becomes ``checked_at``; otherwise the server
    receive time is used. The result is rejected when it lies more than
    ``_FUTURE_SKEW_SECONDS`` ahead of the receive time, so a single far-future
    timestamp cannot pin the provider row and block legitimate later writes.

    Args:
        payload_timestamp: The optional event timestamp from the payload.
        received_at: The server receive time (used as the fallback and as the
            reference for the future-skew bound).

    Returns:
        The bounded observed time.

    Raises:
        HTTPException: 422 for an invalid or over-skewed future timestamp.
    """
    if payload_timestamp is None:
        return received_at
    checked_at = _parse_checked_at(payload_timestamp)
    if checked_at > received_at + timedelta(seconds=_FUTURE_SKEW_SECONDS):
        raise HTTPException(
            status_code=422,
            detail="timestamp is too far in the future",
        )
    return checked_at


def _ordered_matching_services(
    session: Session,
    *,
    source: str | None,
    group: str | None,
    endpoint: str,
) -> list[CatalogObject]:
    """Return every matching service in a stable order.

    The scan is over all service rows uniformly (never filtered by the caller's
    visibility), so a concealed token cannot infer hidden mapping existence
    from the number of rows a scan reads.

    Args:
        session: The database session to query.
        source: The optional Gatus source label.
        group: The optional Gatus group label.
        endpoint: The required Gatus endpoint name.

    Returns:
        Every service whose ``data.gatus`` mapping matches, ordered by id.
    """
    services = session.scalars(
        select(CatalogObject)
        .where(CatalogObject.kind == "service")
        .order_by(CatalogObject.id)
    ).all()
    matches: list[CatalogObject] = []
    for service in services:
        mapping = _read_gatus_mapping(service)
        if mapping is None:
            continue
        if not _mapping_matches(mapping, source=source, group=group, endpoint=endpoint):
            continue
        matches.append(service)
    return matches


def _resolve_authorized_gatus_targets(
    session: Session,
    *,
    access: ReadAccess,
    source: str | None,
    group: str | None,
    endpoint: str,
) -> list[CatalogObject]:
    """Find services whose ``data.gatus`` mapping matches and are authorized.

    The match is exact and case-sensitive. ``endpoint`` is always required;
    ``source`` and ``group`` must match when the service's mapping declares
    them. A service with only ``gatus.endpoint`` matches any payload with that
    endpoint, regardless of source/group.

    Concealment: only services the caller has ``DISCOVER`` over are retained.
    Ambiguity is measured only over authorized matches, never over hidden ones,
    so a hidden second mapping never leaks its existence or cardinality.

    Args:
        session: The database session to query.
        access: The caller's read access (for capability filtering).
        source: The optional Gatus source label.
        group: The optional Gatus group label.
        endpoint: The required Gatus endpoint name.

    Returns:
        The list of *authorized* matching service catalog objects. Zero means
        no authorized match; more than one means an ambiguous authorized
        mapping.
    """
    authorized: list[CatalogObject] = []
    for service in _ordered_matching_services(
        session, source=source, group=group, endpoint=endpoint
    ):
        if Permission.DISCOVER not in access.capabilities_for(service.id):
            continue
        authorized.append(service)
    return authorized


def _read_gatus_mapping(row: CatalogObject) -> dict[str, str] | None:
    """Read the ``data.gatus`` mapping document from a catalog object.

    Args:
        row: The catalog object row.

    Returns:
        The mapping dict with ``source``, ``group``, ``endpoint`` keys, or
        ``None`` if the object has no gatus mapping.
    """
    try:
        data = json.loads(row.data_json or "{}")
    except (TypeError, ValueError):
        return None
    mapping = data.get("gatus") if isinstance(data, dict) else None
    if not isinstance(mapping, dict) or "endpoint" not in mapping:
        return None
    return mapping


def _mapping_matches(
    mapping: dict[str, str],
    *,
    source: str | None,
    group: str | None,
    endpoint: str,
) -> bool:
    """Check whether a service's gatus mapping matches the payload identity.

    Args:
        mapping: The service's ``data.gatus`` document.
        source: The payload's source label (optional).
        group: The payload's group label (optional).
        endpoint: The payload's endpoint name (required).

    Returns:
        True if all declared mapping fields match the payload.
    """
    if mapping.get("endpoint") != endpoint:
        return False
    declared_source = mapping.get("source")
    if declared_source is not None and declared_source != source:
        return False
    declared_group = mapping.get("group")
    if declared_group is not None and declared_group != group:
        return False
    return True


def _redacted(value: str) -> str:
    """Return a hashed, non-reversible form of a value for safe logging.

    Args:
        value: The string to redact.

    Returns:
        A ``sha256:<16-hex>`` digest that cannot be reversed to the
        original value.
    """
    digest = hashlib.sha256(value.encode()).hexdigest()
    return f"sha256:{digest[:16]}"
