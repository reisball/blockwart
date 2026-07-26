from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, ValidationError, field_validator

from blockwart.domain.security import find_secret_violations
from blockwart.domain.timestamps import format_rfc3339_utc

SourceType = Literal["unknown", "manual", "import", "discovery"]
SOURCE_TYPES: tuple[SourceType, ...] = (
    "unknown",
    "manual",
    "import",
    "discovery",
)


class CatalogProvenance(BaseModel):
    source_type: SourceType = "unknown"
    source_ref: str | None = Field(default=None, max_length=2048)
    managed_by: str | None = Field(default=None, max_length=255)
    observed_at: str | None = None
    verified_at: str | None = None
    stale_after: str | None = None
    manual_override: bool = False

    @field_validator("source_ref", "managed_by")
    @classmethod
    def normalize_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None

    @field_validator("observed_at", "verified_at", "stale_after")
    @classmethod
    def normalize_timestamp(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return normalize_rfc3339_utc(value)


class CatalogProvenanceOut(CatalogProvenance):
    is_stale: bool = False


def manual_provenance() -> CatalogProvenance:
    return CatalogProvenance(
        source_type="manual",
        manual_override=True,
    )


def unknown_provenance() -> CatalogProvenance:
    return CatalogProvenance()


def dump_provenance(provenance: CatalogProvenance) -> str:
    payload = provenance.model_dump(exclude={"is_stale"})
    violations = find_secret_violations(payload)
    if violations:
        raise ValueError("; ".join(violations))
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def load_provenance(raw_json: str | None) -> tuple[CatalogProvenance, bool]:
    try:
        payload = json.loads(raw_json)
    except (TypeError, json.JSONDecodeError):
        return unknown_provenance(), False
    if not isinstance(payload, dict) or find_secret_violations(payload):
        return unknown_provenance(), False
    try:
        return CatalogProvenance.model_validate(payload), True
    except ValidationError:
        return unknown_provenance(), False


def provenance_for_read(
    provenance: CatalogProvenance,
    *,
    now: datetime | None = None,
) -> CatalogProvenanceOut:
    return CatalogProvenanceOut(
        **provenance.model_dump(),
        is_stale=is_stale(provenance, now=now),
    )


def is_stale(
    provenance: CatalogProvenance,
    *,
    now: datetime | None = None,
) -> bool:
    if provenance.stale_after is None:
        return False
    boundary = parse_rfc3339_utc(provenance.stale_after)
    reference = now or datetime.now(UTC)
    if reference.tzinfo is None:
        reference = reference.replace(tzinfo=UTC)
    return boundary <= reference.astimezone(UTC)


def normalize_rfc3339_utc(value: str | datetime) -> str:
    parsed = parse_rfc3339_utc(value)
    normalized = format_rfc3339_utc(parsed)
    if normalized is None:  # pragma: no cover - format helper is total for datetime
        raise ValueError("timestamp is required")
    return normalized


def parse_rfc3339_utc(value: str | datetime) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        normalized = value.strip()
        if not normalized:
            raise ValueError("timestamp must not be empty")
        try:
            parsed = datetime.fromisoformat(normalized.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("timestamp must be RFC3339") from exc
    else:
        raise ValueError("timestamp must be RFC3339")
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include an UTC offset")
    return parsed.astimezone(UTC)


def seed_timestamp(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("seed provenance timestamps must be strings")
    normalized = value.strip()
    if len(normalized) == 10:
        normalized = f"{normalized}T00:00:00Z"
    return normalize_rfc3339_utc(normalized)
