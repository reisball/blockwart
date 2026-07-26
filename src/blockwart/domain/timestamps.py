from datetime import UTC, datetime


def format_rfc3339_utc(value: datetime | None) -> str | None:
    """Format stored timestamps as RFC3339 UTC, treating legacy naive values as UTC."""

    if value is None:
        return None
    if value.tzinfo is None:
        normalized = value.replace(tzinfo=UTC)
    else:
        normalized = value.astimezone(UTC)
    return normalized.isoformat(timespec="microseconds").replace("+00:00", "Z")
