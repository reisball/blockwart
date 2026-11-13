"""Read-only UI display helpers; stored timestamps and audit actors are untouched."""

from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo


def activity_time(value: str | None, locale: str, *, now: datetime | None = None) -> dict[str, str]:
    """Format an occurrence using Berlin calendar dates, including DST boundaries.

    Args:
        value: Exact RFC3339 occurrence value; missing or invalid stays unknown.
        locale: Requested UI locale.
        now: Optional deterministic reference instant for tests.

    Returns:
        Day, clock, exact tooltip and unchanged datetime value for the template.
    """
    unknown = "Zeit unbekannt" if locale == "de" else "Time unknown"
    try:
        parsed = datetime.fromisoformat((value or "").replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("Timestamp lacks an offset")
    except (ValueError, TypeError):
        return {"day": unknown, "clock": "", "title": unknown, "datetime": ""}
    zone = ZoneInfo("Europe/Berlin")
    local = parsed.astimezone(zone)
    today = (now or datetime.now(UTC)).astimezone(zone).date()
    if local.date() == today:
        day = "Heute" if locale == "de" else "Today"
    elif local.date() == today - timedelta(days=1):
        day = "Gestern" if locale == "de" else "Yesterday"
    else:
        day = local.strftime("%d.%m.%Y" if locale == "de" else "%Y-%m-%d")
    return {
        "day": day,
        "clock": local.strftime("%H:%M"),
        "datetime": value or "",
        "title": f"{value} · {local:%Y-%m-%d %H:%M %Z} (Europe/Berlin)",
    }
