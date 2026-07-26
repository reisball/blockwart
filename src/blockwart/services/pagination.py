from __future__ import annotations

import base64
import binascii
import hashlib
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

SortDirection = Literal["asc", "desc"]

CursorKey = tuple[str, str]

_CURSOR_VERSION = 1
_MAX_CURSOR_LENGTH = 2048


class InvalidCursor(ValueError):
    """Raised when an opaque cursor does not match the active query."""


@dataclass(frozen=True, slots=True)
class CursorPage[T]:
    items: list[T]
    next_cursor: str | None
    total: int | None


def paginate_items[T](
    items: Sequence[T],
    *,
    key: Callable[[T], CursorKey],
    limit: int,
    resource: str,
    sort: str,
    direction: SortDirection,
    query: Mapping[str, object],
    cursor: str | None,
    include_total: bool,
) -> CursorPage[T]:
    """Return one deterministic keyset page bound to the active query."""
    fingerprint = _query_fingerprint(
        resource=resource,
        sort=sort,
        direction=direction,
        query=query,
    )
    position = (
        _decode_cursor(
            cursor,
            fingerprint=fingerprint,
            sort=sort,
            direction=direction,
        )
        if cursor
        else None
    )
    ordered = sorted(items, key=key, reverse=direction == "desc")
    if position is not None:
        ordered = [
            item
            for item in ordered
            if _is_after(key(item), position, direction)
        ]
    window = ordered[: limit + 1]
    page_items = window[:limit]
    next_cursor = None
    if len(window) > limit and page_items:
        primary, tie_breaker = key(page_items[-1])
        next_cursor = _encode_cursor(
            fingerprint=fingerprint,
            sort=sort,
            direction=direction,
            primary=primary,
            tie_breaker=tie_breaker,
        )
    return CursorPage(
        items=page_items,
        next_cursor=next_cursor,
        total=len(items) if include_total else None,
    )


def _is_after(
    candidate: CursorKey,
    position: CursorKey,
    direction: SortDirection,
) -> bool:
    if direction == "asc":
        return candidate > position
    return candidate < position


def _query_fingerprint(
    *,
    resource: str,
    sort: str,
    direction: SortDirection,
    query: Mapping[str, object],
) -> str:
    payload = {
        "direction": direction,
        "query": dict(sorted(query.items())),
        "resource": resource,
        "sort": sort,
    }
    serialized = json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:24]


def _encode_cursor(
    *,
    fingerprint: str,
    sort: str,
    direction: SortDirection,
    primary: str,
    tie_breaker: str,
) -> str:
    payload = {
        "d": direction,
        "f": fingerprint,
        "p": primary,
        "s": sort,
        "t": tie_breaker,
        "v": _CURSOR_VERSION,
    }
    serialized = json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return base64.urlsafe_b64encode(serialized).decode("ascii").rstrip("=")


def _decode_cursor(
    cursor: str,
    *,
    fingerprint: str,
    sort: str,
    direction: SortDirection,
) -> CursorKey:
    if not cursor or len(cursor) > _MAX_CURSOR_LENGTH:
        raise InvalidCursor("Cursor is empty or too long")
    padding = "=" * (-len(cursor) % 4)
    try:
        raw = base64.b64decode(
            f"{cursor}{padding}",
            altchars=b"-_",
            validate=True,
        )
        payload = json.loads(raw.decode("utf-8"))
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InvalidCursor("Cursor is malformed") from exc
    if not isinstance(payload, dict):
        raise InvalidCursor("Cursor payload is invalid")
    if set(payload) != {"d", "f", "p", "s", "t", "v"}:
        raise InvalidCursor("Cursor payload is invalid")
    if (
        payload["v"] != _CURSOR_VERSION
        or payload["f"] != fingerprint
        or payload["s"] != sort
        or payload["d"] != direction
        or not isinstance(payload["p"], str)
        or not isinstance(payload["t"], str)
    ):
        raise InvalidCursor("Cursor does not match the active query")
    return payload["p"], payload["t"]
