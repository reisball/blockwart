"""One injectable wall-clock seam for time-bounded access.

Temporary grants and access requests judge time in the request path. Reading
the clock through this module (``clock.utcnow()``) instead of calling
``datetime.now`` inline gives tests a single place to move time across expiry
boundaries without editing database rows.
"""

from __future__ import annotations

from datetime import UTC, datetime


def utcnow() -> datetime:
    """Current UTC time as the naive timestamp the schema stores."""
    return datetime.now(UTC).replace(tzinfo=None)
