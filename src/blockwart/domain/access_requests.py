from enum import StrEnum


class AccessRequestStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    CANCELLED = "cancelled"
    EXPIRED = "expired"


class AccessRequestDuration(StrEnum):
    TEMPORARY = "temporary"
    PERMANENT = "permanent"


def is_access_request_status(value: str) -> bool:
    try:
        AccessRequestStatus(value)
    except ValueError:
        return False
    return True
