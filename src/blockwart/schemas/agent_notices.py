from datetime import datetime

from pydantic import BaseModel, Field


class AgentNoticeSubscriptionIn(BaseModel):
    event_type: str = Field(min_length=1, max_length=64)
    scope: str = Field(pattern=r"^(object|catalog)$")
    object_id: str | None = Field(default=None, max_length=128)
    principal_id: str = Field(min_length=1, max_length=36)
    target_id: str = Field(min_length=1, max_length=36)


class AgentNoticeSubscriptionOut(BaseModel):
    id: str
    event_type: str
    scope: str
    object_id: str | None
    principal_id: str
    target_id: str
    active: bool
    revoked_at: datetime | None


class AgentNoticeSubscriptionListOut(BaseModel):
    count: int
    items: list[AgentNoticeSubscriptionOut]


class AgentNoticeDeliveryJobOut(BaseModel):
    """Redacted delivery diagnostics. No payload, transport, or token data."""

    job_id: int
    event_id: str
    event_type: str
    object_ref: str
    status: str
    attempts: int
    next_attempt_at: datetime | None
    expires_at: datetime
    delivered_at: datetime | None
    acknowledged_at: datetime | None
    suppressed_at: datetime | None
    last_error_code: str | None
    created_at: datetime


class AgentNoticeDeliveryJobListOut(BaseModel):
    count: int
    items: list[AgentNoticeDeliveryJobOut]


class AgentNoticeOut(BaseModel):
    """The agent-visible notice: minimal payload plus its delivery state."""

    event_id: str
    event_type: str
    schema_version: int
    object_ref: str
    message: str
    blockwart_reference: str
    status: str
    delivered_at: datetime | None


class AgentNoticeListOut(BaseModel):
    count: int
    notices: list[AgentNoticeOut]


class AgentNoticeAcknowledgeOut(BaseModel):
    acknowledged: bool
    error_code: str | None = None
