from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from blockwart.db.base import Base
from blockwart.domain.access_request_notices import (
    NOTICE_ATTEMPT_OUTCOMES,
    NOTICE_ERROR_CODES,
    NOTICE_STATUS_VALUES,
)


def _in_list(values: tuple[str, ...]) -> str:
    return ",".join(f"'{value}'" for value in values)


class AccessRequestNotice(Base):
    """One durable hint order per access request and approved recipient route.

    The row is the outbox entry: it is written in the same transaction as the
    request it announces and is never an input to that request. A failing,
    expiring or dead-lettered notice cannot change a request or a grant.
    ``(request_id, target_id)`` is unique so repeated or concurrent fan-out
    produces one logical notice per recipient route. The recipient is
    re-authorized at every attempt, never trusted from this row.
    """

    __tablename__ = "access_request_notices"
    __table_args__ = (
        CheckConstraint(
            f"status IN ({_in_list(NOTICE_STATUS_VALUES)})",
            name="ck_access_request_notices_status",
        ),
        CheckConstraint(
            "last_error_code IS NULL OR last_error_code IN ("
            + _in_list(NOTICE_ERROR_CODES)
            + ")",
            name="ck_access_request_notices_error_code",
        ),
        CheckConstraint("attempts >= 0", name="ck_access_request_notices_attempts"),
        CheckConstraint(
            "(lease_token IS NULL) = (lease_expires_at IS NULL)",
            name="ck_access_request_notices_lease_pair",
        ),
        CheckConstraint(
            "status = 'pending' OR lease_token IS NULL",
            name="ck_access_request_notices_terminal_unleased",
        ),
        UniqueConstraint(
            "request_id",
            "target_id",
            name="uq_access_request_notices_identity",
        ),
        Index(
            "ix_access_request_notices_due",
            "status",
            "next_attempt_at",
        ),
        Index(
            "ix_access_request_notices_request",
            "request_id",
            "status",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    request_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("access_requests.id", ondelete="CASCADE"),
        nullable=False,
    )
    target_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("agent_delivery_targets.id", ondelete="CASCADE"),
        nullable=False,
    )
    # The principal the route belonged to when the notice was planned. It is a
    # diagnostic record only; authorization reads the live target and policy.
    recipient_principal_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("principals.id", ondelete="RESTRICT"),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(String(16), default="pending", server_default="pending")
    attempts: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    next_attempt_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    # Durable, fenced delivery lease committed before any network I/O; see the
    # outbox service. ``claimed_by`` is a diagnostic worker label only.
    claimed_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    lease_token: Mapped[str | None] = mapped_column(String(32), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    suppressed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_error_code: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        server_default=func.now(),
        onupdate=func.now(),
    )


class AccessRequestNoticeAttempt(Base):
    """Redacted attempt audit. No payload, route, token or URL content."""

    __tablename__ = "access_request_notice_attempts"
    __table_args__ = (
        CheckConstraint(
            f"outcome IN ({_in_list(NOTICE_ATTEMPT_OUTCOMES)})",
            name="ck_access_request_notice_attempts_outcome",
        ),
        CheckConstraint(
            "error_code IS NULL OR error_code IN (" + _in_list(NOTICE_ERROR_CODES) + ")",
            name="ck_access_request_notice_attempts_error_code",
        ),
        Index(
            "ix_access_request_notice_attempts_notice",
            "notice_id",
            "attempt_no",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    notice_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("access_request_notices.id", ondelete="CASCADE"),
        nullable=False,
    )
    attempt_no: Mapped[int] = mapped_column(Integer, nullable=False)
    outcome: Mapped[str] = mapped_column(String(24), nullable=False)
    error_code: Mapped[str | None] = mapped_column(String(32), nullable=True)
    attempted_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
