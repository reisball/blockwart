from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from blockwart.db.base import Base

_EVENT_TYPES = "'release_update_available'"
_TRANSPORTS = "'openclaw_test_gateway'"
_SCOPES = "'object','catalog'"
_STATUSES = (
    "'pending','delivered','failed','suppressed','expired','acknowledged'"
)
_ERROR_CODES = (
    "'transport_timeout','transport_unavailable','rate_limited',"
    "'target_inactive','principal_inactive','subscription_revoked',"
    "'read_permission_lost','ttl_expired','attempt_limit_reached',"
    "'storm_suppressed','delivery_error'"
)
_ATTEMPT_OUTCOMES = (
    "'success','confirmed_duplicate','timeout','unavailable','rate_limited','lease_expired'"
)


class AgentDeliveryTarget(Base):
    """One approved, addressable agent destination.

    A target binds one active Blockwart service-account principal to a named
    delivery route. It deliberately stores no credential material: transport
    secrets stay outside the catalog, the audit trail, and this table.

    Deactivating (revoking) the target must suppress every still-pending
    delivery fail-closed; the row is kept for redacted diagnostics only.
    """

    __tablename__ = "agent_delivery_targets"
    __table_args__ = (
        CheckConstraint(
            f"transport IN ({_TRANSPORTS})",
            name="ck_agent_delivery_targets_transport",
        ),
        CheckConstraint(
            "active IN (true, false)",
            name="ck_agent_delivery_targets_active_boolean",
        ),
        Index(
            "ix_agent_delivery_targets_principal",
            "principal_id",
            "active",
        ),
        # One logical agent route is registered at most once at a time. The
        # constraint is partial so a revoked registration stays as redacted
        # history while the same route can be approved again later.
        Index(
            "uq_agent_delivery_targets_active_route",
            "transport",
            "route",
            unique=True,
            sqlite_where=text("active = true"),
            postgresql_where=text("active = true"),
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    principal_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("principals.id", ondelete="RESTRICT"),
        nullable=False,
    )
    label: Mapped[str] = mapped_column(String(128))
    # Stable, non-secret OpenClaw routing identity (agent/session/inbox). The
    # gateway uses this to distinguish targets; it is never a credential.
    route: Mapped[str] = mapped_column(String(191), nullable=False)
    transport: Mapped[str] = mapped_column(String(32), nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        server_default=func.now(),
        onupdate=func.now(),
    )


class AgentNoticeSubscription(Base):
    """Explicit routing rule: event/object scope to an agent target.

    A subscription is created deliberately by a platform administrator and is
    revocable at any time. Revocation suppresses pending deliveries for later
    events and fail-closes jobs whose authorization re-check observes it.
    """

    __tablename__ = "agent_notice_subscriptions"
    __table_args__ = (
        CheckConstraint(
            f"event_type IN ({_EVENT_TYPES})",
            name="ck_agent_notice_subscriptions_event_type",
        ),
        CheckConstraint(
            f"scope IN ({_SCOPES})",
            name="ck_agent_notice_subscriptions_scope",
        ),
        CheckConstraint(
            "active IN (true, false)",
            name="ck_agent_notice_subscriptions_active_boolean",
        ),
        CheckConstraint(
            "scope <> 'object' OR object_id IS NOT NULL",
            name="ck_agent_notice_subscriptions_object_scope_anchor",
        ),
        Index(
            "ix_agent_notice_subscriptions_routing",
            "event_type",
            "active",
        ),
        # A routing rule exists at most once per event, scope, and target. Two
        # partial indexes keep this exact on both backends even though the
        # catalog scope has no object id (NULLs never collide in a unique index).
        Index(
            "uq_agent_notice_subscriptions_active_object",
            "event_type",
            "object_id",
            "target_id",
            unique=True,
            sqlite_where=text("active = true AND scope = 'object'"),
            postgresql_where=text("active = true AND scope = 'object'"),
        ),
        Index(
            "uq_agent_notice_subscriptions_active_catalog",
            "event_type",
            "target_id",
            unique=True,
            sqlite_where=text("active = true AND scope = 'catalog'"),
            postgresql_where=text("active = true AND scope = 'catalog'"),
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    scope: Mapped[str] = mapped_column(String(16), nullable=False)
    object_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    principal_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("principals.id", ondelete="RESTRICT"),
        nullable=False,
    )
    target_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("agent_delivery_targets.id", ondelete="RESTRICT"),
        nullable=False,
    )
    active: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_by_principal_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("principals.id", ondelete="SET NULL"),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        server_default=func.now(),
        onupdate=func.now(),
    )


class AgentNoticeEvent(Base):
    """One deduplicated logical notice event with a stable public id."""

    __tablename__ = "agent_notice_events"
    __table_args__ = (
        CheckConstraint(
            f"event_type IN ({_EVENT_TYPES})",
            name="ck_agent_notice_events_event_type",
        ),
        UniqueConstraint(
            "event_type",
            "object_id",
            "dedupe_key",
            name="uq_agent_notice_events_identity",
        ),
        Index(
            "ix_agent_notice_events_object",
            "object_id",
            "occurred_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    payload_version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    object_id: Mapped[str] = mapped_column(String(128), nullable=False)
    # Stable per logical occurrence, e.g. release version. Retries of the same
    # upstream observation can never create a second logical event.
    dedupe_key: Mapped[str] = mapped_column(String(191), nullable=False)
    latest_tag: Mapped[str | None] = mapped_column(String(128), nullable=True)
    latest_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class AgentDeliveryJob(Base):
    """One durable, deduplicated delivery order per event and target.

    The unique ``(event_id, target_id)`` identity makes fan-out idempotent:
    concurrent or repeated emission produces exactly one logical job.
    ``status`` follows the published state machine
    (pending/delivered/failed/suppressed/expired/acknowledged); retries only
    ever touch rows in the ``pending`` state, and a receiver that honors the
    stable ``delivery_id`` collapses response-loss retries, so a confirmed
    delivery is never repeated.
    """

    __tablename__ = "agent_delivery_jobs"
    __table_args__ = (
        CheckConstraint(
            f"status IN ({_STATUSES})",
            name="ck_agent_delivery_jobs_status",
        ),
        CheckConstraint(
            "last_error_code IS NULL OR last_error_code IN ("
            + _ERROR_CODES
            + ")",
            name="ck_agent_delivery_jobs_error_code",
        ),
        CheckConstraint("attempts >= 0", name="ck_agent_delivery_jobs_attempts"),
        CheckConstraint(
            "(lease_token IS NULL) = (lease_expires_at IS NULL)",
            name="ck_agent_delivery_jobs_lease_pair",
        ),
        CheckConstraint(
            "status = 'pending' OR lease_token IS NULL",
            name="ck_agent_delivery_jobs_terminal_unleased",
        ),
        UniqueConstraint(
            "event_id",
            "target_id",
            name="uq_agent_delivery_jobs_identity",
        ),
        Index(
            "ix_agent_delivery_jobs_due",
            "status",
            "next_attempt_at",
        ),
        Index(
            "ix_agent_delivery_jobs_target",
            "target_id",
            "status",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("agent_notice_events.id", ondelete="CASCADE"),
        nullable=False,
    )
    target_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("agent_delivery_targets.id", ondelete="CASCADE"),
        nullable=False,
    )
    subscription_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("agent_notice_subscriptions.id", ondelete="RESTRICT"),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(String(16), default="pending", server_default="pending")
    attempts: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    next_attempt_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    # Durable delivery lease, committed before any network I/O. ``lease_token``
    # is the fencing token: it is regenerated by every claim and every write
    # that records a delivery result is conditional on it, so a worker whose
    # lease expired and was reclaimed can no longer change the job. A crashed
    # worker's lease simply expires and the job becomes claimable again.
    # ``claimed_by`` is a diagnostic worker label only.
    claimed_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    lease_token: Mapped[str | None] = mapped_column(String(32), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    suppressed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_error_code: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        server_default=func.now(),
        onupdate=func.now(),
    )


class AgentDeliveryAttempt(Base):
    """Redacted attempt audit. No payload, prompt, token, or URL content."""

    __tablename__ = "agent_delivery_attempts"
    __table_args__ = (
        CheckConstraint(
            f"outcome IN ({_ATTEMPT_OUTCOMES})",
            name="ck_agent_delivery_attempts_outcome",
        ),
        CheckConstraint(
            "error_code IS NULL OR error_code IN (" + _ERROR_CODES + ")",
            name="ck_agent_delivery_attempts_error_code",
        ),
        Index(
            "ix_agent_delivery_attempts_job",
            "job_id",
            "attempt_no",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    job_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("agent_delivery_jobs.id", ondelete="CASCADE"),
        nullable=False,
    )
    attempt_no: Mapped[int] = mapped_column(Integer, nullable=False)
    outcome: Mapped[str] = mapped_column(String(24), nullable=False)
    error_code: Mapped[str | None] = mapped_column(String(32), nullable=True)
    attempted_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
