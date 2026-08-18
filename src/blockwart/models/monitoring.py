from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Index,
    Integer,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from blockwart.db.base import Base

# The controlled vocabularies are duplicated as SQL CHECK constraints on
# purpose: the database refuses an unknown provider, state, or error code even
# if a future ingestion path bypasses the domain layer.
_PROVIDERS = "'builtin_http'"
_STATES = "'unknown','healthy','down','check_error'"
_ERROR_CODES = (
    "'connect_failed','dns_failed','http_client_error','http_server_error',"
    "'invalid_target','policy_denied','probe_failed','redirect_not_supported',"
    "'response_too_large','timeout','tls_failed'"
)


class ServiceObservation(Base):
    """One canonical monitoring observation per service instance and provider.

    Observations are deliberately stored outside ``catalog_objects``. Polling
    must not advance the object revision, the business ``updated_at``, or the
    object audit timeline, so the catalog row stays untouched between manual
    edits.

    The identity is ``(object_id, object_instance_id, provider)``:

    - ``object_instance_id`` binds the row to one concrete catalog row, so a
      deleted-and-recreated object ID cannot inherit the previous object's
      observations;
    - ``provider`` keeps two acquisition sources independent, so a later
      receiver can write beside the built-in probe rather than overwrite it.
    """

    __tablename__ = "service_observations"
    __table_args__ = (
        UniqueConstraint(
            "object_id",
            "object_instance_id",
            "provider",
            name="uq_service_observations_identity",
        ),
        CheckConstraint(f"provider IN ({_PROVIDERS})", name="ck_service_observations_provider"),
        CheckConstraint(f"state IN ({_STATES})", name="ck_service_observations_state"),
        CheckConstraint(
            f"error_code IS NULL OR error_code IN ({_ERROR_CODES})",
            name="ck_service_observations_error_code",
        ),
        CheckConstraint(
            "http_status IS NULL OR (http_status >= 100 AND http_status <= 599)",
            name="ck_service_observations_http_status",
        ),
        CheckConstraint(
            "latency_ms IS NULL OR latency_ms >= 0",
            name="ck_service_observations_latency",
        ),
        Index(
            "ix_service_observations_object",
            "object_id",
            "object_instance_id",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    object_id: Mapped[str] = mapped_column(String(128), nullable=False)
    object_instance_id: Mapped[str] = mapped_column(String(32), nullable=False)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="unknown")
    http_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(32), nullable=True)
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    next_due_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        server_default=func.now(),
        nullable=False,
    )


class ServiceCheckLease(Base):
    """Scheduling state for one due service check.

    The lease is the multi-process safety primitive. Acquiring it is a single
    conditional ``UPDATE`` guarded by the current due time and lease expiry, so
    two web processes racing for the same service produce exactly one effective
    check on both SQLite and PostgreSQL without vendor-specific locking.

    It is stored separately from the observation because a push-based provider
    needs an observation without ever needing a poll lease.
    """

    __tablename__ = "service_check_leases"
    __table_args__ = (
        UniqueConstraint(
            "object_id",
            "object_instance_id",
            name="uq_service_check_leases_identity",
        ),
        CheckConstraint(f"provider IN ({_PROVIDERS})", name="ck_service_check_leases_provider"),
        CheckConstraint(
            "(lease_owner IS NULL AND lease_expires_at IS NULL) OR "
            "(lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)",
            name="ck_service_check_leases_lease_pair",
        ),
        Index("ix_service_check_leases_due", "due_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    object_id: Mapped[str] = mapped_column(String(128), nullable=False)
    object_instance_id: Mapped[str] = mapped_column(String(32), nullable=False)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    due_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    lease_owner: Mapped[str | None] = mapped_column(String(64), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        server_default=func.now(),
        nullable=False,
    )
