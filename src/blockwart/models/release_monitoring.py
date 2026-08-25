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
# purpose: the database refuses an unknown provider or error code even if a
# future ingestion path bypasses the domain layer.
_PROVIDERS = "'github_releases'"
_ERROR_CODES = (
    "'connect_failed','dns_failed','http_client_error','http_server_error',"
    "'invalid_release_version','invalid_target','not_a_stable_release',"
    "'not_found','policy_denied','provider_failed','rate_limited',"
    "'redirect_not_supported','response_too_large','timeout','tls_failed',"
    "'unreadable_release'"
)


class ServiceReleaseObservation(Base):
    """One upstream release observation per service instance and provider.

    Release observations are deliberately stored outside ``catalog_objects``
    and outside ``service_observations``:

    - the catalog row must stay untouched between manual edits, so a check can
      never advance an object revision, the business ``updated_at``, or the
      object audit timeline;
    - a health observation and a release observation answer different
      questions.  Keeping them in separate tables is what stops "an update is
      available" from ever leaking into an availability claim, and what stops a
      release check failure from looking like a service outage.

    The identity is ``(object_id, object_instance_id, provider)``.
    ``object_instance_id`` binds the row to one concrete catalog row, so a
    deleted-and-recreated object id cannot inherit an earlier object's release
    history.

    Only bounded, validated evidence is stored.  ``latest_tag`` passed the
    URL-safe tag rule, ``latest_version`` is its normalized comparable form,
    and ``release_etag`` passed the ETag grammar.  No release note, title,
    author, asset name, upstream URL, or error string is ever persisted.
    """

    __tablename__ = "service_release_observations"
    __table_args__ = (
        UniqueConstraint(
            "object_id",
            "object_instance_id",
            "provider",
            name="uq_service_release_observations_identity",
        ),
        CheckConstraint(
            f"provider IN ({_PROVIDERS})",
            name="ck_service_release_observations_provider",
        ),
        CheckConstraint(
            f"error_code IS NULL OR error_code IN ({_ERROR_CODES})",
            name="ck_service_release_observations_error_code",
        ),
        CheckConstraint(
            "http_status IS NULL OR (http_status >= 100 AND http_status <= 599)",
            name="ck_service_release_observations_http_status",
        ),
        CheckConstraint(
            "consecutive_failures >= 0",
            name="ck_service_release_observations_failures",
        ),
        Index(
            "ix_service_release_observations_object",
            "object_id",
            "object_instance_id",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    object_id: Mapped[str] = mapped_column(String(128), nullable=False)
    object_instance_id: Mapped[str] = mapped_column(String(32), nullable=False)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    # SHA-256 of the canonical case-folded owner/repository identity. A target
    # change invalidates both the cached release and its conditional ETag.
    target_key: Mapped[str] = mapped_column(String(64), nullable=False)
    latest_tag: Mapped[str | None] = mapped_column(String(128), nullable=True)
    latest_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    released_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    # The upstream validator for a conditional request. It is replayed only as
    # an ``If-None-Match`` value against the same compiled-in API origin, so it
    # can never become a redirect, a credential, or a second target.
    release_etag: Mapped[str | None] = mapped_column(String(128), nullable=True)
    http_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # Drives the bounded exponential backoff. It is reset by any check that
    # obtained usable evidence, including a 304 confirmation.
    consecutive_failures: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    # The instant this deployment last confirmed what upstream publishes.
    # Evidence freshness follows this column, so a run of failing checks ages
    # the stored release normally instead of looking fresh.
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    next_due_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        server_default=func.now(),
        nullable=False,
    )


class ServiceReleaseCheckLease(Base):
    """Scheduling state for one due release check.

    The lease is the multi-process safety primitive, and it is separate from
    ``service_check_leases`` so a health probe and a release check never
    contend for one another's slot or silently replace one another's provider.

    Acquiring it is a single conditional ``UPDATE`` guarded by the current due
    time and lease expiry, so two web processes racing for the same service
    produce exactly one outbound request on both SQLite and PostgreSQL without
    vendor-specific locking.
    """

    __tablename__ = "service_release_check_leases"
    __table_args__ = (
        UniqueConstraint(
            "object_id",
            "object_instance_id",
            name="uq_service_release_leases_identity",
        ),
        CheckConstraint(
            f"provider IN ({_PROVIDERS})",
            name="ck_service_release_leases_provider",
        ),
        CheckConstraint(
            "(lease_owner IS NULL AND lease_expires_at IS NULL) OR "
            "(lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)",
            name="ck_service_release_leases_lease_pair",
        ),
        Index("ix_service_release_leases_due", "due_at"),
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
