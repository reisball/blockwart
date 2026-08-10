from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from blockwart.db.base import Base


class Principal(Base):
    __tablename__ = "principals"
    __table_args__ = (
        CheckConstraint(
            "principal_type IN ('human','service_account')",
            name="ck_principals_type",
        ),
        CheckConstraint(
            "active IN (0,1)",
            name="ck_principals_active_boolean",
        ),
        CheckConstraint(
            "platform_role IS NULL OR platform_role = 'admin'",
            name="ck_principals_platform_role",
        ),
        CheckConstraint(
            "catalog_role IS NULL OR catalog_role = 'catalog_owner'",
            name="ck_principals_catalog_role",
        ),
        CheckConstraint(
            "revision >= 1",
            name="ck_principals_revision_positive",
        ),
        UniqueConstraint(
            "login",
            name="uq_principals_login",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    principal_type: Mapped[str] = mapped_column(String(32), index=True)
    login: Mapped[str] = mapped_column(
        String(128),
    )
    display_name: Mapped[str] = mapped_column(String(255))
    active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        server_default=text("1"),
        index=True,
    )
    platform_role: Mapped[str | None] = mapped_column(
        String(32),
        nullable=True,
        index=True,
    )
    catalog_role: Mapped[str | None] = mapped_column(
        String(32),
        nullable=True,
        index=True,
    )
    revision: Mapped[int] = mapped_column(
        Integer,
        default=1,
        server_default=text("1"),
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        server_default=func.now(),
        onupdate=func.now(),
    )


class PasswordCredential(Base):
    __tablename__ = "password_credentials"

    principal_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("principals.id", ondelete="CASCADE"),
        primary_key=True,
    )
    password_hash: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        server_default=func.now(),
        onupdate=func.now(),
    )


class BrowserSession(Base):
    __tablename__ = "browser_sessions"
    __table_args__ = (
        CheckConstraint(
            "expires_at > created_at",
            name="ck_browser_sessions_expiry",
        ),
        Index(
            "ix_browser_sessions_principal_active",
            "principal_id",
            "revoked_at",
            "expires_at",
        ),
        UniqueConstraint(
            "token_hash",
            name="uq_browser_sessions_token_hash",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    principal_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("principals.id", ondelete="CASCADE"),
        nullable=False,
    )
    token_hash: Mapped[str] = mapped_column(String(64))
    csrf_hash: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class LoginChallenge(Base):
    __tablename__ = "login_challenges"
    __table_args__ = (
        CheckConstraint(
            "expires_at > created_at",
            name="ck_login_challenges_expiry",
        ),
        UniqueConstraint(
            "token_hash",
            name="uq_login_challenges_token_hash",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class ServiceToken(Base):
    __tablename__ = "service_tokens"
    __table_args__ = (
        CheckConstraint(
            "audience IN ('api','mcp')",
            name="ck_service_tokens_audience",
        ),
        UniqueConstraint(
            "principal_id",
            "name",
            name="uq_service_tokens_principal_name",
        ),
        UniqueConstraint(
            "token_hash",
            name="uq_service_tokens_token_hash",
        ),
        Index(
            "ix_service_tokens_principal_active",
            "principal_id",
            "revoked_at",
            "expires_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    principal_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("principals.id", ondelete="CASCADE"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(128))
    audience: Mapped[str] = mapped_column(
        String(16),
        default="api",
        server_default=text("'api'"),
    )
    token_prefix: Mapped[str] = mapped_column(String(24))
    token_hash: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    rotated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class SecurityEvent(Base):
    __tablename__ = "security_events"
    __table_args__ = (
        CheckConstraint(
            "outcome IN ('success','failure','denied')",
            name="ck_security_events_outcome",
        ),
        CheckConstraint(
            "channel IN ('ui','api','mcp','cli','system')",
            name="ck_security_events_channel",
        ),
        Index(
            "ix_security_events_principal_created",
            "principal_id",
            "created_at",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    principal_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("principals.id", ondelete="SET NULL"),
        nullable=True,
    )
    event_type: Mapped[str] = mapped_column(String(96), index=True)
    outcome: Mapped[str] = mapped_column(String(16), index=True)
    channel: Mapped[str] = mapped_column(String(16), index=True)
    request_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    details_json: Mapped[str] = mapped_column(
        Text,
        default="{}",
        server_default="{}",
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), index=True)


class ServiceTokenFailureBucket(Base):
    __tablename__ = "service_token_failure_buckets"
    __table_args__ = (
        CheckConstraint(
            "dimension IN ('global','source','token')",
            name="ck_service_token_failure_buckets_dimension",
        ),
        CheckConstraint(
            "failure_count >= 1",
            name="ck_service_token_failure_buckets_count",
        ),
        CheckConstraint(
            "event_emitted IN (0,1)",
            name="ck_service_token_failure_buckets_event_boolean",
        ),
        UniqueConstraint(
            "dimension",
            "key_hash",
            "window_start",
            name="uq_service_token_failure_bucket_key",
        ),
        Index(
            "ix_service_token_failure_buckets_expiry",
            "expires_at",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    dimension: Mapped[str] = mapped_column(String(16), nullable=False)
    key_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    window_start: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    failure_count: Mapped[int] = mapped_column(default=1, server_default="1", nullable=False)
    event_emitted: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        server_default=text("0"),
        nullable=False,
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)


class IdempotencyRecord(Base):
    __tablename__ = "idempotency_records"
    __table_args__ = (
        UniqueConstraint(
            "principal_id",
            "key_hash",
            name="uq_idempotency_records_principal_key",
        ),
        Index(
            "ix_idempotency_records_expiry",
            "expires_at",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    principal_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("principals.id", ondelete="CASCADE"),
        nullable=False,
    )
    key_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    operation_context: Mapped[str] = mapped_column(String(255), nullable=False)
    request_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    response_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
