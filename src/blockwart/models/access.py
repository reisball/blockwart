from datetime import datetime

from sqlalchemy import (
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


class ObjectGrant(Base):
    __tablename__ = "object_grants"
    __table_args__ = (
        CheckConstraint(
            "role IN "
            "('discoverer','viewer','renamer','editor','creator',"
            "'credential_reference_creator','access_manager','owner')",
            name="ck_object_grants_role",
        ),
        CheckConstraint(
            "scope IN ('self','subtree')",
            name="ck_object_grants_scope",
        ),
        UniqueConstraint(
            "principal_id",
            "object_id",
            "role",
            "scope",
            name="uq_object_grants_assignment",
        ),
        Index(
            "ix_object_grants_principal_role_scope",
            "principal_id",
            "role",
            "scope",
        ),
        Index(
            "ix_object_grants_object_principal",
            "object_id",
            "principal_id",
        ),
        Index(
            "ix_object_grants_expires_at",
            "expires_at",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    principal_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("principals.id", ondelete="RESTRICT"),
        nullable=False,
    )
    object_id: Mapped[str] = mapped_column(
        String(128),
        ForeignKey("catalog_objects.id", ondelete="RESTRICT"),
        nullable=False,
    )
    role: Mapped[str] = mapped_column(String(32))
    scope: Mapped[str] = mapped_column(String(16))
    # Null means the grant is permanent and only ends through the normal
    # revocation lifecycle. A non-null value is enforced in the request path:
    # policy computation ignores expired grants without requiring a restart.
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
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


class AccessRequest(Base):
    """One request for temporary or permanent Viewer access on one object.

    The first delivery intentionally supports exactly Viewer/self requests.
    The role and scope columns are still materialized so later deliveries can
    widen the supported roles without another table redesign.

    ``status`` is the *stored* lifecycle state and only changes through
    explicit write lifecycles (create, decide, cancel, grant revocation).
    Expiry of a requested or approved window is a fact that arrives without a
    write, so readers project it with ``effective_access_request_status``
    instead of writing it. Only ``pending`` is part of the open-request
    uniqueness rule: an approved request never blocks a replacement because
    the grant it created is what decides whether access still exists.
    """

    __tablename__ = "access_requests"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending','approved','denied','cancelled','expired','revoked')",
            name="ck_access_requests_status",
        ),
        CheckConstraint(
            "role IN ('viewer')",
            name="ck_access_requests_role_v1",
        ),
        CheckConstraint(
            "scope IN ('self')",
            name="ck_access_requests_scope_v1",
        ),
        CheckConstraint(
            "duration IN ('temporary','permanent')",
            name="ck_access_requests_duration",
        ),
        Index(
            "uq_access_requests_open",
            "requester_principal_id",
            "object_id",
            "role",
            "scope",
            unique=True,
            sqlite_where=text("status = 'pending'"),
            postgresql_where=text("status = 'pending'"),
        ),
        Index(
            "ix_access_requests_object_status",
            "object_id",
            "status",
        ),
        Index(
            "ix_access_requests_requester_created",
            "requester_principal_id",
            "created_at",
        ),
        Index(
            "ix_access_requests_grant",
            "grant_id",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    requester_principal_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("principals.id", ondelete="RESTRICT"),
        nullable=False,
    )
    object_id: Mapped[str] = mapped_column(
        String(128),
        ForeignKey("catalog_objects.id", ondelete="RESTRICT"),
        nullable=False,
    )
    role: Mapped[str] = mapped_column(String(32), default="viewer")
    scope: Mapped[str] = mapped_column(String(16), default="self")
    duration: Mapped[str] = mapped_column(String(16), default="temporary")
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)
    # Untrusted requester input: bounded and control-character stripped before
    # it is stored, redacted before any notification payload or log line.
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    requested_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )
    approved_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )
    decided_by_principal_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("principals.id", ondelete="SET NULL"),
        nullable=True,
    )
    decided_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    grant_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("object_grants.id", ondelete="SET NULL"),
        nullable=True,
    )
    # When an approved request stopped carrying access (expiry or revocation)
    # or a pending request lapsed. Written only by the explicit write
    # lifecycle that materializes the end; the original decision columns above
    # are never rewritten.
    ended_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        server_default=func.now(),
        onupdate=func.now(),
    )
