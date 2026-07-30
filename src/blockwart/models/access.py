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


class ObjectGrant(Base):
    __tablename__ = "object_grants"
    __table_args__ = (
        CheckConstraint(
            "role IN "
            "('discoverer','viewer','editor','creator','access_manager','owner')",
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
