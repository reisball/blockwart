from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
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


class CatalogObject(Base):
    __tablename__ = "catalog_objects"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    kind: Mapped[str] = mapped_column(String(64), index=True)
    label: Mapped[str] = mapped_column(String(255), index=True)
    status: Mapped[str] = mapped_column(String(64), default="unknown")
    summary: Mapped[str | None] = mapped_column(Text)
    data_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        server_default=func.now(),
        onupdate=func.now(),
    )


class Relationship(Base):
    __tablename__ = "relationships"
    __table_args__ = (
        UniqueConstraint(
            "from_ref",
            "relation_type",
            "to_ref",
            name="uq_relationships_triplet",
        ),
        CheckConstraint(
            "from_ref <> to_ref",
            name="ck_relationships_no_self_reference",
        ),
        CheckConstraint(
            "relation_type IN "
            "('hosts','depends_on','supports','feeds','exposes','documents','uses','related_to')",
            name="ck_relationships_known_type",
        ),
        Index(
            "uq_relationships_placement_parent",
            "to_ref",
            unique=True,
            sqlite_where=text("relation_type = 'hosts'"),
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    from_ref: Mapped[str] = mapped_column(String(192), index=True)
    relation_type: Mapped[str] = mapped_column(String(96), index=True)
    to_ref: Mapped[str] = mapped_column(String(192), index=True)


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    object_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(96))
    actor: Mapped[str] = mapped_column(String(128), default="system")
    summary: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
