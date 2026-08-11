from datetime import datetime
from uuid import uuid4

from sqlalchemy import (
    DDL,
    CheckConstraint,
    DateTime,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    event,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from blockwart.db.base import Base


class CatalogObject(Base):
    __tablename__ = "catalog_objects"
    __table_args__ = (
        UniqueConstraint(
            "instance_id",
            name="uq_catalog_objects_instance_id",
        ),
        CheckConstraint(
            "revision >= 1",
            name="ck_catalog_objects_revision_positive",
        ),
        CheckConstraint(
            "lifecycle IS NULL OR lifecycle IN ('planned','active','retired')",
            name="ck_catalog_objects_lifecycle",
        ),
        CheckConstraint(
            "health IS NULL OR health IN ('unknown','healthy','degraded','down','maintenance')",
            name="ck_catalog_objects_health",
        ),
        CheckConstraint(
            "(kind IN ('host','system','network','device','service') "
            "AND lifecycle IS NOT NULL AND health IS NOT NULL) OR "
            "(kind NOT IN ('host','system','network','device','service') "
            "AND lifecycle IS NULL AND health IS NULL)",
            name="ck_catalog_objects_asset_state",
        ),
        CheckConstraint(
            "lifecycle IS NULL OR "
            "(lifecycle = 'planned' AND status = 'inactive') OR "
            "(lifecycle = 'retired' AND status = 'deleted') OR "
            "(lifecycle = 'active' AND health IN ('down','maintenance') "
            "AND status = 'inactive') OR "
            "(lifecycle = 'active' AND health IN ('unknown','healthy','degraded') "
            "AND status = 'active')",
            name="ck_catalog_objects_compatibility_status",
        ),
    )

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    instance_id: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=lambda: uuid4().hex,
    )
    kind: Mapped[str] = mapped_column(String(64), index=True)
    label: Mapped[str] = mapped_column(String(255), index=True)
    status: Mapped[str] = mapped_column(String(64), default="unknown")
    lifecycle: Mapped[str | None] = mapped_column(String(32), nullable=True)
    health: Mapped[str | None] = mapped_column(String(32), nullable=True)
    summary: Mapped[str | None] = mapped_column(Text)
    data_json: Mapped[str] = mapped_column(Text, default="{}")
    provenance_json: Mapped[str] = mapped_column(
        Text,
        default='{"manual_override":false,"source_type":"unknown"}',
        server_default='{"manual_override":false,"source_type":"unknown"}',
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
            "('hosts','depends_on','supports','feeds','exposes','documents','uses','related_to',"
            "'attached_to','uplinks_to')",
            name="ck_relationships_known_type",
        ),
        Index(
            "uq_relationships_placement_parent",
            "to_ref",
            unique=True,
            sqlite_where=text("relation_type = 'hosts'"),
            postgresql_where=text("relation_type = 'hosts'"),
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    from_ref: Mapped[str] = mapped_column(String(192), index=True)
    relation_type: Mapped[str] = mapped_column(String(96), index=True)
    to_ref: Mapped[str] = mapped_column(String(192), index=True)
    metadata_json: Mapped[str] = mapped_column(
        Text,
        default="{}",
        server_default=text("'{}'"),
    )


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    object_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(96))
    actor: Mapped[str] = mapped_column(String(128), default="system")
    summary: Mapped[str] = mapped_column(Text)
    details_json: Mapped[str] = mapped_column(
        Text,
        default='{"event":"legacy","version":1}',
        server_default='{"event":"legacy","version":1}',
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class ObjectComment(Base):
    """Immutable, object-instance-scoped operational comment."""

    __tablename__ = "object_comments"
    __table_args__ = (
        CheckConstraint(
            "origin IN ('ui','api','mcp','legacy')",
            name="ck_object_comments_origin",
        ),
        CheckConstraint(
            "format IN ('markdown','plain_text')",
            name="ck_object_comments_format",
        ),
        CheckConstraint(
            "origin = 'legacy' OR length(body) > 0",
            name="ck_object_comments_body_nonempty",
        ),
        CheckConstraint(
            "format <> 'markdown' OR length(body) <= 4000",
            name="ck_object_comments_markdown_length",
        ),
        CheckConstraint(
            "(origin = 'legacy' AND format = 'plain_text' "
            "AND author_principal_id IS NULL AND author_login IS NULL "
            "AND author_display_name IS NULL AND author_principal_type IS NULL) OR "
            "(origin <> 'legacy' AND format = 'markdown' "
            "AND author_principal_id IS NOT NULL AND author_login IS NOT NULL "
            "AND author_display_name IS NOT NULL AND author_principal_type IS NOT NULL)",
            name="ck_object_comments_attribution",
        ),
        Index(
            "ix_object_comments_instance_created",
            "object_id",
            "object_instance_id",
            "object_created_at",
            "created_at",
            "id",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    object_id: Mapped[str] = mapped_column(String(128), nullable=False)
    object_instance_id: Mapped[str] = mapped_column(String(32), nullable=False)
    object_created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    author_principal_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    author_login: Mapped[str | None] = mapped_column(String(128), nullable=True)
    author_display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    author_principal_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    origin: Mapped[str] = mapped_column(String(16), nullable=False)
    format: Mapped[str] = mapped_column(String(16), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)


event.listen(
    ObjectComment.__table__,
    "after_create",
    DDL(
        "CREATE TRIGGER object_comments_no_update "
        "BEFORE UPDATE ON object_comments BEGIN "
        "SELECT RAISE(ABORT, 'object comments are append-only'); END"
    ).execute_if(dialect="sqlite"),
)
event.listen(
    ObjectComment.__table__,
    "after_create",
    DDL(
        "CREATE TRIGGER object_comments_no_delete "
        "BEFORE DELETE ON object_comments BEGIN "
        "SELECT RAISE(ABORT, 'object comments are append-only'); END"
    ).execute_if(dialect="sqlite"),
)
event.listen(
    ObjectComment.__table__,
    "after_create",
    DDL(
        "CREATE OR REPLACE FUNCTION blockwart_raise_exception() "
        "RETURNS TRIGGER AS $$ BEGIN RAISE EXCEPTION 'operation blocked by trigger'; END; $$ LANGUAGE plpgsql"  # noqa: E501
    ).execute_if(dialect="postgresql"),
)
event.listen(
    ObjectComment.__table__,
    "after_create",
    DDL(
        "CREATE TRIGGER object_comments_no_update "
        "BEFORE UPDATE ON object_comments "
        "FOR EACH ROW EXECUTE FUNCTION blockwart_raise_exception()"
    ).execute_if(dialect="postgresql"),
)
event.listen(
    ObjectComment.__table__,
    "after_create",
    DDL(
        "CREATE TRIGGER object_comments_no_delete "
        "BEFORE DELETE ON object_comments "
        "FOR EACH ROW EXECUTE FUNCTION blockwart_raise_exception()"
    ).execute_if(dialect="postgresql"),
)


event.listen(
    CatalogObject.__table__,
    "after_create",
    DDL(
        "ALTER TABLE catalog_objects ALTER COLUMN instance_id "
        "SET DEFAULT md5(random()::text || clock_timestamp()::text)"
    ).execute_if(dialect="postgresql"),
)
# SQLite: ALTER TABLE ... ALTER COLUMN is not supported.
# The Python-side default (uuid4().hex) handles instance_id on insert.
# For raw SQL inserts, a trigger would be needed — but migrations cover that path.
