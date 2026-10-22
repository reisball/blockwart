"""Additive project records; identity is bound to a catalog object instance."""

from datetime import datetime

from sqlalchemy import DDL, CheckConstraint, DateTime, Index, Integer, String, Text, event
from sqlalchemy.orm import Mapped, mapped_column

from blockwart.db.base import Base


class ProjectRecord(Base):
    __tablename__ = "project_records"
    __table_args__ = (
        CheckConstraint("kind IN ('item','page','access')", name="ck_project_records_kind"),
        CheckConstraint("version >= 1", name="ck_project_records_version"),
        Index("ix_project_records_instance_kind_id", "project_instance_id", "kind", "id"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    project_instance_id: Mapped[str] = mapped_column(String(32), nullable=False)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    data_json: Mapped[str] = mapped_column(Text, nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class ProjectRecordVersion(Base):
    __tablename__ = "project_record_versions"
    entry_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    data_json: Mapped[str] = mapped_column(Text, nullable=False)
    author_id: Mapped[str] = mapped_column(String(36), nullable=False)
    author_label: Mapped[str] = mapped_column(String(255), nullable=False)
    origin: Mapped[str] = mapped_column(String(16), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


for operation in ("update", "delete"):
    event.listen(
        ProjectRecordVersion.__table__,
        "after_create",
        DDL(
            f"CREATE TRIGGER project_versions_no_{operation} BEFORE {operation.upper()} "
            "ON project_record_versions BEGIN "
            "SELECT RAISE(ABORT, 'project record history is append-only'); END"
        ).execute_if(dialect="sqlite"),
    )
    event.listen(
        ProjectRecordVersion.__table__,
        "after_create",
        DDL(
            f"CREATE TRIGGER project_versions_no_{operation} BEFORE {operation.upper()} "
            "ON project_record_versions FOR EACH ROW EXECUTE FUNCTION blockwart_raise_exception()"
        ).execute_if(dialect="postgresql"),
    )
