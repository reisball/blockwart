"""Value-free operation custody; deliberately survives object/principal deletion."""
from sqlalchemy import CheckConstraint, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from blockwart.db.base import Base


class SafeOperation(Base):
    __tablename__ = "safe_operations"
    __table_args__ = (
        CheckConstraint("state IN ('intent','dispatched','succeeded','conflict','failed')",
                        name="ck_safe_operation_state"),
    )
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    actor: Mapped[str] = mapped_column(String(128))
    channel: Mapped[str] = mapped_column(String(32))
    object_id: Mapped[str] = mapped_column(String(128))
    instance_id: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(16))
    cas: Mapped[int] = mapped_column(Integer)
    source_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    state: Mapped[str] = mapped_column(String(16), default="intent")
    result_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
