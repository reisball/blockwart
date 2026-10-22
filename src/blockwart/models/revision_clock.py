"""Persistent per-ID revision allocation, including across delete/recreate."""

from sqlalchemy import DDL, CheckConstraint, Integer, String, event
from sqlalchemy.orm import Mapped, mapped_column

from blockwart.db.base import Base


class ObjectRevisionClock(Base):
    # Deliberately no FK: deleting a catalog object must retain this clock.
    __tablename__ = "object_revision_clocks"
    __table_args__ = (CheckConstraint("revision >= 1", name="ck_object_revision_clock_positive"),)

    object_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    revision: Mapped[int] = mapped_column(Integer, nullable=False)


SQLITE_INSERT = """CREATE TRIGGER catalog_revision_allocate AFTER INSERT ON catalog_objects BEGIN
    INSERT INTO object_revision_clocks(object_id, revision) VALUES(NEW.id, NEW.revision)
    ON CONFLICT(object_id) DO UPDATE SET revision = MAX(revision + 1, NEW.revision);
    UPDATE catalog_objects SET revision = (
        SELECT revision FROM object_revision_clocks WHERE object_id = NEW.id
    ) WHERE id = NEW.id;
END"""
SQLITE_DELETE = """CREATE TRIGGER catalog_revision_retain AFTER DELETE ON catalog_objects BEGIN
    INSERT INTO object_revision_clocks(object_id, revision) VALUES(OLD.id, OLD.revision)
    ON CONFLICT(object_id) DO UPDATE SET revision = MAX(revision, OLD.revision);
END"""
PG_FUNCTION = """CREATE FUNCTION blockwart_catalog_revision() RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO object_revision_clocks(object_id, revision) VALUES(NEW.id, NEW.revision)
        ON CONFLICT(object_id) DO UPDATE
            SET revision = GREATEST(object_revision_clocks.revision + 1, NEW.revision)
        RETURNING revision INTO NEW.revision;
        RETURN NEW;
    ELSE
        INSERT INTO object_revision_clocks(object_id, revision) VALUES(OLD.id, OLD.revision)
        ON CONFLICT(object_id) DO UPDATE
            SET revision = GREATEST(object_revision_clocks.revision, OLD.revision);
        RETURN OLD;
    END IF;
END; $$ LANGUAGE plpgsql"""
PG_INSERT = """CREATE TRIGGER catalog_revision_allocate BEFORE INSERT ON catalog_objects
FOR EACH ROW EXECUTE FUNCTION blockwart_catalog_revision()"""
PG_DELETE = """CREATE TRIGGER catalog_revision_retain AFTER DELETE ON catalog_objects
FOR EACH ROW EXECUTE FUNCTION blockwart_catalog_revision()"""

for dialect, statements in (
    ("sqlite", (SQLITE_INSERT, SQLITE_DELETE)),
    ("postgresql", (PG_FUNCTION, PG_INSERT, PG_DELETE)),
):
    for statement in statements:
        event.listen(
            ObjectRevisionClock.__table__,
            "after_create",
            DDL(statement).execute_if(dialect=dialect),
        )

event.listen(
    Base.metadata,
    "after_drop",
    DDL("DROP FUNCTION IF EXISTS blockwart_catalog_revision()").execute_if(dialect="postgresql"),
)
