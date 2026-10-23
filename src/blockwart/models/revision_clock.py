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
SQLITE_UPDATE = """CREATE TRIGGER catalog_revision_advance AFTER UPDATE ON catalog_objects BEGIN
    INSERT INTO object_revision_clocks(object_id, revision) VALUES(NEW.id,
        CASE WHEN NEW.revision <= OLD.revision AND (
            NEW.revision < OLD.revision OR
            (NEW.id, NEW.instance_id, NEW.kind, NEW.label, NEW.status, NEW.lifecycle,
             NEW.health, NEW.summary, NEW.data_json, NEW.provenance_json,
             NEW.created_at, NEW.updated_at) IS NOT
            (OLD.id, OLD.instance_id, OLD.kind, OLD.label, OLD.status, OLD.lifecycle,
             OLD.health, OLD.summary, OLD.data_json, OLD.provenance_json,
             OLD.created_at, OLD.updated_at)
        ) THEN OLD.revision + 1 ELSE NEW.revision END)
    ON CONFLICT(object_id) DO UPDATE SET revision = MAX(
        revision + CASE WHEN NEW.id IS NOT OLD.id THEN 1 ELSE 0 END, excluded.revision);
    UPDATE catalog_objects SET revision = (
        SELECT revision FROM object_revision_clocks WHERE object_id = NEW.id
    ) WHERE id = NEW.id AND revision < (
        SELECT revision FROM object_revision_clocks WHERE object_id = NEW.id
    );
END"""
SQLITE_DELETE = """CREATE TRIGGER catalog_revision_retain AFTER DELETE ON catalog_objects BEGIN
    INSERT INTO object_revision_clocks(object_id, revision) VALUES(OLD.id, OLD.revision)
    ON CONFLICT(object_id) DO UPDATE SET revision = MAX(revision, OLD.revision);
END"""
PG_FUNCTION = """CREATE FUNCTION blockwart_catalog_revision() RETURNS TRIGGER AS $$
DECLARE allocated_revision integer;
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO object_revision_clocks(object_id, revision) VALUES(NEW.id, NEW.revision)
        ON CONFLICT(object_id) DO UPDATE
            SET revision = GREATEST(object_revision_clocks.revision + 1, NEW.revision)
        RETURNING revision INTO allocated_revision;
        UPDATE catalog_objects SET revision = allocated_revision
        WHERE id = NEW.id AND revision < allocated_revision;
        RETURN NEW;
    ELSIF TG_OP = 'UPDATE' THEN
        IF NEW.revision <= OLD.revision AND NEW IS DISTINCT FROM OLD THEN
            NEW.revision := OLD.revision + 1;
        END IF;
        INSERT INTO object_revision_clocks(object_id, revision) VALUES(NEW.id, NEW.revision)
        ON CONFLICT(object_id) DO UPDATE SET revision = GREATEST(
            object_revision_clocks.revision +
                CASE WHEN NEW.id IS DISTINCT FROM OLD.id THEN 1 ELSE 0 END,
            NEW.revision)
        RETURNING revision INTO NEW.revision;
        RETURN NEW;
    ELSE
        INSERT INTO object_revision_clocks(object_id, revision) VALUES(OLD.id, OLD.revision)
        ON CONFLICT(object_id) DO UPDATE
            SET revision = GREATEST(object_revision_clocks.revision, OLD.revision);
        RETURN OLD;
    END IF;
END; $$ LANGUAGE plpgsql"""
PG_INSERT = """CREATE TRIGGER catalog_revision_allocate AFTER INSERT ON catalog_objects
FOR EACH ROW EXECUTE FUNCTION blockwart_catalog_revision()"""
PG_UPDATE = """CREATE TRIGGER catalog_revision_advance BEFORE UPDATE ON catalog_objects
FOR EACH ROW EXECUTE FUNCTION blockwart_catalog_revision()"""
PG_DELETE = """CREATE TRIGGER catalog_revision_retain AFTER DELETE ON catalog_objects
FOR EACH ROW EXECUTE FUNCTION blockwart_catalog_revision()"""

for dialect, statements in (
    ("sqlite", (SQLITE_INSERT, SQLITE_UPDATE, SQLITE_DELETE)),
    ("postgresql", (PG_FUNCTION, PG_INSERT, PG_UPDATE, PG_DELETE)),
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
