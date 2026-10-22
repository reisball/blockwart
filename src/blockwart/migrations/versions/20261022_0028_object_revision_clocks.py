"""Retain per-ID revision clocks across catalog object lifecycles. Refs #272."""

import sqlalchemy as sa
from alembic import op

revision = "20261022_0028"
down_revision = "20261022_0027"
branch_labels = None
depends_on = None

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
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO object_revision_clocks(object_id, revision) VALUES(NEW.id, NEW.revision)
        ON CONFLICT(object_id) DO UPDATE
            SET revision = GREATEST(object_revision_clocks.revision + 1, NEW.revision)
        RETURNING revision INTO NEW.revision;
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
PG_INSERT = """CREATE TRIGGER catalog_revision_allocate BEFORE INSERT ON catalog_objects
FOR EACH ROW EXECUTE FUNCTION blockwart_catalog_revision()"""
PG_UPDATE = """CREATE TRIGGER catalog_revision_advance BEFORE UPDATE ON catalog_objects
FOR EACH ROW EXECUTE FUNCTION blockwart_catalog_revision()"""
PG_DELETE = """CREATE TRIGGER catalog_revision_retain AFTER DELETE ON catalog_objects
FOR EACH ROW EXECUTE FUNCTION blockwart_catalog_revision()"""


def upgrade() -> None:
    op.create_table(
        "object_revision_clocks",
        sa.Column("object_id", sa.String(128), primary_key=True),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.CheckConstraint("revision >= 1", name="ck_object_revision_clock_positive"),
    )
    op.execute("INSERT INTO object_revision_clocks SELECT id, revision FROM catalog_objects")
    statements = (
        (SQLITE_INSERT, SQLITE_UPDATE, SQLITE_DELETE)
        if op.get_bind().dialect.name == "sqlite"
        else (PG_FUNCTION, PG_INSERT, PG_UPDATE, PG_DELETE)
    )
    for statement in statements:
        op.execute(statement)


def downgrade() -> None:
    if op.get_bind().scalar(sa.text("SELECT count(*) FROM object_revision_clocks")):
        raise RuntimeError("Refusing to discard object revision history")
    suffix = " ON catalog_objects" if op.get_bind().dialect.name == "postgresql" else ""
    for name in (
        "catalog_revision_allocate",
        "catalog_revision_advance",
        "catalog_revision_retain",
    ):
        op.execute(f"DROP TRIGGER {name}{suffix}")
    if suffix:
        op.execute("DROP FUNCTION blockwart_catalog_revision()")
    op.drop_table("object_revision_clocks")
