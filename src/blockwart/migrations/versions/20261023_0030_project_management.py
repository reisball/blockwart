"""Typed PM records, stable codes, and append-only task events. Refs #287.

Only the workspace table check is widened; record JSON, IDs and history are
not interpreted or reclassified. SQLite batch-copy preserves all rows.
"""

import sqlalchemy as sa
from alembic import op

revision = "20261023_0030"
down_revision = "20261022_0029"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("project_records") as batch:
        batch.drop_constraint("ck_project_records_kind", type_="check")
        batch.create_check_constraint(
            "ck_project_records_kind", "kind IN ('item','page','access','repository')"
        )
        batch.add_column(sa.Column("short_code", sa.String(32), nullable=True))
        batch.add_column(
            sa.Column("requirement_revision", sa.Integer(), nullable=False, server_default="1")
        )
    bind = op.get_bind()
    rows = bind.execute(
        sa.text("SELECT id,project_instance_id FROM project_records ORDER BY created_at,id")
    ).all()
    counters = {}
    for identity, instance in rows:
        counters[instance] = counters.get(instance, 0) + 1
        bind.execute(
            sa.text("UPDATE project_records SET short_code=:code WHERE id=:id"),
            {"code": f"REC-{counters[instance]:05d}", "id": identity},
        )
    op.create_index(
        "uq_project_record_code",
        "project_records",
        ["project_instance_id", "short_code"],
        unique=True,
    )
    op.create_table(
        "project_record_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("project_instance_id", sa.String(32), nullable=False),
        sa.Column("record_id", sa.String(36), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("data_json", sa.Text(), nullable=False),
        sa.Column("author_id", sa.String(36), nullable=False),
        sa.Column("author_label", sa.String(255), nullable=False),
        sa.Column("origin", sa.String(16), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    for field in ("project_instance_id", "record_id"):
        op.create_index(f"ix_project_record_events_{field}", "project_record_events", [field])
    for operation in ("update", "delete"):
        if bind.dialect.name == "sqlite":
            op.execute(
                f"CREATE TRIGGER project_events_no_{operation} "
                f"BEFORE {operation.upper()} ON project_record_events BEGIN "
                "SELECT RAISE(ABORT, 'project event history is append-only'); END"
            )
        else:
            op.execute(
                f"CREATE TRIGGER project_events_no_{operation} "
                f"BEFORE {operation.upper()} ON project_record_events "
                "FOR EACH ROW EXECUTE FUNCTION blockwart_raise_exception()"
            )


def downgrade():
    bind = op.get_bind()
    if bind.scalar(sa.text("SELECT count(*) FROM project_record_events")) or bind.scalar(
        sa.text("SELECT count(*) FROM project_records")
    ):
        raise RuntimeError("Refusing PM downgrade with data; restore a verified pre-upgrade backup")
    if bind.dialect.name == "postgresql":
        for operation in ("update", "delete"):
            op.execute(f"DROP TRIGGER project_events_no_{operation} ON project_record_events")
    op.drop_table("project_record_events")
    op.drop_index("uq_project_record_code", table_name="project_records")
    with op.batch_alter_table("project_records") as batch:
        batch.drop_constraint("ck_project_records_kind", type_="check")
        batch.create_check_constraint("ck_project_records_kind", "kind IN ('item','page','access')")
        batch.drop_column("short_code")
        batch.drop_column("requirement_revision")
