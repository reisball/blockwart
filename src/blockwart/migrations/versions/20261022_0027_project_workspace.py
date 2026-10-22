"""Add project records without rewriting any existing project or chronology.

Revision ID: 20261022_0027
Revises: 20260926_0026
"""

import sqlalchemy as sa
from alembic import op

revision = "20261022_0027"
down_revision = "20260926_0026"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "project_records",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("project_instance_id", sa.String(32), nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("data_json", sa.Text(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.CheckConstraint("kind IN ('item','page','access')", name="ck_project_records_kind"),
        sa.CheckConstraint("version >= 1", name="ck_project_records_version"),
    )
    op.create_index(
        "ix_project_records_instance_kind_id",
        "project_records",
        ["project_instance_id", "kind", "id"],
    )
    op.create_table(
        "project_record_versions",
        sa.Column("entry_id", sa.String(36), primary_key=True),
        sa.Column("version", sa.Integer(), primary_key=True),
        sa.Column("data_json", sa.Text(), nullable=False),
        sa.Column("author_id", sa.String(36), nullable=False),
        sa.Column("author_label", sa.String(255), nullable=False),
        sa.Column("origin", sa.String(16), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
    )

    for operation in ("update", "delete"):
        if op.get_bind().dialect.name == "sqlite":
            op.execute(
                f"CREATE TRIGGER project_versions_no_{operation} "
                f"BEFORE {operation.upper()} ON project_record_versions BEGIN "
                "SELECT RAISE(ABORT, 'project record history is append-only'); END"
            )
        else:
            op.execute(
                f"CREATE TRIGGER project_versions_no_{operation} "
                f"BEFORE {operation.upper()} ON project_record_versions "
                "FOR EACH ROW EXECUTE FUNCTION blockwart_raise_exception()"
            )


def downgrade() -> None:
    if op.get_bind().scalar(sa.text("SELECT count(*) FROM project_records")):
        raise RuntimeError("Refusing to discard project workspace records; export first")
    if op.get_bind().scalar(sa.text("SELECT count(*) FROM project_record_versions")):
        raise RuntimeError("Refusing to discard project history; export first")
    if op.get_bind().dialect.name == "postgresql":
        for operation in ("update", "delete"):
            op.execute(f"DROP TRIGGER project_versions_no_{operation} ON project_record_versions")
    op.drop_table("project_record_versions")
    op.drop_index("ix_project_records_instance_kind_id", table_name="project_records")
    op.drop_table("project_records")
