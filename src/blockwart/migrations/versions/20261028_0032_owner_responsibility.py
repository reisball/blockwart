"""Explicit Owner responsibility and single-target Operations Runbooks. Refs #320."""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20261028_0032"
down_revision = "20261026_0031"
branch_labels = None
depends_on = None

_OLD_SCOPE = "scope IN ('self','subtree')"
_NEW_SCOPE = "scope IN ('self','subtree','responsibility')"
_OLD_TYPES = (
    "relation_type IN "
    "('hosts','depends_on','supports','feeds','exposes','documents','uses','related_to',"
    "'attached_to','uplinks_to')"
)
_NEW_TYPES = _OLD_TYPES[:-1] + ",'operations_runbook_for')"
_INDEX = "uq_relationships_operations_runbook_target"


def _checks(table, checks):
    if op.get_bind().dialect.name == "sqlite":
        with op.batch_alter_table(table, recreate="always") as batch:
            for name, expression in checks:
                if expression is None:
                    batch.drop_constraint(name, type_="check")
                else:
                    batch.create_check_constraint(name, expression)
    else:
        for name, expression in checks:
            if expression is None:
                op.drop_constraint(name, table, type_="check")
            else:
                op.create_check_constraint(name, table, expression)


def upgrade() -> None:
    _checks("object_grants", [
        ("ck_object_grants_scope", None), ("ck_object_grants_scope", _NEW_SCOPE),
        ("ck_object_grants_responsibility_owner", "scope <> 'responsibility' OR role = 'owner'"),
    ])
    _checks("relationships", [
        ("ck_relationships_known_type", None), ("ck_relationships_known_type", _NEW_TYPES),
    ])
    op.create_index(
        _INDEX, "relationships", ["from_ref"], unique=True,
        sqlite_where=sa.text("relation_type = 'operations_runbook_for'"),
        postgresql_where=sa.text("relation_type = 'operations_runbook_for'"),
    )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        bind.execute(sa.text("LOCK TABLE object_grants, relationships IN ACCESS EXCLUSIVE MODE"))
    grants = bind.scalar(sa.text(
        "SELECT count(*) FROM object_grants WHERE scope = 'responsibility'"
    ))
    links = bind.scalar(sa.text(
        "SELECT count(*) FROM relationships WHERE relation_type = 'operations_runbook_for'"
    ))
    if grants or links:
        raise RuntimeError(
            "Revoke responsibility grants and Operations links explicitly before downgrade; "
            "restore the paired backup for rollback instead of reinterpreting authority"
        )
    op.drop_index(_INDEX, table_name="relationships")
    _checks("relationships", [
        ("ck_relationships_known_type", None), ("ck_relationships_known_type", _OLD_TYPES),
    ])
    _checks("object_grants", [
        ("ck_object_grants_responsibility_owner", None),
        ("ck_object_grants_scope", None), ("ck_object_grants_scope", _OLD_SCOPE),
    ])
