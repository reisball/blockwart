"""allow gatus as monitoring provider in CHECK constraints

Revision ID: 20260819_0019
Revises: 20260818_0018

The CHECK constraints on ``service_observations.provider`` and
``service_check_leases.provider`` are rebuilt to accept ``'gatus'``
beside ``'builtin_http'``. This is a constraint widening — no data is
migrated, no column changes type, and no existing row is altered.

The gatus provider is push-based and never creates lease rows, so only
the observation table will ever store ``provider='gatus'`` in practice.
The lease constraint is widened for symmetry and forward safety.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "20260819_0019"
down_revision: str | Sequence[str] | None = "20260818_0018"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_PROVIDERS = "'builtin_http','gatus'"


def upgrade() -> None:
    op.drop_constraint(
        "ck_service_observations_provider",
        "service_observations",
        type_="check",
    )
    op.create_check_constraint(
        "ck_service_observations_provider",
        "service_observations",
        f"provider IN ({_PROVIDERS})",
    )
    op.drop_constraint(
        "ck_service_check_leases_provider",
        "service_check_leases",
        type_="check",
    )
    op.create_check_constraint(
        "ck_service_check_leases_provider",
        "service_check_leases",
        f"provider IN ({_PROVIDERS})",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_service_check_leases_provider",
        "service_check_leases",
        type_="check",
    )
    op.create_check_constraint(
        "ck_service_check_leases_provider",
        "service_check_leases",
        "provider IN ('builtin_http')",
    )
    op.drop_constraint(
        "ck_service_observations_provider",
        "service_observations",
        type_="check",
    )
    op.create_check_constraint(
        "ck_service_observations_provider",
        "service_observations",
        "provider IN ('builtin_http')",
    )
