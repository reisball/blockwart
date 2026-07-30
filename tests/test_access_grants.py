import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from blockwart.db.session import transaction
from blockwart.domain.auth import GrantScope, Role
from blockwart.models import AuditEvent, CatalogObject, ObjectGrant, Relationship
from blockwart.services.access import (
    LastOwnerError,
    create_object_grant,
    revoke_object_grant,
)
from blockwart.services.identity import create_service_account


def _asset(object_id: str, kind: str) -> CatalogObject:
    return CatalogObject(
        id=object_id,
        kind=kind,
        label=object_id,
        status="active",
        lifecycle="active",
        health="healthy",
        summary=None,
        data_json="{}",
        provenance_json='{"manual_override":false,"source_type":"unknown"}',
    )


def test_grant_create_is_idempotent_and_bumps_anchor_revision_once(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            session.add(_asset("anchor", "host"))
            principal = create_service_account(
                session,
                login="grant.viewer",
                display_name="Grant Viewer",
            )
            session.flush()
            grant = create_object_grant(
                session,
                principal_id=principal.id,
                object_id="anchor",
                role=Role.VIEWER,
                scope=GrantScope.SELF,
                actor_principal_id=principal.id,
                channel="cli",
                request_id="grant-create-1",
            )
            repeated = create_object_grant(
                session,
                principal_id=principal.id,
                object_id="anchor",
                role=Role.VIEWER,
                scope=GrantScope.SELF,
                actor_principal_id=principal.id,
            )

        anchor = session.get(CatalogObject, "anchor")
        assert anchor is not None
        assert anchor.revision == 2
        assert repeated.id == grant.id
        events = list(
            session.scalars(
                select(AuditEvent).where(AuditEvent.action == "grant_create")
            ).all()
        )
        assert len(events) == 1
        assert events[0].actor == principal.id
        assert '"old_revision":1' in events[0].details_json
        assert '"new_revision":2' in events[0].details_json


def test_database_constraints_reject_duplicate_and_dangling_grants(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            session.add(_asset("anchor", "host"))
            principal = create_service_account(
                session,
                login="constraint.viewer",
                display_name="Constraint Viewer",
            )
            session.add(
                ObjectGrant(
                    principal_id=principal.id,
                    object_id="anchor",
                    role=Role.VIEWER,
                    scope=GrantScope.SELF,
                )
            )
        session.add(
            ObjectGrant(
                principal_id=principal.id,
                object_id="anchor",
                role=Role.VIEWER,
                scope=GrantScope.SELF,
            )
        )
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()

        session.add(
            ObjectGrant(
                principal_id=principal.id,
                object_id="missing-object",
                role=Role.VIEWER,
                scope=GrantScope.SELF,
            )
        )
        with pytest.raises(IntegrityError):
            session.commit()


def test_last_owner_guard_covers_every_descendant_of_subtree_grant(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            session.add_all(
                [
                    _asset("root", "host"),
                    _asset("child", "system"),
                    _asset("service", "service"),
                ]
            )
            session.flush()
            session.add_all(
                [
                    Relationship(
                        from_ref="host:root",
                        relation_type="hosts",
                        to_ref="system:child",
                    ),
                    Relationship(
                        from_ref="system:child",
                        relation_type="hosts",
                        to_ref="service:service",
                    ),
                ]
            )
            first = create_service_account(
                session,
                login="owner.first",
                display_name="First Owner",
            )
            second = create_service_account(
                session,
                login="owner.second",
                display_name="Second Owner",
            )
            first_grant = create_object_grant(
                session,
                principal_id=first.id,
                object_id="root",
                role=Role.OWNER,
                scope=GrantScope.SUBTREE,
            )

        with pytest.raises(LastOwnerError):
            with transaction(session):
                revoke_object_grant(
                    session,
                    grant_id=first_grant.id,
                )

        with transaction(session):
            create_object_grant(
                session,
                principal_id=second.id,
                object_id="root",
                role=Role.OWNER,
                scope=GrantScope.SELF,
            )
        with pytest.raises(LastOwnerError):
            with transaction(session):
                revoke_object_grant(
                    session,
                    grant_id=first_grant.id,
                )

        with transaction(session):
            create_object_grant(
                session,
                principal_id=second.id,
                object_id="root",
                role=Role.OWNER,
                scope=GrantScope.SUBTREE,
            )
            assert revoke_object_grant(
                session,
                grant_id=first_grant.id,
                actor_principal_id=second.id,
                channel="ui",
                request_id="grant-revoke-1",
            )

        assert session.get(ObjectGrant, first_grant.id) is None
        root = session.get(CatalogObject, "root")
        assert root is not None
        assert root.revision == 5
        event = session.scalar(
            select(AuditEvent)
            .where(AuditEvent.action == "grant_revoke")
            .order_by(AuditEvent.id.desc())
        )
        assert event is not None
        assert event.actor == second.id
