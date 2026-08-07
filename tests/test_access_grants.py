from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from blockwart.db.session import DatabaseTransactionError, transaction
from blockwart.domain.auth import CatalogRole, GrantScope, Role
from blockwart.models import (
    AuditEvent,
    CatalogObject,
    ObjectGrant,
    Principal,
    Relationship,
)
from blockwart.services.access import (
    LastOwnerError,
    OwnerCoverageError,
    active_catalog_owner_ids,
    active_owner_covered_object_ids,
    create_object_grant,
    ensure_complete_owner_coverage,
    ensure_owner_coverage_after_exclusions,
    revoke_object_grant,
)
from blockwart.services.catalog import delete_relationship
from blockwart.services.identity import (
    IdentityConflict,
    create_service_account,
    deactivate_principal,
)


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


def test_principal_deactivation_requires_replacement_owner_for_every_descendant(
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
                login="deactivate.first",
                display_name="First Owner",
            )
            second = create_service_account(
                session,
                login="deactivate.second",
                display_name="Second Owner",
            )
            create_object_grant(
                session,
                principal_id=first.id,
                object_id="root",
                role=Role.OWNER,
                scope=GrantScope.SUBTREE,
            )

        with pytest.raises(LastOwnerError):
            with transaction(session):
                deactivate_principal(session, principal_id=first.id)
        assert session.get(Principal, first.id).active is True

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
                deactivate_principal(session, principal_id=first.id)

        with transaction(session):
            create_object_grant(
                session,
                principal_id=second.id,
                object_id="root",
                role=Role.OWNER,
                scope=GrantScope.SUBTREE,
            )
            assert deactivate_principal(session, principal_id=first.id)
        assert session.get(Principal, first.id).active is False


def test_placement_removal_cannot_drop_last_effective_owner(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            session.add_all([_asset("root", "host"), _asset("child", "service")])
            session.flush()
            placement = Relationship(
                from_ref="host:root",
                relation_type="hosts",
                to_ref="service:child",
            )
            session.add(placement)
            first = create_service_account(
                session,
                login="placement.first",
                display_name="Placement Owner",
            )
            replacement = create_service_account(
                session,
                login="placement.replacement",
                display_name="Replacement Owner",
            )
            create_object_grant(
                session,
                principal_id=first.id,
                object_id="root",
                role=Role.OWNER,
                scope=GrantScope.SUBTREE,
            )
            session.flush()
            placement_id = placement.id

        with pytest.raises(LastOwnerError):
            with transaction(session):
                delete_relationship(session, placement_id)
        assert session.get(Relationship, placement_id) is not None

        with transaction(session):
            create_object_grant(
                session,
                principal_id=replacement.id,
                object_id="child",
                role=Role.OWNER,
                scope=GrantScope.SELF,
            )
            assert delete_relationship(session, placement_id)
        assert session.get(Relationship, placement_id) is None


def _catalog_owner(session, login: str):
    return create_service_account(
        session,
        login=login,
        display_name=login.replace(".", " ").title(),
        catalog_role=CatalogRole.CATALOG_OWNER,
    )


def test_active_catalog_owner_covers_every_object_without_creating_grants(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            session.add_all([_asset("anchor", "host"), _asset("island", "host")])
            owner = _catalog_owner(session, "coverage.owner")

        covered = active_owner_covered_object_ids(session)
        ensure_complete_owner_coverage(session)
        grants = session.scalars(select(ObjectGrant)).all()

    assert covered == {"anchor", "island"}
    assert list(grants) == []
    assert owner.catalog_role == CatalogRole.CATALOG_OWNER


def test_owner_coverage_codes_stay_stable_and_add_the_catalog_owner_gate(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        with pytest.raises(OwnerCoverageError) as empty:
            ensure_complete_owner_coverage(session)
        assert empty.value.code == "owner_catalog_empty"

        with transaction(session):
            session.add_all([_asset("anchor", "host"), _asset("island", "host")])
            principal = create_service_account(
                session,
                login="scoped.owner",
                display_name="Scoped Owner",
            )
            create_object_grant(
                session,
                principal_id=principal.id,
                object_id="anchor",
                role=Role.OWNER,
                scope=GrantScope.SUBTREE,
            )

        with pytest.raises(OwnerCoverageError) as partial:
            ensure_complete_owner_coverage(session)
        assert partial.value.code == "owner_coverage_incomplete"

        with transaction(session):
            create_object_grant(
                session,
                principal_id=principal.id,
                object_id="island",
                role=Role.OWNER,
                scope=GrantScope.SUBTREE,
            )

        # Complete legacy Owner coverage never substitutes for the global role.
        with pytest.raises(OwnerCoverageError) as gated:
            ensure_complete_owner_coverage(session)
        assert gated.value.code == "catalog_owner_missing"
        ensure_complete_owner_coverage(session, require_catalog_owner=False)

        with transaction(session):
            _catalog_owner(session, "activating.owner")
        ensure_complete_owner_coverage(session)


def test_exclusion_ignores_the_excluded_catalog_owner_but_keeps_other_sources(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            session.add_all([_asset("anchor", "host"), _asset("island", "host")])
            excluded = _catalog_owner(session, "excluded.owner")
            other = _catalog_owner(session, "other.owner")
            scoped = create_service_account(
                session,
                login="exclusion.scoped.owner",
                display_name="Exclusion Scoped Owner",
            )
            create_object_grant(
                session,
                principal_id=scoped.id,
                object_id="anchor",
                role=Role.OWNER,
                scope=GrantScope.SELF,
            )

        assert active_owner_covered_object_ids(
            session,
            excluded_principal_ids=(excluded.id,),
        ) == {"anchor", "island"}
        # Without any remaining global owner only the scoped grant covers.
        assert active_owner_covered_object_ids(
            session,
            excluded_principal_ids=(excluded.id, other.id),
        ) == {"anchor"}
        ensure_owner_coverage_after_exclusions(
            session,
            excluded_principal_ids=(excluded.id,),
        )
        with pytest.raises(LastOwnerError):
            ensure_owner_coverage_after_exclusions(
                session,
                excluded_principal_ids=(excluded.id, other.id),
            )


def test_last_active_catalog_owner_cannot_be_deactivated_through_the_service(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            session.add(_asset("anchor", "host"))
            owner = _catalog_owner(session, "single.owner")
            create_object_grant(
                session,
                principal_id=owner.id,
                object_id="anchor",
                role=Role.OWNER,
                scope=GrantScope.SELF,
            )

        with pytest.raises(IdentityConflict):
            with transaction(session):
                deactivate_principal(session, principal_id=owner.id)

        with transaction(session):
            standby = _catalog_owner(session, "standby.owner")
        with transaction(session):
            assert deactivate_principal(session, principal_id=owner.id) is True

        stored = session.get(Principal, owner.id)
        assert stored is not None
        assert stored.active is False
        assert stored.catalog_role == CatalogRole.CATALOG_OWNER
        assert active_catalog_owner_ids(session) == {standby.id}


def test_concurrent_writers_cannot_remove_the_last_active_catalog_owner(
    alembic_database,
) -> None:
    session_factory = alembic_database.sessions
    with session_factory() as session:
        with transaction(session):
            first = _catalog_owner(session, "race.first.owner")
            second = _catalog_owner(session, "race.second.owner")
        owner_ids = [first.id, second.id]

    def demote(principal_id: str) -> bool:
        with session_factory() as session:
            try:
                with transaction(session):
                    session.execute(
                        update(Principal)
                        .where(Principal.id == principal_id)
                        .values(catalog_role=None)
                    )
            except DatabaseTransactionError:
                return False
        return True

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(demote, owner_ids))

    assert sorted(results) == [False, True]
    with session_factory() as session:
        assert len(active_catalog_owner_ids(session)) == 1
