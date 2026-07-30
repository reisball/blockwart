from sqlalchemy import event

from blockwart.db.session import transaction
from blockwart.domain.auth import (
    GrantScope,
    ObjectVisibility,
    Permission,
    Role,
    permissions_for_role,
)
from blockwart.models import CatalogObject, Principal, Relationship
from blockwart.services.access import create_object_grant
from blockwart.services.identity import create_service_account
from blockwart.services.policy import policy_for_principal


def _object(object_id: str, kind: str) -> CatalogObject:
    is_asset = kind in {"host", "system", "network", "service"}
    return CatalogObject(
        id=object_id,
        kind=kind,
        label=object_id.replace("-", " ").title(),
        status="active",
        lifecycle="active" if is_asset else None,
        health="healthy" if is_asset else None,
        summary=None,
        data_json="{}",
        provenance_json='{"manual_override":false,"source_type":"unknown"}',
    )


def _seed_fabrik(session):
    session.add_all(
        [
            _object("fabrik", "host"),
            _object("lxc-137", "system"),
            _object("blockwart", "service"),
            _object("other-host", "host"),
            _object("hidden-network", "network"),
        ]
    )
    session.flush()
    session.add_all(
        [
            Relationship(
                from_ref="host:fabrik",
                relation_type="hosts",
                to_ref="system:lxc-137",
            ),
            Relationship(
                from_ref="system:lxc-137",
                relation_type="hosts",
                to_ref="service:blockwart",
            ),
            Relationship(
                from_ref="host:fabrik",
                relation_type="hosts",
                to_ref="network:hidden-network",
            ),
        ]
    )


def test_role_matrix_is_exact_and_closed() -> None:
    assert permissions_for_role(Role.DISCOVERER) == {Permission.DISCOVER}
    assert permissions_for_role(Role.VIEWER) == {
        Permission.DISCOVER,
        Permission.READ,
    }
    assert permissions_for_role(Role.EDITOR) == {
        Permission.DISCOVER,
        Permission.READ,
        Permission.WRITE,
    }
    assert permissions_for_role(Role.CREATOR) == {
        Permission.DISCOVER,
        Permission.READ,
        Permission.CREATE_CHILD,
    }
    assert permissions_for_role(Role.ACCESS_MANAGER) == {
        Permission.DISCOVER,
        Permission.READ,
        Permission.MANAGE_ACCESS,
    }
    assert permissions_for_role(Role.OWNER) == set(Permission)


def test_fabrik_parent_detail_child_stubs_and_selected_child_detail(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            _seed_fabrik(session)
            principal = create_service_account(
                session,
                login="fabrik.viewer",
                display_name="Fabrik Viewer",
            )
            create_object_grant(
                session,
                principal_id=principal.id,
                object_id="fabrik",
                role=Role.VIEWER,
                scope=GrantScope.SELF,
            )
            create_object_grant(
                session,
                principal_id=principal.id,
                object_id="fabrik",
                role=Role.DISCOVERER,
                scope=GrantScope.SUBTREE,
            )
            create_object_grant(
                session,
                principal_id=principal.id,
                object_id="lxc-137",
                role=Role.EDITOR,
                scope=GrantScope.SELF,
            )

    with alembic_session_factory() as session:
        policy = policy_for_principal(session, principal.id)

    assert policy.visibility_for("fabrik") == ObjectVisibility.DETAIL
    assert policy.visibility_for("lxc-137") == ObjectVisibility.DETAIL
    assert policy.can(Permission.WRITE, "lxc-137")
    assert policy.visibility_for("blockwart") == ObjectVisibility.STUB
    assert not policy.can(Permission.READ, "blockwart")
    assert policy.visibility_for("other-host") == ObjectVisibility.NONE
    assert policy.visibility_for("hidden-network") == ObjectVisibility.NONE
    assert policy.authorized_ids(Permission.DISCOVER) == {
        "fabrik",
        "lxc-137",
        "blockwart",
    }


def test_combined_grants_are_additive_but_do_not_reach_parents_or_siblings(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            _seed_fabrik(session)
            principal = create_service_account(
                session,
                login="combined.grants",
                display_name="Combined Grants",
            )
            create_object_grant(
                session,
                principal_id=principal.id,
                object_id="lxc-137",
                role=Role.EDITOR,
                scope=GrantScope.SELF,
            )
            create_object_grant(
                session,
                principal_id=principal.id,
                object_id="lxc-137",
                role=Role.CREATOR,
                scope=GrantScope.SELF,
            )
        policy = policy_for_principal(session, principal.id)

    assert policy.permissions_for("lxc-137") == {
        Permission.DISCOVER,
        Permission.READ,
        Permission.WRITE,
        Permission.CREATE_CHILD,
    }
    assert policy.visibility_for("fabrik") == ObjectVisibility.NONE
    assert policy.visibility_for("blockwart") == ObjectVisibility.NONE


def test_reparenting_changes_subtree_access_without_policy_cache(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            _seed_fabrik(session)
            principal = create_service_account(
                session,
                login="moving.viewer",
                display_name="Moving Viewer",
            )
            create_object_grant(
                session,
                principal_id=principal.id,
                object_id="other-host",
                role=Role.DISCOVERER,
                scope=GrantScope.SUBTREE,
            )
        assert (
            policy_for_principal(session, principal.id).visibility_for("blockwart")
            == ObjectVisibility.NONE
        )
        with transaction(session):
            edge = session.query(Relationship).filter_by(
                from_ref="system:lxc-137",
                relation_type="hosts",
                to_ref="service:blockwart",
            ).one()
            session.delete(edge)
            session.flush()
            session.add(
                Relationship(
                    from_ref="host:other-host",
                    relation_type="hosts",
                    to_ref="service:blockwart",
                )
            )
        assert (
            policy_for_principal(session, principal.id).visibility_for("blockwart")
            == ObjectVisibility.STUB
        )


def test_inactive_principal_has_no_effective_permissions(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            _seed_fabrik(session)
            principal = create_service_account(
                session,
                login="inactive.viewer",
                display_name="Inactive Viewer",
            )
            create_object_grant(
                session,
                principal_id=principal.id,
                object_id="fabrik",
                role=Role.OWNER,
                scope=GrantScope.SUBTREE,
            )
        with transaction(session):
            stored = session.get(Principal, principal.id)
            assert stored is not None
            stored.active = False
        assert (
            policy_for_principal(session, principal.id).authorized_ids(
                Permission.DISCOVER
            )
            == set()
        )


def test_policy_snapshot_uses_constant_select_count(
    alembic_database,
) -> None:
    session_factory = alembic_database.sessions
    with session_factory() as session:
        with transaction(session):
            session.add(_object("root", "host"))
            for index in range(30):
                session.add(_object(f"service-{index}", "service"))
            session.flush()
            session.add_all(
                [
                    Relationship(
                        from_ref="host:root",
                        relation_type="hosts",
                        to_ref=f"service:service-{index}",
                    )
                    for index in range(30)
                ]
            )
            principal = create_service_account(
                session,
                login="query.counter",
                display_name="Query Counter",
            )
            create_object_grant(
                session,
                principal_id=principal.id,
                object_id="root",
                role=Role.VIEWER,
                scope=GrantScope.SUBTREE,
            )

    select_count = 0

    def count_selects(_conn, _cursor, statement, _parameters, _context, _executemany):
        nonlocal select_count
        if statement.lstrip().upper().startswith(("SELECT", "WITH")):
            select_count += 1

    event.listen(alembic_database.engine, "before_cursor_execute", count_selects)
    try:
        with session_factory() as session:
            policy = policy_for_principal(session, principal.id)
    finally:
        event.remove(alembic_database.engine, "before_cursor_execute", count_selects)

    assert len(policy.authorized_ids(Permission.READ)) == 31
    assert select_count == 1
