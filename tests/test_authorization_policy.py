from sqlalchemy import event, select

from blockwart.db.session import transaction
from blockwart.domain.auth import (
    CatalogRole,
    GrantScope,
    ObjectVisibility,
    Permission,
    PlatformRole,
    Role,
    permissions_for_catalog_role,
    permissions_for_role,
)
from blockwart.models import CatalogObject, ObjectGrant, Principal, Relationship
from blockwart.services.access import active_owner_covered_object_ids, create_object_grant
from blockwart.services.identity import create_service_account, principal_context
from blockwart.services.policy import GlobalPolicySource, policy_for_principal


def _object(object_id: str, kind: str) -> CatalogObject:
    is_asset = kind in {"host", "system", "network", "device", "service"}
    return CatalogObject(
        id=object_id,
        kind=kind,
        label=object_id.replace("-", " ").title(),
        status="active",
        lifecycle="active" if is_asset else None,
        health="healthy" if is_asset else None,
        summary=None,
        data_json=(
            '{"device":{"category":"other"},"schema_version":1}'
            if kind == "device"
            else "{}"
        ),
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


def test_attachment_links_do_not_propagate_subtree_rbac_or_owner_coverage(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            session.add_all([_object("root", "host"), _object("sensor", "device")])
            session.flush()
            session.add(
                Relationship(
                    from_ref="device:sensor",
                    relation_type="attached_to",
                    to_ref="host:root",
                )
            )
            principal = create_service_account(
                session,
                login="attachment.owner",
                display_name="Attachment Owner",
            )
            create_object_grant(
                session,
                principal_id=principal.id,
                object_id="root",
                role=Role.OWNER,
                scope=GrantScope.SUBTREE,
            )

        policy = policy_for_principal(session, principal.id)
        covered_ids = active_owner_covered_object_ids(session)

    assert policy.visibility_for("root") == ObjectVisibility.DETAIL
    assert policy.visibility_for("sensor") == ObjectVisibility.NONE
    assert covered_ids == {"root"}


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
    # One global-authority lookup plus the single recursive grant query.
    assert select_count == 2


def test_catalog_role_matrix_is_exact_and_closed() -> None:
    assert set(CatalogRole) == {CatalogRole.CATALOG_OWNER}
    assert permissions_for_catalog_role(CatalogRole.CATALOG_OWNER) == set(Permission)


def test_active_catalog_owner_holds_every_permission_without_any_grant(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            _seed_fabrik(session)
            principal = create_service_account(
                session,
                login="global.owner",
                display_name="Global Owner",
                catalog_role=CatalogRole.CATALOG_OWNER,
            )
        policy = policy_for_principal(session, principal.id)
        catalog_ids = set(session.scalars(select(CatalogObject.id)).all())
        grant_count = len(session.scalars(select(ObjectGrant)).all())

    assert principal.is_catalog_owner
    assert not principal.is_admin
    assert grant_count == 0
    for object_id in catalog_ids:
        assert policy.permissions_for(object_id) == set(Permission)
        assert policy.visibility_for(object_id) == ObjectVisibility.DETAIL
        assert policy.grants_for(object_id) == ()
    assert policy.authorized_ids(Permission.DELETE) == catalog_ids
    assert policy.has_global_authority(GlobalPolicySource.CATALOG_OWNER)
    assert [authority.source for authority in policy.global_authorities] == [
        GlobalPolicySource.CATALOG_OWNER
    ]


def test_catalog_owner_covers_objects_created_after_the_role_was_assigned(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            _seed_fabrik(session)
            principal = create_service_account(
                session,
                login="growing.owner",
                display_name="Growing Owner",
                catalog_role=CatalogRole.CATALOG_OWNER,
            )
        with transaction(session):
            session.add(_object("later-host", "host"))
        policy = policy_for_principal(session, principal.id)
        grant_count = len(session.scalars(select(ObjectGrant)).all())

    assert grant_count == 0
    assert policy.permissions_for("later-host") == set(Permission)
    assert policy.grants_for("later-host") == ()


def test_inactive_catalog_owner_receives_no_catalog_permissions(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            _seed_fabrik(session)
            principal = create_service_account(
                session,
                login="inactive.owner",
                display_name="Inactive Owner",
                catalog_role=CatalogRole.CATALOG_OWNER,
            )
            create_service_account(
                session,
                login="standby.owner",
                display_name="Standby Owner",
                catalog_role=CatalogRole.CATALOG_OWNER,
            )
        with transaction(session):
            stored = session.get(Principal, principal.id)
            assert stored is not None
            stored.active = False
        policy = policy_for_principal(session, principal.id)

    assert policy.authorized_ids(Permission.DISCOVER) == set()
    assert policy.global_authorities == ()
    assert not policy.has_global_authority(GlobalPolicySource.CATALOG_OWNER)


def test_catalog_owner_and_platform_admin_are_independent_axes(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            _seed_fabrik(session)
            admin = create_service_account(
                session,
                login="platform.admin",
                display_name="Platform Admin",
                platform_role=PlatformRole.ADMIN,
            )
            owner = create_service_account(
                session,
                login="catalog.owner",
                display_name="Catalog Owner",
                catalog_role=CatalogRole.CATALOG_OWNER,
            )
        admin_policy = policy_for_principal(session, admin.id)
        owner_policy = policy_for_principal(session, owner.id)
        stored_owner = session.get(Principal, owner.id)
        assert stored_owner is not None
        stored_context = principal_context(stored_owner)

    assert admin.is_admin
    assert not admin.is_catalog_owner
    assert admin_policy.authorized_ids(Permission.DISCOVER) == set()
    assert admin_policy.global_authorities == ()

    assert owner.is_catalog_owner
    assert not owner.is_admin
    assert stored_context.catalog_role == CatalogRole.CATALOG_OWNER
    assert stored_context.platform_role is None
    assert owner_policy.authorized_ids(Permission.DELETE)


def test_scoped_grants_stay_additive_and_projected_under_global_authority(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            _seed_fabrik(session)
            principal = create_service_account(
                session,
                login="mixed.owner",
                display_name="Mixed Owner",
                catalog_role=CatalogRole.CATALOG_OWNER,
            )
            create_object_grant(
                session,
                principal_id=principal.id,
                object_id="lxc-137",
                role=Role.EDITOR,
                scope=GrantScope.SELF,
            )
        policy = policy_for_principal(session, principal.id)

    sources = policy.grants_for("lxc-137")
    assert len(sources) == 1
    assert sources[0].role == Role.EDITOR
    assert sources[0].scope == GrantScope.SELF
    assert sources[0].anchor_object_id == "lxc-137"
    assert policy.permissions_for("lxc-137") == set(Permission)
    # Global authority is never projected as an object grant.
    assert policy.grants_for("fabrik") == ()


def test_policy_fingerprint_tracks_catalog_role_changes(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            _seed_fabrik(session)
            principal = create_service_account(
                session,
                login="fingerprint.owner",
                display_name="Fingerprint Owner",
            )
            create_service_account(
                session,
                login="fingerprint.standby.owner",
                display_name="Fingerprint Standby Owner",
                catalog_role=CatalogRole.CATALOG_OWNER,
            )
        before = policy_for_principal(session, principal.id).fingerprint()
        with transaction(session):
            stored = session.get(Principal, principal.id)
            assert stored is not None
            stored.catalog_role = CatalogRole.CATALOG_OWNER
        promoted = policy_for_principal(session, principal.id).fingerprint()
        with transaction(session):
            stored = session.get(Principal, principal.id)
            assert stored is not None
            stored.catalog_role = None
        after = policy_for_principal(session, principal.id).fingerprint()

    assert before != promoted
    assert after == before


def test_catalog_owner_policy_uses_constant_select_count(
    alembic_database,
) -> None:
    session_factory = alembic_database.sessions
    with session_factory() as session:
        with transaction(session):
            session.add(_object("root", "host"))
            for index in range(30):
                session.add(_object(f"service-{index}", "service"))
            principal = create_service_account(
                session,
                login="global.query.counter",
                display_name="Global Query Counter",
                catalog_role=CatalogRole.CATALOG_OWNER,
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
    # Global-authority lookup, catalog identity projection, and the grant query.
    assert select_count == 3
