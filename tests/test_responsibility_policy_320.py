"""End-to-end Owner reach invariants for explicit operational responsibility."""
from __future__ import annotations

import json

import pytest
from alembic import command
from sqlalchemy import select, text

from blockwart.db.migrations import build_alembic_config
from blockwart.db.session import transaction
from blockwart.domain.auth import GrantScope, Permission, Role
from blockwart.domain.relationships import RelationshipIntegrityError
from blockwart.models import CatalogObject, ObjectGrant, Principal, Relationship
from blockwart.services.access import (
    AccessGrantError,
    LastOwnerError,
    create_object_grant,
    grant_scope_object_ids,
    inherited_owner_grant_ids,
    owner_grant_covered_object_ids,
    revoke_object_grant,
)
from blockwart.services.catalog import create_relationship, delete_relationship
from blockwart.services.commands import (
    CommandAuthorizationDenied,
    CommandConflict,
    WriteContext,
    create_object_relationship,
    delete_object_relationship,
)
from blockwart.services.grant_management import preview_grant_scope, update_managed_grant
from blockwart.services.identity import create_service_account, principal_context
from blockwart.services.policy import policy_for_principal


def _object(identity, kind, **data):
    return CatalogObject(
        id=identity, kind=kind, label=identity, status="active",
        lifecycle="active" if kind in {"host", "system", "service"} else None,
        health="healthy" if kind in {"host", "system", "service"} else None,
        data_json=json.dumps({"schema_version": 1, **(
            {"runbook_status": "draft", "approval_required": False} if kind == "runbook" else {}
        ), **data}), provenance_json="{}",
    )


def _context(session, principal_id):
    return WriteContext(
        principal=principal_context(session.get(Principal, principal_id)),
        policy=policy_for_principal(session, principal_id), channel="api",
    )


def _seed(session):
    session.add_all([
        _object("root", "host"), _object("lxc", "system"),
        _object("service", "service", auth={"credential_references": ["credential_reference:ref"]}),
        _object("operations", "runbook"), _object("descriptive", "runbook"),
        _object("other", "service"), _object("ref", "credential_reference"),
    ])
    session.flush()
    for source, relation, target in [
        ("host:root", "hosts", "system:lxc"),
        ("system:lxc", "hosts", "service:service"),
        ("runbook:operations", "operations_runbook_for", "service:service"),
        ("runbook:descriptive", "documents", "service:service"),
        ("service:service", "related_to", "service:other"),
    ]:
        create_relationship(session, from_ref=source, relation_type=relation, to_ref=target)
    owner = create_service_account(session, login="responsible", display_name="Responsible")
    grant = create_object_grant(
        session, principal_id=owner.id, object_id="lxc", role="owner", scope="responsibility",
    )
    return owner.id, grant.id


def test_one_lxc_grant_unifies_policy_preview_owner_coverage_and_provenance(
    alembic_session_factory,
):
    with alembic_session_factory() as session, transaction(session):
        principal_id, grant_id = _seed(session)
        policy = policy_for_principal(session, principal_id)
        owned = {"lxc", "service", "operations"}
        assert grant_scope_object_ids(session, object_id="lxc", scope="responsibility") == owned
        assert owner_grant_covered_object_ids(session, lock=False) == owned
        preview = preview_grant_scope(
            session, _context(session, principal_id), object_id="lxc",
            role="owner", scope="responsibility",
        )
        assert {obj.id for obj in preview.affected_objects} == owned
        assert set(preview.permissions) == set(Permission)
        for identity in owned:
            assert policy.permissions_for(identity) == set(Permission)
            source, = policy.grants_for(identity)
            assert source.grant_id == grant_id
            assert source.anchor_object_id == "lxc"
            assert source.scope == GrantScope.RESPONSIBILITY
            assert source.role == Role.OWNER
        assert inherited_owner_grant_ids(session, object_id="operations") == {grant_id}
        assert not inherited_owner_grant_ids(session, object_id="lxc")
        for identity in {"root", "descriptive", "other"}:
            assert not policy.permissions_for(identity)
        assert policy.permissions_for("ref") == {Permission.DISCOVER, Permission.READ}
        assert policy.grants_for("ref")[0].role == Role.VIEWER
        assert session.scalars(select(ObjectGrant)).all() == [session.get(ObjectGrant, grant_id)]
        old_fingerprint = policy.fingerprint()
        session.add(_object("new-service", "service"))
        session.flush()
        create_relationship(
            session, from_ref="system:lxc", relation_type="hosts", to_ref="service:new-service",
        )
        policy = policy_for_principal(session, principal_id)
        assert policy.can(Permission.MANAGE_ACCESS, "new-service")
        assert policy.fingerprint() != old_fingerprint


@pytest.mark.parametrize("scope", ["self", "subtree"])
def test_existing_scopes_keep_their_original_semantics(alembic_session_factory, scope):
    with alembic_session_factory() as session, transaction(session):
        principal_id, grant_id = _seed(session)
        session.get(ObjectGrant, grant_id).scope = scope
        session.flush()
        policy = policy_for_principal(session, principal_id)
        assert policy.can(Permission.WRITE, "lxc")
        assert policy.can(Permission.WRITE, "service") == (scope == "subtree")
        for identity in ("operations", "ref", "descriptive", "other"):
            assert not policy.permissions_for(identity)


@pytest.mark.parametrize("role,kind", [("viewer", "system"), ("editor", "service"),
                                      ("owner", "runbook"), ("owner", "credential_reference")])
def test_responsibility_rejects_wrong_roles_or_anchor_kinds(alembic_session_factory, role, kind):
    with alembic_session_factory() as session, transaction(session):
        session.add(_object("target", kind))
        principal = create_service_account(session, login="candidate", display_name="Candidate")
        with pytest.raises(AccessGrantError, match="responsibility requires"):
            create_object_grant(session, principal_id=principal.id, object_id="target",
                                role=role, scope="responsibility")


def test_single_responsibility_target_and_revocation_preserve_owner_coverage(
    alembic_session_factory,
):
    with alembic_session_factory() as session, transaction(session):
        principal_id, grant_id = _seed(session)
        with pytest.raises(RelationshipIntegrityError) as error:
            create_relationship(session, from_ref="runbook:operations",
                                relation_type="operations_runbook_for", to_ref="service:other")
        assert error.value.code == "multiple_responsibility_targets"
        with pytest.raises(LastOwnerError):
            revoke_object_grant(session, grant_id=grant_id)
        relation = session.scalar(select(Relationship).where(
            Relationship.relation_type == "operations_runbook_for",
        ))
        with pytest.raises(LastOwnerError), session.begin_nested():
            delete_relationship(session, relation.id)
        assert policy_for_principal(session, principal_id).can(Permission.WRITE, "operations")


def test_scope_shrink_and_inherited_self_lockout_are_rejected(alembic_session_factory):
    with alembic_session_factory() as session, transaction(session):
        principal_id, grant_id = _seed(session)
        context = _context(session, principal_id)
        with pytest.raises(CommandConflict), session.begin_nested():
            update_managed_grant(
                session, context, object_id="lxc", grant_id=grant_id,
                role="owner", scope="self",
                expected_revision=session.get(CatalogObject, "lxc").revision,
            )
        backup = create_service_account(session, login="backup", display_name="Backup")
        create_object_grant(session, principal_id=backup.id, object_id="operations",
                            role="owner", scope="self")
        with pytest.raises(CommandConflict, match="own access"), session.begin_nested():
            delete_object_relationship(
                session, _context(session, principal_id), object_id="operations",
                from_ref="runbook:operations", relation_type="operations_runbook_for",
                to_ref="service:service",
                expected_revision=session.get(CatalogObject, "operations").revision,
            )


def test_owner_can_reassign_runbook_but_editor_cannot_capture_it(alembic_session_factory):
    with alembic_session_factory() as session, transaction(session):
        principal_id, _ = _seed(session)
        actor = create_service_account(session, login="editor", display_name="Editor")
        for identity in ("operations", "other"):
            create_object_grant(session, principal_id=actor.id, object_id=identity,
                                role="editor", scope="self")
        with pytest.raises(CommandAuthorizationDenied):
            create_object_relationship(
                session, _context(session, actor.id), object_id="other",
                from_ref="runbook:operations", relation_type="operations_runbook_for",
                to_ref="service:other",
                expected_revision=session.get(CatalogObject, "other").revision,
            )
        # Explicit direct ownership permits a safe detachment and reassignment.
        for identity in ("operations", "other"):
            create_object_grant(session, principal_id=principal_id, object_id=identity,
                                role="owner", scope="self")
        delete_object_relationship(
            session, _context(session, principal_id), object_id="operations",
            from_ref="runbook:operations", relation_type="operations_runbook_for",
            to_ref="service:service",
            expected_revision=session.get(CatalogObject, "operations").revision,
        )
        create_object_relationship(
            session, _context(session, principal_id), object_id="operations",
            from_ref="runbook:operations", relation_type="operations_runbook_for",
            to_ref="service:other",
            expected_revision=session.get(CatalogObject, "operations").revision,
        )
        assert grant_scope_object_ids(session, object_id="lxc", scope="responsibility") == {
            "lxc", "service",
        }


def test_migration_preserves_existing_grants_and_refuses_lossy_downgrade(alembic_database_factory):
    database = alembic_database_factory("responsibility.sqlite3")
    config = build_alembic_config(database.database_url)
    command.downgrade(config, "20261026_0031")
    with database.sessions() as session, transaction(session):
        session.add(_object("lxc", "system"))
        principal = create_service_account(session, login="migration", display_name="Migration")
        grant = create_object_grant(session, principal_id=principal.id, object_id="lxc",
                                    role="owner", scope="self")
        original = session.execute(text("SELECT * FROM object_grants")).all()
        grant_id = grant.id
    command.upgrade(config, "head")
    with database.sessions() as session, transaction(session):
        assert session.execute(text("SELECT * FROM object_grants")).all() == original
        session.get(ObjectGrant, grant_id).scope = "responsibility"
    with pytest.raises(RuntimeError, match="Revoke responsibility"):
        command.downgrade(config, "20261026_0031")
    with database.sessions() as session, transaction(session):
        session.get(ObjectGrant, grant_id).scope = "self"
    command.downgrade(config, "20261026_0031")
