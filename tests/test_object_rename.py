"""Generic object rename with its own RBAC capability (issue #233).

Rename is deliberately narrow in three separate ways, and these tests prove
each one: it is authorized by its own `rename` capability instead of general
`write`, it accepts only a label instead of a reconstructed object document,
and it writes only the `label` column. The row-exact fingerprints below are the
evidence for the third claim, so a future widening of the applied statement
fails here rather than in production.
"""

from __future__ import annotations

import json
from collections.abc import Generator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import inspect, select, text
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.db.session import transaction
from blockwart.domain.auth import (
    CatalogRole,
    GrantScope,
    Permission,
    Role,
    permissions_for_catalog_role,
    permissions_for_role,
)
from blockwart.main import create_app
from blockwart.mcp.server import GRANT_ROLE_SCHEMA, TOOL_DEFINITIONS, call_tool
from blockwart.models import (
    AuditEvent,
    CatalogObject,
    ObjectGrant,
    Principal,
    Relationship,
)
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services.access import create_object_grant
from blockwart.services.catalog import create_relationship, upsert_object
from blockwart.services.commands import (
    CommandAuthorizationDenied,
    CommandPreconditionFailed,
    WriteContext,
    rename_catalog_object,
)
from blockwart.services.identity import (
    create_service_account,
    issue_service_token,
    principal_context,
)
from blockwart.services.policy import policy_for_principal

RENAME_PATH = "/api/v1/objects/{object_id}/rename"
PREVIEW_PATH = "/api/v1/objects/{object_id}/rename-preview"
SECRET_MARKER = "Bearer abcdefghijklmnopqrstuvwxyz0123456789"

# The nine currently nameable kinds with their canonical minimal valid data, so
# every rename below runs the real kind registry rather than a stub.
KIND_DATA: dict[str, dict] = {
    "host": {"schema_version": 1},
    "system": {"schema_version": 1},
    "network": {"schema_version": 1, "network": {"category": "access_point"}},
    "device": {"schema_version": 1, "device": {"category": "adapter"}},
    "service": {"schema_version": 1},
    "credential_reference": {"schema_version": 1},
    "runbook": {
        "schema_version": 1,
        "runbook_status": "draft",
        "approval_required": False,
    },
    "decision": {"schema_version": 1, "decision_status": "proposed"},
    "project": {
        "schema_version": 1,
        "category": "implementation",
        "project_status": "planned",
    },
}
ASSET_KINDS = ("host", "system", "network", "device", "service")
# One principal per role under test, each holding that role at `self` scope on
# every kind object. The role matrix below is generated from this mapping.
SCOPED_ROLES: dict[str, Role] = {
    "renamer": Role.RENAMER,
    "editor": Role.EDITOR,
    "owner": Role.OWNER,
    "viewer": Role.VIEWER,
    "creator": Role.CREATOR,
    "access_manager": Role.ACCESS_MANAGER,
    "discoverer": Role.DISCOVERER,
}
ROLES_THAT_MAY_RENAME = ("renamer", "editor", "owner")
ROLES_THAT_MAY_NOT_RENAME = ("viewer", "creator", "access_manager")


def _object(
    object_id: str,
    *,
    kind: str = "service",
    label: str | None = None,
    summary: str | None = None,
    data: dict | None = None,
) -> CatalogObjectIn:
    payload: dict = {
        "id": object_id,
        "kind": kind,
        "label": label or object_id,
        "summary": summary,
        "data": data if data is not None else dict(KIND_DATA[kind]),
    }
    if kind in ASSET_KINDS:
        payload["lifecycle"] = "active"
        payload["health"] = "healthy"
    return CatalogObjectIn(**payload)


def _kind_object_id(kind: str) -> str:
    return f"rename-{kind.replace('_', '-')}"


@pytest.fixture
def rename_state(alembic_session_factory):
    """One object per kind, a placement tree, and one principal per role."""
    principals: dict[str, str] = {}
    tokens: dict[str, str] = {}
    with alembic_session_factory() as session:
        with transaction(session):
            for kind in KIND_DATA:
                upsert_object(
                    session,
                    _object(
                        _kind_object_id(kind),
                        kind=kind,
                        label=f"Before {kind}",
                        summary="unchanged summary",
                    ),
                )
            # The canonical placement tree used by every `subtree` assertion.
            upsert_object(session, _object("tree-host", kind="host", label="Tree host"))
            upsert_object(
                session,
                _object("tree-system", kind="system", label="Tree system"),
            )
            upsert_object(
                session,
                _object("tree-service", kind="service", label="Tree service"),
            )
            upsert_object(
                session,
                _object("outside-service", kind="service", label="Outside service"),
            )
            create_relationship(
                session,
                from_ref="host:tree-host",
                relation_type="hosts",
                to_ref="system:tree-system",
            )
            create_relationship(
                session,
                from_ref="system:tree-system",
                relation_type="hosts",
                to_ref="service:tree-service",
            )
            # An ordinary, non-placement relationship must not widen any scope.
            create_relationship(
                session,
                from_ref="service:tree-service",
                relation_type="depends_on",
                to_ref="service:outside-service",
            )

            def account(login: str, **kwargs) -> str:
                principal = create_service_account(
                    session,
                    login=login,
                    display_name=login,
                    **kwargs,
                )
                principals[login.split(".")[-1]] = principal.id
                tokens[login.split(".")[-1]] = issue_service_token(
                    session,
                    principal_id=principal.id,
                    name="api-writes",
                ).value
                return principal.id

            for name, role in SCOPED_ROLES.items():
                principal_id = account(f"rename.{name}")
                for kind in KIND_DATA:
                    create_object_grant(
                        session,
                        principal_id=principal_id,
                        object_id=_kind_object_id(kind),
                        role=role,
                        scope=GrantScope.SELF,
                    )
            subtree_id = account("rename.subtree")
            create_object_grant(
                session,
                principal_id=subtree_id,
                object_id="tree-host",
                role=Role.RENAMER,
                scope=GrantScope.SUBTREE,
            )
            selfscope_id = account("rename.selfscope")
            create_object_grant(
                session,
                principal_id=selfscope_id,
                object_id="tree-host",
                role=Role.RENAMER,
                scope=GrantScope.SELF,
            )
            account("rename.catalogowner", catalog_role=CatalogRole.CATALOG_OWNER)
            account("rename.stranger")
    return {
        "session_factory": alembic_session_factory,
        "principals": principals,
        "tokens": tokens,
    }


@pytest.fixture
def rename_client(rename_state) -> Generator[TestClient, None, None]:
    session_factory = rename_state["session_factory"]
    app = create_app()

    def override_get_session() -> Generator[Session, None, None]:
        with session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    with TestClient(app) as client:
        yield client


def _auth(state, actor: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {state['tokens'][actor]}"}


def _etag(session_factory, object_id: str) -> str:
    with session_factory() as session:
        revision = session.scalar(
            select(CatalogObject.revision).where(CatalogObject.id == object_id)
        )
    return f'"rev-{revision}"'


def _rename(client, state, actor, object_id, new_label, *, if_match, path=RENAME_PATH):
    headers = dict(_auth(state, actor))
    if if_match is not None:
        headers["If-Match"] = if_match
    return client.post(
        path.format(object_id=object_id),
        headers=headers,
        json={"new_label": new_label},
    )


def _preview(client, state, actor, object_id, new_label, *, if_match):
    return _rename(
        client,
        state,
        actor,
        object_id,
        new_label,
        if_match=if_match,
        path=PREVIEW_PATH,
    )


def _write_context(session, principal_id: str, *, channel: str = "api") -> WriteContext:
    return WriteContext(
        principal=principal_context(session.get(Principal, principal_id)),
        policy=policy_for_principal(session, principal_id),
        channel=channel,
        request_id="rename-request",
    )


def _database_fingerprint(session: Session) -> dict[str, list[tuple[object, ...]]]:
    """Every persisted row, so an unintended side effect cannot hide."""
    bind = session.get_bind()
    return {
        table: sorted(
            (tuple(row) for row in session.execute(text(f'SELECT * FROM "{table}"'))),
            key=repr,
        )
        for table in sorted(inspect(bind).get_table_names())
    }


def _object_row(session_factory, object_id: str) -> dict[str, object]:
    """The complete stored record, excluding only the rename's own outputs."""
    with session_factory() as session:
        row = session.get(CatalogObject, object_id)
        assert row is not None
        return {
            "id": row.id,
            "instance_id": row.instance_id,
            "kind": row.kind,
            "status": row.status,
            "lifecycle": row.lifecycle,
            "health": row.health,
            "summary": row.summary,
            "data_json": row.data_json,
            "provenance_json": row.provenance_json,
            "created_at": row.created_at,
        }


def _relationship_rows(session_factory) -> list[tuple[str, str, str]]:
    with session_factory() as session:
        return sorted(
            (row.from_ref, row.relation_type, row.to_ref)
            for row in session.scalars(select(Relationship)).all()
        )


def _grant_rows(session_factory) -> list[tuple[str, str, str, str]]:
    with session_factory() as session:
        return sorted(
            (row.principal_id, row.object_id, row.role, row.scope)
            for row in session.scalars(select(ObjectGrant)).all()
        )


def _audit_events(session_factory, object_id: str) -> list[AuditEvent]:
    """Only the rename events, so fixture creates and grants stay out of view."""
    with session_factory() as session:
        return list(
            session.scalars(
                select(AuditEvent)
                .where(
                    AuditEvent.object_id == object_id,
                    AuditEvent.action == "object_renamed",
                )
                .order_by(AuditEvent.id)
            ).all()
        )


def _revision(session_factory, object_id: str) -> int:
    with session_factory() as session:
        return session.get(CatalogObject, object_id).revision


# ---------------------------------------------------------------------------
# The capability itself
# ---------------------------------------------------------------------------


def test_rename_is_a_distinct_capability_with_its_own_narrow_role() -> None:
    assert permissions_for_role(Role.RENAMER) == {
        Permission.DISCOVER,
        Permission.READ,
        Permission.RENAME,
    }
    for role in (Role.EDITOR, Role.OWNER):
        assert Permission.RENAME in permissions_for_role(role)
    assert Permission.RENAME in permissions_for_catalog_role(CatalogRole.CATALOG_OWNER)
    for role in (Role.VIEWER, Role.CREATOR, Role.ACCESS_MANAGER, Role.DISCOVERER):
        assert Permission.RENAME not in permissions_for_role(role)
    assert Permission.RENAME not in permissions_for_catalog_role(
        CatalogRole.CATALOG_VIEWER
    )
    # The narrow role really is narrow: it carries no write authority at all.
    assert Permission.WRITE not in permissions_for_role(Role.RENAMER)
    assert Permission.CREATE_CHILD not in permissions_for_role(Role.RENAMER)
    assert Permission.MANAGE_ACCESS not in permissions_for_role(Role.RENAMER)
    assert Permission.DELETE not in permissions_for_role(Role.RENAMER)


# ---------------------------------------------------------------------------
# Preview and apply for every nameable kind
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", sorted(KIND_DATA))
def test_preview_and_apply_cover_every_nameable_kind(
    rename_client: TestClient,
    rename_state,
    kind: str,
) -> None:
    session_factory = rename_state["session_factory"]
    object_id = _kind_object_id(kind)
    etag = _etag(session_factory, object_id)
    before_row = _object_row(session_factory, object_id)

    preview = _preview(
        rename_client,
        rename_state,
        "renamer",
        object_id,
        f"After {kind}",
        if_match=etag,
    )

    assert preview.status_code == 200, preview.text
    body = preview.json()
    assert body["object_id"] == object_id
    assert body["object_kind"] == kind
    assert body["changed"] is True
    assert body["base_etag"] == etag
    assert body["expected_result_revision"] == body["base_revision"] + 1
    assert body["diff_truncated"] is False
    # The exact rename diff: one entry, on the common top-level label only.
    assert [entry["path"] for entry in body["diff"]] == ["/label"]
    assert body["diff"][0]["operation"] == "changed"
    assert body["diff"][0]["before"]["text"] == f"Before {kind}"
    assert body["diff"][0]["after"]["text"] == f"After {kind}"
    # Preview writes nothing.
    assert _etag(session_factory, object_id) == etag

    applied = _rename(
        rename_client,
        rename_state,
        "renamer",
        object_id,
        f"After {kind}",
        if_match=etag,
    )

    assert applied.status_code == 200, applied.text
    assert applied.json() == {
        "object_id": object_id,
        "object_kind": kind,
        "old_label": f"Before {kind}",
        "new_label": f"After {kind}",
        "revision": body["expected_result_revision"],
        "etag": body["expected_result_etag"],
        "changed": True,
    }
    assert applied.headers["etag"] == body["expected_result_etag"]
    # Every field other than the label survives byte-identically.
    assert _object_row(session_factory, object_id) == before_row
    with session_factory() as session:
        assert session.get(CatalogObject, object_id).label == f"After {kind}"


def test_preview_of_the_settled_state_is_the_canonical_no_op(
    rename_client: TestClient,
    rename_state,
) -> None:
    session_factory = rename_state["session_factory"]
    object_id = _kind_object_id("service")
    etag = _etag(session_factory, object_id)

    noop = _preview(
        rename_client,
        rename_state,
        "renamer",
        object_id,
        "Before service",
        if_match=etag,
    )

    assert noop.status_code == 200, noop.text
    body = noop.json()
    assert body["changed"] is False
    assert body["diff"] == []
    assert body["base_etag"] == body["expected_result_etag"] == etag
    assert body["base_revision"] == body["expected_result_revision"]
    # Repeating the identical preview is deterministic down to the digest.
    repeated = _preview(
        rename_client,
        rename_state,
        "renamer",
        object_id,
        "Before service",
        if_match=etag,
    )
    assert repeated.json() == body


# ---------------------------------------------------------------------------
# Role matrix, scope, and denial
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("actor", ROLES_THAT_MAY_RENAME)
def test_roles_that_carry_rename_may_preview_and_apply(
    rename_client: TestClient,
    rename_state,
    actor: str,
) -> None:
    session_factory = rename_state["session_factory"]
    object_id = _kind_object_id("service")
    etag = _etag(session_factory, object_id)

    preview = _preview(
        rename_client,
        rename_state,
        actor,
        object_id,
        f"Renamed by {actor}",
        if_match=etag,
    )
    applied = _rename(
        rename_client,
        rename_state,
        actor,
        object_id,
        f"Renamed by {actor}",
        if_match=etag,
    )

    assert preview.status_code == 200, preview.text
    assert applied.status_code == 200, applied.text
    assert applied.json()["new_label"] == f"Renamed by {actor}"


def test_catalog_owner_may_rename_every_object(
    rename_client: TestClient,
    rename_state,
) -> None:
    session_factory = rename_state["session_factory"]
    for object_id in ("rename-service", "outside-service", "tree-host"):
        etag = _etag(session_factory, object_id)
        applied = _rename(
            rename_client,
            rename_state,
            "catalogowner",
            object_id,
            f"Catalog owner named {object_id}",
            if_match=etag,
        )
        assert applied.status_code == 200, applied.text
        assert applied.json()["changed"] is True


@pytest.mark.parametrize("actor", ROLES_THAT_MAY_NOT_RENAME)
def test_viewer_creator_and_access_manager_cannot_rename(
    rename_client: TestClient,
    rename_state,
    actor: str,
) -> None:
    session_factory = rename_state["session_factory"]
    object_id = _kind_object_id("service")
    etag = _etag(session_factory, object_id)

    preview = _preview(
        rename_client,
        rename_state,
        actor,
        object_id,
        "Should not apply",
        if_match=etag,
    )
    applied = _rename(
        rename_client,
        rename_state,
        actor,
        object_id,
        "Should not apply",
        if_match=etag,
    )

    assert preview.status_code == 403, preview.text
    assert applied.status_code == 403, applied.text
    with session_factory() as session:
        row = session.get(CatalogObject, object_id)
        assert row.label == "Before service"
        assert f'"rev-{row.revision}"' == etag


def test_discover_only_and_unauthorized_principals_receive_the_same_denials(
    rename_client: TestClient,
    rename_state,
) -> None:
    session_factory = rename_state["session_factory"]
    object_id = _kind_object_id("service")
    etag = _etag(session_factory, object_id)

    discoverer = _rename(
        rename_client,
        rename_state,
        "discoverer",
        object_id,
        "Nope",
        if_match=etag,
    )
    stranger = _rename(
        rename_client,
        rename_state,
        "stranger",
        object_id,
        "Nope",
        if_match=etag,
    )

    # A discover-only principal is denied; a principal without any grant is not
    # told that the object exists at all.
    assert discoverer.status_code == 403
    assert stranger.status_code == 404


def test_subtree_scope_follows_only_the_canonical_placement_tree(
    rename_client: TestClient,
    rename_state,
) -> None:
    session_factory = rename_state["session_factory"]

    for object_id in ("tree-host", "tree-system", "tree-service"):
        response = _rename(
            rename_client,
            rename_state,
            "subtree",
            object_id,
            f"Subtree renamed {object_id}",
            if_match=_etag(session_factory, object_id),
        )
        assert response.status_code == 200, response.text

    # An ordinary `depends_on` relationship never widens the subtree.
    outside = _rename(
        rename_client,
        rename_state,
        "subtree",
        "outside-service",
        "Should not apply",
        if_match=_etag(session_factory, "outside-service"),
    )

    assert outside.status_code == 404, outside.text
    with session_factory() as session:
        assert session.get(CatalogObject, "outside-service").label == "Outside service"


def test_self_scope_covers_only_the_anchor_object(
    rename_client: TestClient,
    rename_state,
) -> None:
    session_factory = rename_state["session_factory"]

    anchor = _rename(
        rename_client,
        rename_state,
        "selfscope",
        "tree-host",
        "Self scoped host",
        if_match=_etag(session_factory, "tree-host"),
    )
    child = _rename(
        rename_client,
        rename_state,
        "selfscope",
        "tree-system",
        "Should not apply",
        if_match=_etag(session_factory, "tree-system"),
    )

    assert anchor.status_code == 200, anchor.text
    assert child.status_code == 404, child.text


def test_general_write_alone_is_not_accepted_as_rename_authority(
    rename_state,
) -> None:
    """A hand-built policy proves the gate is `rename`, not `write`."""
    session_factory = rename_state["session_factory"]
    principal_id = rename_state["principals"]["viewer"]
    etag = _etag(session_factory, "rename-service")
    with session_factory() as session:
        base = _write_context(session, principal_id)
        writer_only = WriteContext(
            principal=base.principal,
            policy=_PolicyStub(
                principal_id=principal_id,
                permissions={
                    "rename-service": frozenset(
                        {Permission.DISCOVER, Permission.READ, Permission.WRITE}
                    )
                },
            ),
            channel="api",
            request_id="rename-request",
        )
        with pytest.raises(CommandAuthorizationDenied) as denied:
            rename_catalog_object(
                session,
                writer_only,
                object_id="rename-service",
                new_label="Should not apply",
                expected_revision=etag,
            )
    assert denied.value.permission == Permission.RENAME


class _PolicyStub:
    """A policy carrying exactly the permissions a test grants it."""

    def __init__(self, *, principal_id: str, permissions: dict) -> None:
        self.principal_id = principal_id
        self._permissions = permissions

    def permissions_for(self, object_id: str) -> frozenset:
        return self._permissions.get(object_id, frozenset())

    def can(self, permission, object_id: str) -> bool:
        return Permission(permission) in self.permissions_for(object_id)


# ---------------------------------------------------------------------------
# Preconditions, no-op, and concurrency
# ---------------------------------------------------------------------------


def test_missing_stale_weak_and_malformed_etags_are_rejected_before_mutation(
    rename_client: TestClient,
    rename_state,
) -> None:
    session_factory = rename_state["session_factory"]
    object_id = _kind_object_id("service")
    current = _etag(session_factory, object_id)

    missing = _rename(
        rename_client, rename_state, "renamer", object_id, "Nope", if_match=None
    )
    stale = _rename(
        rename_client, rename_state, "renamer", object_id, "Nope", if_match='"rev-99"'
    )
    weak = _rename(
        rename_client,
        rename_state,
        "renamer",
        object_id,
        "Nope",
        if_match=f"W/{current}",
    )
    malformed = _rename(
        rename_client, rename_state, "renamer", object_id, "Nope", if_match="not-an-etag"
    )
    wildcard = _rename(
        rename_client, rename_state, "renamer", object_id, "Nope", if_match="*"
    )

    assert missing.status_code == 428, missing.text
    assert stale.status_code == 412, stale.text
    assert weak.status_code == 412, weak.text
    assert malformed.status_code == 412, malformed.text
    assert wildcard.status_code == 412, wildcard.text
    # The same rejections apply to the read-only preview.
    for if_match, expected in (
        (None, 428),
        ('"rev-99"', 412),
        (f"W/{current}", 412),
        ("not-an-etag", 412),
    ):
        response = _preview(
            rename_client, rename_state, "renamer", object_id, "Nope", if_match=if_match
        )
        assert response.status_code == expected, response.text
    with session_factory() as session:
        row = session.get(CatalogObject, object_id)
        assert row.label == "Before service"
        assert f'"rev-{row.revision}"' == current


def test_no_op_rename_is_deterministic_and_creates_no_revision(
    rename_client: TestClient,
    rename_state,
) -> None:
    session_factory = rename_state["session_factory"]
    object_id = _kind_object_id("service")
    etag = _etag(session_factory, object_id)

    first = _rename(
        rename_client, rename_state, "renamer", object_id, "Before service", if_match=etag
    )
    second = _rename(
        rename_client, rename_state, "renamer", object_id, "Before service", if_match=etag
    )

    assert first.status_code == 200, first.text
    assert first.json() == second.json()
    assert first.json()["changed"] is False
    assert first.json()["revision"] == _revision(session_factory, object_id)
    assert first.json()["etag"] == etag
    assert first.headers["etag"] == etag
    assert _audit_events(session_factory, object_id) == []


def test_a_committed_no_op_rename_writes_no_row_at_all(
    rename_state,
) -> None:
    """Row-exact evidence, taken below HTTP so no token bookkeeping intrudes."""
    session_factory = rename_state["session_factory"]
    principal_id = rename_state["principals"]["renamer"]
    object_id = _kind_object_id("service")
    etag = _etag(session_factory, object_id)
    with session_factory() as session:
        before = _database_fingerprint(session)

    with session_factory() as session:
        context = _write_context(session, principal_id)
        with transaction(session):
            result = rename_catalog_object(
                session,
                context,
                object_id=object_id,
                new_label="Before service",
                expected_revision=etag,
            )

    assert result.changed is False
    assert result.etag == etag
    with session_factory() as session:
        assert _database_fingerprint(session) == before


def test_concurrent_renames_from_one_base_etag_let_exactly_one_win(
    rename_state,
) -> None:
    session_factory = rename_state["session_factory"]
    principal_id = rename_state["principals"]["renamer"]
    object_id = _kind_object_id("service")

    base = _revision(session_factory, object_id)

    with session_factory() as first_session, session_factory() as second_session:
        first_context = _write_context(first_session, principal_id)
        second_context = _write_context(second_session, principal_id)
        with transaction(first_session):
            winner = rename_catalog_object(
                first_session,
                first_context,
                object_id=object_id,
                new_label="Winner",
                expected_revision=f'"rev-{base}"',
            )
        with pytest.raises(CommandPreconditionFailed):
            with transaction(second_session):
                rename_catalog_object(
                    second_session,
                    second_context,
                    object_id=object_id,
                    new_label="Loser",
                    expected_revision=f'"rev-{base}"',
                )

    assert winner.revision == base + 1
    with session_factory() as session:
        row = session.get(CatalogObject, object_id)
        assert row.label == "Winner"
        assert row.revision == base + 1


def test_a_write_between_preview_and_apply_fails_the_ordinary_precondition(
    rename_client: TestClient,
    rename_state,
) -> None:
    session_factory = rename_state["session_factory"]
    object_id = _kind_object_id("service")
    etag = _etag(session_factory, object_id)

    preview = _preview(
        rename_client, rename_state, "renamer", object_id, "Planned", if_match=etag
    )
    interleaved = _rename(
        rename_client, rename_state, "owner", object_id, "Interleaved", if_match=etag
    )
    applied = _rename(
        rename_client, rename_state, "renamer", object_id, "Planned", if_match=etag
    )

    assert preview.status_code == 200
    assert interleaved.status_code == 200
    assert applied.status_code == 412, applied.text


# ---------------------------------------------------------------------------
# Invariants
# ---------------------------------------------------------------------------


def test_rename_changes_only_the_label_row_and_the_revision_columns(
    rename_client: TestClient,
    rename_state,
) -> None:
    session_factory = rename_state["session_factory"]
    base = _revision(session_factory, "tree-system")
    relationships = _relationship_rows(session_factory)
    grants = _grant_rows(session_factory)
    rows = {
        object_id: _object_row(session_factory, object_id)
        for object_id in ("tree-host", "tree-system", "tree-service", "outside-service")
    }

    response = _rename(
        rename_client,
        rename_state,
        "subtree",
        "tree-system",
        "Renamed tree system",
        if_match=_etag(session_factory, "tree-system"),
    )

    assert response.status_code == 200, response.text
    assert _relationship_rows(session_factory) == relationships
    assert _grant_rows(session_factory) == grants
    for object_id, before in rows.items():
        assert _object_row(session_factory, object_id) == before
    with session_factory() as session:
        # Placement is a relationship, and the object ref that carries it is
        # built from id and kind, neither of which a rename touches.
        assert session.scalar(
            select(Relationship.from_ref).where(
                Relationship.to_ref == "system:tree-system"
            )
        ) == "host:tree-host"
        assert session.get(CatalogObject, "tree-system").revision == base + 1


def test_rename_never_accepts_another_field(
    rename_client: TestClient,
    rename_state,
) -> None:
    session_factory = rename_state["session_factory"]
    object_id = _kind_object_id("service")
    etag = _etag(session_factory, object_id)

    response = rename_client.post(
        RENAME_PATH.format(object_id=object_id),
        headers={**_auth(rename_state, "renamer"), "If-Match": etag},
        json={"new_label": "Attempted", "summary": "smuggled", "status": "deleted"},
    )

    assert response.status_code == 422, response.text
    with session_factory() as session:
        row = session.get(CatalogObject, object_id)
        assert row.label == "Before service"
        assert row.summary == "unchanged summary"
        assert row.status == "active"
        assert f'"rev-{row.revision}"' == etag


def test_the_kind_specific_label_validation_is_reused(
    rename_client: TestClient,
    rename_state,
) -> None:
    session_factory = rename_state["session_factory"]
    object_id = _kind_object_id("service")
    etag = _etag(session_factory, object_id)

    empty = _rename(rename_client, rename_state, "renamer", object_id, "", if_match=etag)
    too_long = _rename(
        rename_client, rename_state, "renamer", object_id, "x" * 256, if_match=etag
    )
    secret_shaped = _rename(
        rename_client, rename_state, "renamer", object_id, SECRET_MARKER, if_match=etag
    )

    assert empty.status_code == 422, empty.text
    assert too_long.status_code == 422, too_long.text
    # The shared secret-shaped value rule of the full-object contract applies.
    assert secret_shaped.status_code == 422, secret_shaped.text
    assert SECRET_MARKER not in secret_shaped.text
    with session_factory() as session:
        assert session.get(CatalogObject, object_id).label == "Before service"


def test_rename_introduces_no_global_label_uniqueness(
    rename_client: TestClient,
    rename_state,
) -> None:
    session_factory = rename_state["session_factory"]

    first = _rename(
        rename_client,
        rename_state,
        "renamer",
        "rename-service",
        "Shared name",
        if_match=_etag(session_factory, "rename-service"),
    )
    second = _rename(
        rename_client,
        rename_state,
        "renamer",
        "rename-host",
        "Shared name",
        if_match=_etag(session_factory, "rename-host"),
    )

    assert first.status_code == 200, first.text
    assert second.status_code == 200, second.text


# ---------------------------------------------------------------------------
# Audit and revision behaviour
# ---------------------------------------------------------------------------


def test_a_successful_rename_emits_one_complete_object_renamed_event(
    rename_client: TestClient,
    rename_state,
) -> None:
    session_factory = rename_state["session_factory"]
    object_id = _kind_object_id("decision")
    base = _revision(session_factory, object_id)
    etag = _etag(session_factory, object_id)

    response = _rename(
        rename_client,
        rename_state,
        "renamer",
        object_id,
        "After decision",
        if_match=etag,
        path=RENAME_PATH,
    )

    assert response.status_code == 200, response.text
    events = _audit_events(session_factory, object_id)
    assert [event.action for event in events] == ["object_renamed"]
    details = json.loads(events[0].details_json)
    assert details["event"] == "object_renamed"
    assert details["object_ref"] == f"decision:{object_id}"
    assert details["object_kind"] == "decision"
    assert details["old_label"] == "Before decision"
    assert details["new_label"] == "After decision"
    assert details["channel"] == "api"
    assert details["old_revision"] == base
    assert details["new_revision"] == base + 1
    assert details["request_id"]
    assert events[0].actor == rename_state["principals"]["renamer"]
    assert details["principal_id"] == rename_state["principals"]["renamer"]
    assert details["changes"] == [
        {
            "field": "label",
            "before": "Before decision",
            "after": "After decision",
            "old": "Before decision",
            "new": "After decision",
            "value_change": True,
        }
    ]


def test_the_rename_event_is_readable_on_the_audit_resource(
    rename_client: TestClient,
    rename_state,
) -> None:
    session_factory = rename_state["session_factory"]
    object_id = _kind_object_id("service")

    _rename(
        rename_client,
        rename_state,
        "renamer",
        object_id,
        "Audited name",
        if_match=_etag(session_factory, object_id),
    )
    events = rename_client.get(
        f"/api/v1/objects/{object_id}/audit-events",
        headers=_auth(rename_state, "renamer"),
    )

    assert events.status_code == 200, events.text
    item = events.json()["items"][0]
    assert item["action"] == "object_renamed"
    assert item["summary"] == (
        f"Renamed service:{object_id} from Before service to Audited name"
    )


# ---------------------------------------------------------------------------
# Published contract surfaces
# ---------------------------------------------------------------------------


def test_mcp_rename_tools_publish_the_reviewed_contract() -> None:
    apply_tool = TOOL_DEFINITIONS["blockwart.rename_object"]
    preview_tool = TOOL_DEFINITIONS["blockwart.preview_object_rename"]

    # Preview takes exactly the apply arguments and mutates nothing.
    assert preview_tool["inputSchema"] == apply_tool["inputSchema"]
    assert preview_tool["annotations"]["readOnlyHint"] is True
    assert apply_tool["annotations"]["readOnlyHint"] is False
    assert apply_tool["annotations"]["destructiveHint"] is False
    assert sorted(apply_tool["inputSchema"]["properties"]) == [
        "if_match",
        "new_label",
        "object_id",
    ]
    assert apply_tool["inputSchema"]["additionalProperties"] is False
    # No object document can be smuggled through the narrow contract.
    assert "object" not in apply_tool["inputSchema"]["properties"]
    assert "data" not in json.dumps(apply_tool["inputSchema"]["properties"])


def test_mcp_rename_forwards_the_exact_upstream_requests() -> None:
    calls: list[tuple] = []

    def requester(method, path, body, headers):
        calls.append((method, path, body, headers))
        return {"changed": True}

    call_tool(
        "blockwart.rename_object",
        {"object_id": "rename-service", "new_label": "Named", "if_match": '"rev-2"'},
        requester=requester,
    )
    call_tool(
        "blockwart.preview_object_rename",
        {"object_id": "rename-service", "new_label": "Named", "if_match": '"rev-2"'},
        requester=requester,
    )

    assert [(method, path) for method, path, _, _ in calls] == [
        ("POST", "/api/v1/objects/rename-service/rename"),
        ("POST", "/api/v1/objects/rename-service/rename-preview"),
    ]
    for _, _, body, headers in calls:
        assert body == {"new_label": "Named"}
        assert headers["If-Match"] == '"rev-2"'
        assert headers["X-Blockwart-Channel"] == "mcp"


def test_mcp_and_rest_renames_are_byte_identical(
    rename_client: TestClient,
    rename_state,
) -> None:
    session_factory = rename_state["session_factory"]
    etag = _etag(session_factory, "rename-host")

    rest = _preview(
        rename_client, rename_state, "renamer", "rename-host", "Parity", if_match=etag
    )

    def requester(method, path, body, headers):
        response = rename_client.request(
            method,
            path,
            json=body,
            headers={**headers, **_auth(rename_state, "renamer")},
        )
        response.raise_for_status()
        return response.json()

    mcp = call_tool(
        "blockwart.preview_object_rename",
        {"object_id": "rename-host", "new_label": "Parity", "if_match": etag},
        requester=requester,
    )

    assert rest.status_code == 200, rest.text
    assert json.loads(mcp["content"][0]["text"]) == rest.json()


def test_the_grant_role_vocabulary_is_consistent_across_surfaces() -> None:
    assert set(GRANT_ROLE_SCHEMA["enum"]) == {role.value for role in Role}
    assert "renamer" in GRANT_ROLE_SCHEMA["enum"]


def test_the_published_documentation_describes_the_rename_contract() -> None:
    docs = Path(__file__).resolve().parents[1] / "docs"
    rbac = (docs / "auth-rbac.md").read_text()
    api = (docs / "api-v1.md").read_text()
    mcp = (docs / "mcp.md").read_text()

    assert "| `renamer` | `discover`, `read`, `rename` |" in rbac
    assert "| `editor` | `discover`, `read`, `write`, `rename` |" in rbac
    assert "### `POST /api/v1/objects/{object_id}/rename`" in api
    assert "### `POST /api/v1/objects/{object_id}/rename-preview`" in api
    assert "blockwart.rename_object -> POST /api/v1/objects/{object_id}/rename" in mcp
    assert (
        "blockwart.preview_object_rename -> "
        "POST /api/v1/objects/{object_id}/rename-preview" in mcp
    )


# ---------------------------------------------------------------------------
# Migration compatibility
# ---------------------------------------------------------------------------


def test_existing_assignments_stay_compatible_and_renamer_becomes_storable(
    alembic_session_factory,
) -> None:
    """Editor, owner, and catalog-owner assignments survive the migration.

    They are never rewritten: the role string a grant already stores is mapped
    to the widened permission set at policy time, so an upgraded installation
    gains `rename` without a data migration.
    """
    with alembic_session_factory() as session:
        with transaction(session):
            upsert_object(session, _object("legacy-service"))
            editor = create_service_account(
                session, login="legacy.editor", display_name="Legacy Editor"
            )
            owner = create_service_account(
                session, login="legacy.owner", display_name="Legacy Owner"
            )
            catalog_owner = create_service_account(
                session,
                login="legacy.catalog",
                display_name="Legacy Catalog Owner",
                catalog_role=CatalogRole.CATALOG_OWNER,
            )
            renamer = create_service_account(
                session, login="legacy.renamer", display_name="Legacy Renamer"
            )
            for principal, role in (
                (editor, Role.EDITOR),
                (owner, Role.OWNER),
                (renamer, Role.RENAMER),
            ):
                create_object_grant(
                    session,
                    principal_id=principal.id,
                    object_id="legacy-service",
                    role=role,
                    scope=GrantScope.SELF,
                )

    with alembic_session_factory() as session:
        editor_policy = policy_for_principal(session, editor.id)
        owner_policy = policy_for_principal(session, owner.id)
        catalog_policy = policy_for_principal(session, catalog_owner.id)
        renamer_policy = policy_for_principal(session, renamer.id)
        stored_roles = sorted(
            row.role for row in session.scalars(select(ObjectGrant)).all()
        )

    assert editor_policy.permissions_for("legacy-service") == {
        Permission.DISCOVER,
        Permission.READ,
        Permission.WRITE,
        Permission.RENAME,
    }
    assert owner_policy.can(Permission.RENAME, "legacy-service")
    assert owner_policy.can(Permission.DELETE, "legacy-service")
    assert catalog_policy.can(Permission.RENAME, "legacy-service")
    assert renamer_policy.permissions_for("legacy-service") == {
        Permission.DISCOVER,
        Permission.READ,
        Permission.RENAME,
    }
    # Stored role strings are untouched by the widened permission mapping.
    assert stored_roles == ["editor", "owner", "renamer"]
