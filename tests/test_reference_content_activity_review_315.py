"""Activity respects global and local reference-content authority (#315 review)."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event, select

from blockwart.api.deps import get_session
from blockwart.domain.auth import CatalogRole, Permission, Role
from blockwart.main import create_app
from blockwart.models import AuditEvent, CatalogObject, ObjectGrant
from blockwart.services.access import create_object_grant
from blockwart.services.activity import query_activity_page
from blockwart.services.identity import create_service_account, issue_service_token
from blockwart.services.read_access import read_access_for_principal

REF_ID = "review-activity-reference"
OLD_LOCATOR = "old-review-315.example.invalid"
NEW_LOCATOR = "new-review-315.example.invalid"


@pytest.fixture
def activity_reference(alembic_session_factory):
    with alembic_session_factory() as session, session.begin():
        session.add(CatalogObject(
            id=REF_ID,
            kind="credential_reference",
            label="Review reference",
            status="active",
            data_json="{}",
            provenance_json="{}",
        ))
        session.flush()
        session.add_all([
            AuditEvent(
                object_id=REF_ID,
                action="update",
                actor="review-fixture",
                summary="Updated reference",
                details_json=json.dumps({
                    "event": "update",
                    "version": 1,
                    "object_ref": f"credential_reference:{REF_ID}",
                    "changes": [{
                        "field": "reference.name",
                        "value_change": True,
                        "old": OLD_LOCATOR,
                        "new": NEW_LOCATOR,
                    }],
                }),
            ),
            AuditEvent(
                object_id=REF_ID,
                action="update",
                actor="review-fixture",
                summary=f"Legacy locator {OLD_LOCATOR}",
                details_json=json.dumps({
                    "event": "legacy",
                    "legacy_summary": f"Legacy locator {OLD_LOCATOR}",
                }),
            ),
        ])
    return REF_ID


def _reader(session, *, catalog_role=None, local_role=None):
    principal = create_service_account(
        session,
        login="review.activity.reader",
        display_name="Review activity reader",
        catalog_role=catalog_role,
    )
    if local_role is not None:
        create_object_grant(
            session,
            principal_id=principal.id,
            object_id=REF_ID,
            role=local_role,
            scope="self",
        )
    return principal


def _assert_content(summaries, has_content):
    assert len(summaries) == 2
    rendered = json.dumps(summaries)
    assert (OLD_LOCATOR in rendered) is has_content
    assert (NEW_LOCATOR in rendered) is has_content
    if has_content:
        assert f"Legacy locator {OLD_LOCATOR}" in summaries
    else:
        assert "Changed reference" in summaries
        assert "Credential reference changed" in summaries


@pytest.mark.parametrize("catalog_role,local_role,has_content", [
    (CatalogRole.CATALOG_OWNER, None, True),
    (CatalogRole.CATALOG_VIEWER, None, False),
    (None, Role.VIEWER, False),
    (None, Role.EDITOR, False),
    (None, Role.REFERENCE_CONTENT_EDITOR, False),
    (None, Role.REFERENCE_CONTENT_READER, True),
    (None, Role.OWNER, True),
])
def test_activity_rest_preserves_independent_content_authority(
    alembic_session_factory, activity_reference, catalog_role, local_role, has_content,
):
    with alembic_session_factory() as session, session.begin():
        principal = _reader(session, catalog_role=catalog_role, local_role=local_role)
        token = issue_service_token(session, principal_id=principal.id, name="review-api").value
        if catalog_role is not None:
            assert not session.scalar(select(ObjectGrant).where(
                ObjectGrant.principal_id == principal.id,
            ))

    app = create_app()

    def session_dependency():
        with alembic_session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = session_dependency
    statements = []

    def observe(_conn, _cursor, statement, _parameters, _context, _executemany):
        statements.append(statement)

    engine = alembic_session_factory.kw["bind"]
    event.listen(engine, "before_cursor_execute", observe)
    try:
        with TestClient(app) as client:
            response = client.get(
                "/api/v1/activity",
                headers={"Authorization": f"Bearer {token}"},
                params={
                    "object_id": activity_reference,
                    "event_type": "object_revision",
                    "include_total": "true",
                },
            )
    finally:
        event.remove(engine, "before_cursor_execute", observe)

    assert response.status_code == 200, response.text
    page = response.json()
    assert page["total"] == 2
    assert page["total_status"] == "exact"
    assert page["next_cursor"] is None
    _assert_content([item["summary"] for item in page["items"]], has_content)
    # Fixing field authority must retain activity's bounded global-read path.
    assert not any(
        "FROM catalog_objects" in sql and "WHERE catalog_objects.id IN" not in sql
        for sql in statements
    )


@pytest.mark.parametrize("materialize_global_permissions", [False, True])
@pytest.mark.parametrize("catalog_role,has_content", [
    (CatalogRole.CATALOG_OWNER, True),
    (CatalogRole.CATALOG_VIEWER, False),
])
def test_activity_global_content_authority_is_independent_of_materialization(
    alembic_session_factory, activity_reference, materialize_global_permissions,
    catalog_role, has_content,
):
    with alembic_session_factory() as session, session.begin():
        principal = _reader(session, catalog_role=catalog_role)
        access = read_access_for_principal(
            session, principal,
            materialize_global_permissions=materialize_global_permissions,
        )
        assert not access.policy.grants_for(activity_reference)
        assert access.policy.can(Permission.READ_REFERENCE_CONTENT, activity_reference) is (
            has_content and materialize_global_permissions
        )
        page = query_activity_page(
            session, access, object_id=activity_reference,
            event_type="object_revision", include_total=True,
        )
        assert page.total == 2
        _assert_content([item.summary for item in page.items], has_content)


@pytest.mark.parametrize("catalog_role,local_role,has_content", [
    (CatalogRole.CATALOG_OWNER, None, True),
    (CatalogRole.CATALOG_VIEWER, None, False),
    (None, Role.VIEWER, False),
    (None, Role.OWNER, True),
])
def test_activity_unclassified_legacy_event_keeps_historical_reference_boundary(
    alembic_session_factory, activity_reference, catalog_role, local_role, has_content,
):
    with alembic_session_factory() as session, session.begin():
        # Model an already authorized conversion: the other structured event
        # retains reference history, but the legacy row has no kind of its own.
        converted = session.get(CatalogObject, activity_reference)
        converted.kind = "host"
        converted.lifecycle = "active"
        converted.health = "healthy"
        principal = _reader(session, catalog_role=catalog_role, local_role=local_role)
        access = read_access_for_principal(
            session, principal, materialize_global_permissions=False,
        )
        page = query_activity_page(
            session, access, object_id=activity_reference,
            event_type="object_revision", include_total=True,
        )
        assert page.total == 2
        _assert_content([item.summary for item in page.items], has_content)


@pytest.mark.parametrize("catalog_role,local_role", [
    (CatalogRole.CATALOG_VIEWER, None),
    (None, Role.VIEWER),
])
def test_activity_historical_reference_preserves_ordinary_structured_events(
    alembic_session_factory, activity_reference, catalog_role, local_role,
):
    with alembic_session_factory() as session, session.begin():
        converted = session.get(CatalogObject, activity_reference)
        converted.kind = "service"
        converted.lifecycle = "active"
        converted.health = "healthy"
        session.add(AuditEvent(
            object_id=activity_reference,
            action="relationship_create",
            actor="review-fixture",
            summary="Created ordinary service relationship",
            details_json=json.dumps({
                "event": "relationship_create",
                "version": 1,
                "from_ref": f"service:{activity_reference}",
                "relation_type": "depends_on",
                "to_ref": "service:ordinary-dependency",
            }),
        ))
        principal = _reader(session, catalog_role=catalog_role, local_role=local_role)
        access = read_access_for_principal(
            session, principal, materialize_global_permissions=False,
        )
        page = query_activity_page(session, access, object_id=activity_reference)
        summaries = [item.summary for item in page.items]
        assert len(summaries) == 3 + (local_role is not None)
        assert (
            f"Created relationship service:{activity_reference} "
            "depends_on service:ordinary-dependency"
        ) in summaries
        assert OLD_LOCATOR not in json.dumps(summaries)
        assert NEW_LOCATOR not in json.dumps(summaries)
        assert "Credential reference changed" in summaries
