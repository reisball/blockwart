from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.config import Settings
from blockwart.db.session import transaction
from blockwart.main import create_app
from blockwart.models import AuditEvent, CatalogObject
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services.catalog import get_object, upsert_object
from blockwart.ui.admin_auth import (
    ADMIN_COOKIE_NAME,
    create_admin_session,
    verify_admin_session,
)

TEST_ADMIN_TOKEN = "test-admin-token-with-at-least-32-characters"
ROTATED_ADMIN_TOKEN = "rotated-admin-token-with-at-least-32-characters"


@pytest.fixture
def session_factory(alembic_session_factory):
    with alembic_session_factory() as session:
        with transaction(session):
            upsert_object(
                session,
                CatalogObjectIn(
                    id="protected-object",
                    kind="system",
                    label="Protected Object",
                    status="active",
                    summary="Must not change without admin access.",
                    data={"schema_version": 1},
                ),
            )
            upsert_object(
                session,
                CatalogObjectIn(
                    id="relationship-target",
                    kind="host",
                    label="Relationship Target",
                    status="active",
                    data={"schema_version": 1},
                ),
            )
    return alembic_session_factory


@pytest.fixture
def anonymous_client(session_factory) -> Generator[TestClient, None, None]:
    app = create_app(settings=Settings(admin_token=TEST_ADMIN_TOKEN))

    def override_get_session() -> Generator[Session, None, None]:
        with session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def configured_client(session_factory) -> Generator[TestClient, None, None]:
    app = create_app(settings=Settings(admin_token=TEST_ADMIN_TOKEN))

    def override_get_session() -> Generator[Session, None, None]:
        with session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def read_only_client(session_factory) -> Generator[TestClient, None, None]:
    app = create_app(settings=Settings())

    def override_get_session() -> Generator[Session, None, None]:
        with session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    with TestClient(app) as test_client:
        yield test_client


def test_machine_api_does_not_publish_catalog_writes(anonymous_client: TestClient) -> None:
    openapi = anonymous_client.get("/openapi.json").json()

    assert set(openapi["paths"]["/api/objects/{object_id}"]) == {"get"}
    assert set(openapi["paths"]["/api/objects"]) == {"get"}
    assert not any(
        path.startswith(("/objects", "/settings", "/admin")) for path in openapi["paths"]
    )


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("POST", "/api/objects"),
        ("PUT", "/api/objects/protected-object"),
        ("PATCH", "/api/objects/protected-object"),
        ("DELETE", "/api/objects/protected-object"),
    ],
)
def test_machine_api_mutations_return_405_without_changing_data(
    anonymous_client: TestClient,
    session_factory,
    method: str,
    path: str,
) -> None:
    with session_factory() as session:
        object_before = get_object(session, "protected-object")
        audit_count_before = len(session.scalars(select(AuditEvent)).all())

    response = anonymous_client.request(method, path, json={"label": "Must Not Change"})

    assert response.status_code == 405
    with session_factory() as session:
        assert get_object(session, "protected-object") == object_before
        assert len(session.scalars(select(AuditEvent)).all()) == audit_count_before


@pytest.mark.parametrize(
    ("path", "form"),
    [
        (
            "/objects",
            {
                "object_id": "must-not-exist",
                "kind": "system",
                "primary_name": "Must Not Exist",
                "status": "active",
            },
        ),
        (
            "/objects/protected-object",
            {"primary_name": "Must Not Change", "status": "inactive"},
        ),
        (
            "/objects/protected-object/network",
            {"address_ip": "192.168.50.250"},
        ),
        (
            "/objects/protected-object/access",
            {
                "method_ref": "system:protected-object",
                "method_index": "0",
                "method_type": "ssh",
            },
        ),
        (
            "/objects/protected-object/relationships",
            {
                "direction": "inbound",
                "relation_type": "hosts",
                "target_ref": "host:relationship-target",
            },
        ),
        (
            "/objects/protected-object/comment",
            {"comment": "Must not be stored."},
        ),
        (
            "/settings/schema",
            {"kind": "system"},
        ),
    ],
)
def test_anonymous_ui_writes_fail_closed_without_changing_data(
    anonymous_client: TestClient,
    session_factory,
    path: str,
    form: dict[str, str],
) -> None:
    with session_factory() as session:
        object_before = get_object(session, "protected-object")
        audit_count_before = len(session.scalars(select(AuditEvent)).all())

    response = anonymous_client.post(path, data=form, follow_redirects=False)

    assert response.status_code == 403
    with session_factory() as session:
        assert get_object(session, "protected-object") == object_before
        assert len(session.scalars(select(AuditEvent)).all()) == audit_count_before
        assert (
            session.scalar(select(CatalogObject).where(CatalogObject.id == "must-not-exist"))
            is None
        )


def test_locked_ui_hides_write_controls(anonymous_client: TestClient) -> None:
    response = anonymous_client.get("/")
    detail = anonymous_client.get("/objects/protected-object?edit=overview")
    schema = anonymous_client.get("/settings/schema")

    assert response.status_code == 200
    assert "Neues Objekt anlegen" not in response.text
    assert 'action="/objects"' not in response.text
    assert "Admin freigeben" in response.text
    assert 'action="/objects/protected-object"' not in detail.text
    assert "Kommentar speichern" not in detail.text
    assert "?edit=overview" not in detail.text
    assert '<form method="post" action="/settings/schema">' not in schema.text


def test_invalid_unlock_does_not_create_session_or_echo_token(
    configured_client: TestClient,
) -> None:
    candidate = "incorrect-admin-token-value"

    response = configured_client.post(
        "/admin/unlock",
        data={"admin_token": candidate},
        follow_redirects=False,
    )

    assert response.status_code == 403
    assert candidate not in response.text
    assert ADMIN_COOKIE_NAME not in configured_client.cookies


def test_missing_admin_token_keeps_application_read_only(
    read_only_client: TestClient,
) -> None:
    admin_page = read_only_client.get("/admin")
    unlock = read_only_client.post(
        "/admin/unlock",
        data={"admin_token": TEST_ADMIN_TOKEN},
        follow_redirects=False,
    )
    write = read_only_client.post(
        "/objects/protected-object/comment",
        data={"comment": "Must stay blocked."},
        follow_redirects=False,
    )

    assert admin_page.status_code == 200
    assert "Nur-Lesen-Modus" in admin_page.text
    assert unlock.status_code == 403
    assert write.status_code == 403
    assert ADMIN_COOKIE_NAME not in read_only_client.cookies


def test_valid_unlock_enables_ui_write_then_lock_disables_it(
    configured_client: TestClient,
    session_factory,
) -> None:
    unlock = configured_client.post(
        "/admin/unlock",
        data={"admin_token": TEST_ADMIN_TOKEN},
        follow_redirects=False,
    )

    assert unlock.status_code == 303
    assert unlock.headers["location"] == "/"
    set_cookie = unlock.headers["set-cookie"]
    assert ADMIN_COOKIE_NAME in set_cookie
    assert TEST_ADMIN_TOKEN not in set_cookie
    assert "HttpOnly" in set_cookie
    assert "SameSite=strict" in set_cookie
    assert "Max-Age=3600" in set_cookie

    unlocked_page = configured_client.get("/")
    assert "Neues Objekt anlegen" in unlocked_page.text
    assert "Admin sperren" in unlocked_page.text

    write = configured_client.post(
        "/objects",
        data={
            "object_id": "admin-created",
            "kind": "system",
            "primary_name": "Admin Created",
            "status": "active",
        },
        follow_redirects=False,
    )
    assert write.status_code == 303
    with session_factory() as session:
        assert get_object(session, "admin-created") is not None

    lock = configured_client.post("/admin/lock", follow_redirects=False)
    assert lock.status_code == 303
    blocked = configured_client.post(
        "/objects/protected-object/comment",
        data={"comment": "Must stay blocked."},
        follow_redirects=False,
    )
    assert blocked.status_code == 403


def test_https_mode_marks_admin_cookie_secure(session_factory) -> None:
    app = create_app(settings=Settings(admin_token=TEST_ADMIN_TOKEN, admin_cookie_secure=True))

    def override_get_session() -> Generator[Session, None, None]:
        with session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    with TestClient(app) as client:
        unlock = client.post(
            "/admin/unlock",
            data={"admin_token": TEST_ADMIN_TOKEN},
            follow_redirects=False,
        )

    assert unlock.status_code == 303
    assert "Secure" in unlock.headers["set-cookie"]


def test_tampered_admin_cookie_is_rejected(configured_client: TestClient) -> None:
    configured_client.post(
        "/admin/unlock",
        data={"admin_token": TEST_ADMIN_TOKEN},
        follow_redirects=False,
    )
    cookie = configured_client.cookies.get(ADMIN_COOKIE_NAME)
    assert cookie is not None
    configured_client.cookies.set(ADMIN_COOKIE_NAME, f"{cookie}tampered")

    response = configured_client.get("/")

    assert "Neues Objekt anlegen" not in response.text
    assert "Admin freigeben" in response.text


def test_admin_session_expires_and_token_rotation_invalidates_it() -> None:
    settings = Settings(admin_token=TEST_ADMIN_TOKEN, admin_session_ttl_seconds=300)
    session = create_admin_session(settings, now=1_000)

    assert verify_admin_session(settings, session, now=1_000)
    assert verify_admin_session(settings, session, now=1_299)
    assert not verify_admin_session(settings, session, now=1_300)
    assert not verify_admin_session(
        Settings(admin_token=ROTATED_ADMIN_TOKEN, admin_session_ttl_seconds=300),
        session,
        now=1_001,
    )


def test_short_admin_token_is_rejected() -> None:
    with pytest.raises(ValidationError, match="at least 32 characters"):
        Settings(admin_token="too-short")


def test_settings_representation_masks_admin_token() -> None:
    settings = Settings(admin_token=TEST_ADMIN_TOKEN)

    assert TEST_ADMIN_TOKEN not in repr(settings)
