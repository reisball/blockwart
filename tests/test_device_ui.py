from __future__ import annotations

import json
from collections.abc import Generator
from dataclasses import dataclass

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.db.session import transaction
from blockwart.domain.auth import GrantScope, Role
from blockwart.main import create_app
from blockwart.models import AuditEvent, CatalogObject, ObjectGrant, Relationship, SecurityEvent
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services.access import create_object_grant
from blockwart.services.catalog import create_relationship, get_object, upsert_object
from blockwart.services.identity import create_human_principal, issue_browser_session
from blockwart.ui.security import AUTH_CSRF_COOKIE_NAME, AUTH_SESSION_COOKIE_NAME


def _device(
    object_id: str,
    label: str,
    category: str,
    *,
    manufacturer: str | None = None,
    model: str | None = None,
    summary: str | None = None,
) -> CatalogObjectIn:
    device: dict[str, str] = {"category": category}
    if manufacturer:
        device["manufacturer"] = manufacturer
    if model:
        device["model"] = model
    return CatalogObjectIn(
        id=object_id,
        kind="device",
        label=label,
        lifecycle="active",
        health="healthy",
        summary=summary,
        data={"schema_version": 1, "device": device},
    )


@dataclass(frozen=True)
class DeviceUiState:
    session_factory: object
    principal_id: str
    browser_value: str
    csrf_token: str


@pytest.fixture
def device_ui_state(alembic_session_factory) -> DeviceUiState:
    with alembic_session_factory() as session:
        with transaction(session):
            objects = [
                upsert_object(
                    session,
                    CatalogObjectIn(
                        id="fabrik-device-root",
                        kind="host",
                        label="Fabrik",
                        lifecycle="active",
                        health="healthy",
                        data={"schema_version": 1},
                    ),
                ),
                upsert_object(
                    session,
                    _device(
                        "zigbee-antenna",
                        "Zigbee antenna",
                        "antenna",
                        manufacturer="Sonoff",
                        model="ZBDongle-E",
                        summary="Pilot antenna",
                    ),
                ),
                upsert_object(
                    session,
                    _device(
                        "door-sensor",
                        "Door sensor",
                        "sensor",
                        manufacturer="Aqara",
                        model="MCCGQ11LM",
                        summary="Pilot sensor",
                    ),
                ),
                upsert_object(
                    session,
                    _device("spare-sensor", "Spare sensor", "sensor"),
                ),
                upsert_object(
                    session,
                    CatalogObjectIn(
                        id="device-target-segment",
                        kind="network",
                        label="Segment is not a device parent",
                        lifecycle="active",
                        health="healthy",
                        data={
                            "schema_version": 1,
                            "network": {"category": "segment"},
                        },
                    ),
                ),
                upsert_object(
                    session,
                    CatalogObjectIn(
                        id="device-target-service",
                        kind="service",
                        label="Service is not a device parent",
                        lifecycle="active",
                        health="healthy",
                        data={"schema_version": 1},
                    ),
                ),
            ]
            create_relationship(
                session,
                from_ref="device:zigbee-antenna",
                relation_type="attached_to",
                to_ref="host:fabrik-device-root",
                metadata={"link_kind": "zigbee", "primary": True, "note": "Pilot uplink"},
            )
            create_relationship(
                session,
                from_ref="device:door-sensor",
                relation_type="attached_to",
                to_ref="device:zigbee-antenna",
                metadata={"link_kind": "zigbee"},
            )
            principal = create_human_principal(
                session,
                login="device.ui.owner",
                display_name="Device UI Owner",
                password="device-ui-owner-password-with-safe-length",
            )
            for catalog_object in objects:
                create_object_grant(
                    session,
                    principal_id=principal.id,
                    object_id=catalog_object.id,
                    role=Role.OWNER,
                    scope=GrantScope.SELF,
                )
            browser = issue_browser_session(
                session,
                principal_id=principal.id,
                ttl_seconds=3600,
            )
    return DeviceUiState(
        session_factory=alembic_session_factory,
        principal_id=principal.id,
        browser_value=browser.value,
        csrf_token=browser.csrf_token,
    )


@pytest.fixture
def device_ui_client(device_ui_state: DeviceUiState) -> Generator[TestClient, None, None]:
    app = create_app()

    def override_get_session() -> Generator[Session, None, None]:
        with device_ui_state.session_factory() as session:  # type: ignore[operator]
            yield session

    app.dependency_overrides[get_session] = override_get_session
    with TestClient(app) as client:
        client.cookies.set(AUTH_SESSION_COOKIE_NAME, device_ui_state.browser_value)
        client.cookies.set(AUTH_CSRF_COOKIE_NAME, device_ui_state.csrf_token)
        yield client


def _form(state: DeviceUiState, **values: str) -> dict[str, str]:
    return {"csrf_token": state.csrf_token, **values}


def _etag(client: TestClient, object_id: str) -> str:
    response = client.get(f"/objects/{object_id}")
    assert response.status_code == 200, response.text
    return response.headers["etag"]


def test_device_catalog_create_detail_filter_and_localized_chain_are_complete(
    device_ui_client: TestClient,
) -> None:
    catalog = device_ui_client.get("/")
    filtered = device_ui_client.get("/?kind=device")
    create_form = device_ui_client.get("/?create=1")
    detail = device_ui_client.get("/objects/door-sensor")
    edit = device_ui_client.get("/objects/door-sensor?edit=device")
    topology = device_ui_client.get("/?view=topology&kind=device")
    german = device_ui_client.get("/?view=topology&kind=device&lang=de")
    german_relationship = device_ui_client.get(
        "/objects/spare-sensor?edit=relationship-add&lang=de"
    )

    assert catalog.status_code == filtered.status_code == create_form.status_code == 200
    assert 'href="/?view=catalog&q=&kind=device"' in catalog.text
    assert "Devices" in catalog.text
    assert 'data-tree-node="devices"' in catalog.text
    assert 'data-asset-ref="device:zigbee-antenna"' in filtered.text
    assert 'data-asset-ref="device:door-sensor"' in filtered.text
    assert 'data-create-field="device_category"' in create_form.text
    assert 'name="device_category" data-field-input="device_category" required' in create_form.text
    assert 'data-relation-type-input' in create_form.text
    assert 'data-device-parent="false"' in create_form.text

    assert detail.status_code == edit.status_code == 200
    assert "Pilot sensor" in detail.text
    assert "Device category" in detail.text
    assert "Sensor" in detail.text
    assert "Aqara" in detail.text
    assert "MCCGQ11LM" in detail.text
    assert 'name="device_category" required' in edit.text
    assert 'name="device_manufacturer"' in edit.text
    assert 'name="device_model"' in edit.text

    chain = topology.text.split('class="device-chain-workbench"', 1)[1]
    assert chain.find("Fabrik") < chain.find("Zigbee antenna") < chain.find("Door sensor")
    assert "Link type: Zigbee" in chain
    assert "Primary attachment" in chain
    assert "Pilot uplink" in chain
    assert "↓" in chain
    assert 'aria-label="Attached to host:fabrik-device-root"' in chain
    assert "Gerätekette" in german.text
    assert "Primäre Verbindung" in german.text
    assert "Übergeordnetes Anschlussobjekt" in german_relationship.text


def test_device_create_is_schema_validated_atomic_audited_and_idempotent(
    device_ui_client: TestClient,
    device_ui_state: DeviceUiState,
) -> None:
    form = _form(
        device_ui_state,
        idempotency_key="device-ui-create-0001",
        object_id="created-antenna",
        kind="device",
        primary_name="Created antenna",
        device_category="antenna",
        device_manufacturer="  Sonoff  ",
        device_model="  ZBDongle-P  ",
        status="active",
        summary="Created through the human UI.",
        relation_target_ref="host:fabrik-device-root",
        relation_type="attached_to",
    )

    first = device_ui_client.post("/objects", data=form, follow_redirects=False)
    replay = device_ui_client.post("/objects", data=form, follow_redirects=False)

    assert first.status_code == replay.status_code == 303
    assert first.headers["location"].endswith("notice=device-created")
    assert replay.headers["location"].endswith("notice=device-created-replayed")
    replay_notice = device_ui_client.get(replay.headers["location"])
    assert "replayed without another write" in replay_notice.text

    with device_ui_state.session_factory() as session:  # type: ignore[operator]
        created = get_object(session, "created-antenna")
        relationship = session.scalar(
            select(Relationship).where(
                Relationship.from_ref == "device:created-antenna",
                Relationship.relation_type == "attached_to",
                Relationship.to_ref == "host:fabrik-device-root",
            )
        )
        owner = session.scalar(
            select(ObjectGrant).where(ObjectGrant.object_id == "created-antenna")
        )
        audits = session.scalars(
            select(AuditEvent).where(AuditEvent.object_id == "created-antenna")
        ).all()
    assert created is not None
    assert created.summary == "Created through the human UI."
    assert created.data["device"] == {
        "category": "antenna",
        "manufacturer": "Sonoff",
        "model": "ZBDongle-P",
    }
    assert relationship is not None
    assert owner is not None
    assert (owner.principal_id, owner.role, owner.scope) == (
        device_ui_state.principal_id,
        "owner",
        "self",
    )
    assert [audit.action for audit in audits] == ["create_attached_device"]

    rejected = device_ui_client.post(
        "/objects",
        data={
            **form,
            "idempotency_key": "device-ui-create-0002",
            "object_id": "invalid-device",
            "device_category": "camera",
        },
        follow_redirects=False,
    )
    assert rejected.status_code == 422
    assert 'role="dialog"' in rejected.text
    assert 'role="alert"' in rejected.text
    assert "Invalid catalog object payload." in rejected.text
    with device_ui_state.session_factory() as session:  # type: ignore[operator]
        assert session.get(CatalogObject, "invalid-device") is None


def test_device_edit_preserves_values_on_validation_and_audits_schema_fields(
    device_ui_client: TestClient,
    device_ui_state: DeviceUiState,
) -> None:
    invalid_value = "x" * 129
    before_etag = _etag(device_ui_client, "spare-sensor")
    with device_ui_state.session_factory() as session:  # type: ignore[operator]
        before = get_object(session, "spare-sensor")
    assert before is not None
    invalid = device_ui_client.post(
        "/objects/spare-sensor",
        data=_form(
            device_ui_state,
            if_match=before_etag,
            device_category="sensor",
            device_manufacturer=invalid_value,
            device_model="Safe model",
        ),
        follow_redirects=False,
    )

    assert invalid.status_code == 422
    assert 'role="alert"' in invalid.text
    assert invalid_value in invalid.text
    with device_ui_state.session_factory() as session:  # type: ignore[operator]
        unchanged = get_object(session, "spare-sensor")
    assert unchanged is not None
    assert unchanged.revision == before.revision
    assert unchanged.data["device"] == {"category": "sensor"}

    updated = device_ui_client.post(
        "/objects/spare-sensor",
        data=_form(
            device_ui_state,
            if_match=before_etag,
            device_category="controller",
            device_manufacturer="Shelly",
            device_model="Plus Uni",
        ),
        follow_redirects=False,
    )
    assert updated.status_code == 303
    summary_etag = _etag(device_ui_client, "spare-sensor")
    summary = device_ui_client.post(
        "/objects/spare-sensor",
        data=_form(
            device_ui_state,
            if_match=summary_etag,
            summary="Maintained from the device detail.",
        ),
        follow_redirects=False,
    )
    assert summary.status_code == 303

    rendered = device_ui_client.get("/objects/spare-sensor")
    assert "Controller" in rendered.text
    assert "Shelly" in rendered.text
    assert "Plus Uni" in rendered.text
    assert "Maintained from the device detail." in rendered.text
    assert "Changed Device category from sensor to controller" in rendered.text
    assert "Changed Manufacturer from empty to Shelly" in rendered.text
    assert "Changed Model from empty to Plus Uni" in rendered.text


def test_device_attach_noop_detach_and_stale_etag_use_slice_two_commands(
    device_ui_client: TestClient,
    device_ui_state: DeviceUiState,
) -> None:
    edit = device_ui_client.get("/objects/spare-sensor?edit=relationship-add")
    assert edit.status_code == 200
    relation_form = edit.text.split('class="form-grid relation-form"', 1)[1]
    assert "Attachment parent" in relation_form
    assert "fabrik-device-root" in relation_form
    assert "zigbee-antenna" in relation_form
    assert "device-target-service" not in relation_form
    assert "device-target-segment" not in relation_form
    assert 'name="link_kind"' in relation_form
    assert 'name="primary" value="true"' in relation_form

    initial_etag = edit.headers["etag"]
    payload = _form(
        device_ui_state,
        if_match=initial_etag,
        direction="outbound",
        relation_type="attached_to",
        target_ref="device:zigbee-antenna",
        link_kind="zigbee",
        source_interface=" radio0 ",
        target_interface_or_port=" coordinator ",
        primary="true",
        note="  Lab pairing  ",
    )
    attached = device_ui_client.post(
        "/objects/spare-sensor/relationships",
        data=payload,
        follow_redirects=False,
    )
    assert attached.status_code == 303
    assert attached.headers["location"].endswith("notice=relationship-attached")

    current_etag = _etag(device_ui_client, "spare-sensor")
    noop = device_ui_client.post(
        "/objects/spare-sensor/relationships",
        data={**payload, "if_match": current_etag},
        follow_redirects=False,
    )
    assert noop.status_code == 303
    assert noop.headers["location"].endswith("notice=relationship-noop")
    noop_page = device_ui_client.get(noop.headers["location"])
    assert "Nothing changed" in noop_page.text
    assert "Link type: Zigbee" in noop_page.text
    assert "Primary attachment" in noop_page.text
    assert "Lab pairing" in noop_page.text

    with device_ui_state.session_factory() as session:  # type: ignore[operator]
        relationship = session.scalar(
            select(Relationship).where(
                Relationship.from_ref == "device:spare-sensor",
                Relationship.relation_type == "attached_to",
                Relationship.to_ref == "device:zigbee-antenna",
            )
        )
        command_audits = session.scalars(
            select(AuditEvent).where(
                AuditEvent.object_id == "spare-sensor",
                AuditEvent.actor == device_ui_state.principal_id,
            )
        ).all()
    assert relationship is not None
    assert json.loads(relationship.metadata_json) == {
        "link_kind": "zigbee",
        "note": "Lab pairing",
        "primary": True,
        "source_interface": "radio0",
        "target_interface_or_port": "coordinator",
    }
    assert [audit.action for audit in command_audits] == ["relationship_create"]

    detached = device_ui_client.post(
        "/objects/spare-sensor/relationships/detach",
        data=_form(
            device_ui_state,
            if_match=current_etag,
            from_ref="device:spare-sensor",
            to_ref="device:zigbee-antenna",
        ),
        follow_redirects=False,
    )
    assert detached.status_code == 303
    assert detached.headers["location"].endswith("notice=relationship-detached")

    stale = device_ui_client.post(
        "/objects/spare-sensor/relationships",
        data={**payload, "if_match": current_etag},
        follow_redirects=False,
    )
    assert stale.status_code == 412
    assert 'role="alert"' in stale.text
    assert "object revision changed" in stale.text
    assert "Lab pairing" in stale.text
    with device_ui_state.session_factory() as session:  # type: ignore[operator]
        assert session.scalar(
            select(func.count())
            .select_from(Relationship)
            .where(
                Relationship.from_ref == "device:spare-sensor",
                Relationship.to_ref == "device:zigbee-antenna",
            )
        ) == 0
        actions = session.scalars(
            select(AuditEvent.action).where(
                AuditEvent.object_id == "spare-sensor",
                AuditEvent.actor == device_ui_state.principal_id,
            )
        ).all()
    assert actions == ["relationship_create", "relationship_delete"]


def test_device_relationship_ui_conceals_targets_and_denies_viewer_writes(
    device_ui_client: TestClient,
    device_ui_state: DeviceUiState,
) -> None:
    with device_ui_state.session_factory() as session:  # type: ignore[operator]
        with transaction(session):
            upsert_object(
                session,
                CatalogObjectIn(
                    id="hidden-device-parent",
                    kind="host",
                    label="Hidden Device Parent",
                    lifecycle="active",
                    health="healthy",
                    data={"schema_version": 1},
                ),
            )
            viewer = create_human_principal(
                session,
                login="device.ui.viewer",
                display_name="Device UI Viewer",
                password="device-ui-viewer-password-with-safe-length",
            )
            create_object_grant(
                session,
                principal_id=viewer.id,
                object_id="spare-sensor",
                role=Role.VIEWER,
                scope=GrantScope.SELF,
            )
            viewer_browser = issue_browser_session(
                session,
                principal_id=viewer.id,
                ttl_seconds=3600,
            )

    concealed = device_ui_client.post(
        "/objects/spare-sensor/relationships",
        data=_form(
            device_ui_state,
            if_match=_etag(device_ui_client, "spare-sensor"),
            direction="outbound",
            relation_type="attached_to",
            target_ref="host:hidden-device-parent",
            link_kind="zigbee",
        ),
        follow_redirects=False,
    )
    assert concealed.status_code == 404
    assert "Resource not found" in concealed.text
    assert "Hidden Device Parent" not in concealed.text
    assert "hidden-device-parent" not in concealed.text

    app = create_app()

    def override_get_session() -> Generator[Session, None, None]:
        with device_ui_state.session_factory() as session:  # type: ignore[operator]
            yield session

    app.dependency_overrides[get_session] = override_get_session
    with TestClient(app) as viewer_client:
        viewer_client.cookies.set(AUTH_SESSION_COOKIE_NAME, viewer_browser.value)
        viewer_client.cookies.set(AUTH_CSRF_COOKIE_NAME, viewer_browser.csrf_token)
        detail = viewer_client.get("/objects/spare-sensor")
        denied = viewer_client.post(
            "/objects/spare-sensor/relationships",
            data={
                "csrf_token": viewer_browser.csrf_token,
                "if_match": detail.headers["etag"],
                "direction": "outbound",
                "relation_type": "attached_to",
                "target_ref": "device:zigbee-antenna",
            },
            follow_redirects=False,
        )

    assert detail.status_code == 200
    assert "Attach device" not in detail.text
    assert "Detach" not in detail.text
    assert denied.status_code == 403
    assert denied.json()["detail"] == "Object permission denied"
    with device_ui_state.session_factory() as session:  # type: ignore[operator]
        denial = session.scalar(
            select(SecurityEvent)
            .where(
                SecurityEvent.principal_id == viewer.id,
                SecurityEvent.event_type == "object_command_authorization",
            )
            .order_by(SecurityEvent.id.desc())
        )
    assert denial is not None
    assert denial.outcome == "denied"
    assert '"permission":"write"' in denial.details_json


def test_unattached_device_has_explicit_empty_chain_state(
    device_ui_client: TestClient,
) -> None:
    response = device_ui_client.get("/objects/spare-sensor")

    assert response.status_code == 200
    assert "Device chain" in response.text
    assert "No visible attachment is recorded for this device." in response.text
    assert 'class="device-chain-row current"' in response.text
