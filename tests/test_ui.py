from collections.abc import Generator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from blockwart.api.deps import get_session
from blockwart.db.base import Base
from blockwart.domain.ui_schema import (
    FIELD_DEFINITIONS,
    UI_SCHEMAS,
    create_field_payload,
    schema_field_payload,
    ui_schema_payload,
)
from blockwart.main import create_app
from blockwart.models import Relationship
from blockwart.schemas.catalog import PUBLIC_OBJECT_KINDS, CatalogObjectIn
from blockwart.services.catalog import get_object, upsert_object
from blockwart.services.seeds import import_seed_file

SEED_PATH = Path(__file__).resolve().parents[1] / "seeds" / "pilot_objects.yaml"


@pytest.fixture
def session_factory(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path / 'ui.db'}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    with factory() as session:
        import_seed_file(session, SEED_PATH)
    return factory


@pytest.fixture
def client(session_factory) -> Generator[TestClient, None, None]:
    app = create_app()

    def override_get_session() -> Generator[Session, None, None]:
        with session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    with TestClient(app) as test_client:
        yield test_client


def test_index_lists_seeded_objects_and_filters_search(client: TestClient) -> None:
    response = client.get("/?q=brieftraeger&kind=system")

    assert response.status_code == 200
    assert "brieftraeger" in response.text
    assert "Referenzdoku" not in response.text
    assert "brieftraeger-ocr-worker" in response.text


def test_index_shows_kind_counts(client: TestClient) -> None:
    response = client.get("/")

    assert response.status_code == 200
    assert "<strong>25</strong> alle" in response.text
    assert "system" in response.text
    assert "netzwerk" in response.text
    assert "service" in response.text
    assert "host" in response.text
    assert 'value="decision"' not in response.text
    assert 'value="project"' not in response.text
    assert 'value="runbook"' not in response.text
    assert "credential_reference" not in response.text
    assert "Neues Objekt anlegen" in response.text
    assert 'href="/settings/schema"' in response.text
    assert 'class="panel panel-sticky"' not in response.text
    assert 'data-theme-value="dark"' in response.text
    assert 'data-theme-value="light"' in response.text
    assert "/static/theme.js" in response.text


def test_create_object_form_is_hidden_behind_button(client: TestClient) -> None:
    response = client.get("/")
    create_response = client.get("/?create=1")

    assert response.status_code == 200
    assert 'href="/?create=1"' in response.text
    assert 'name="object_id"' not in response.text
    assert 'role="button"' in response.text
    assert 'data-object-toggle' in response.text
    assert 'data-detail-link' in response.text
    assert 'class="button button-small button-muted relationship-detail"' in response.text
    assert "<span>hosts</span>" not in response.text
    assert "Typ: system" in response.text
    assert "Status: active" in response.text
    assert "Typ: service" in response.text
    assert "data-relationship-node" in response.text
    assert "data-relationship-detail-panel" in response.text
    assert "<span>Beschreibung</span>" not in response.text
    assert "/static/index.js" in response.text
    assert create_response.status_code == 200
    assert "Neues Objekt anlegen" in create_response.text
    assert 'role="dialog"' in create_response.text
    assert 'class="modal-overlay"' in create_response.text
    assert create_response.text.find('data-create-field="kind"') < create_response.text.find(
        'data-create-field="object_id"'
    )
    assert 'name="object_id"' in create_response.text
    assert 'name="primary_name"' in create_response.text
    assert "Hostname" in create_response.text
    assert 'name="labels"' in create_response.text
    assert "data-kind-select" in create_response.text
    assert "data-platform-field" in create_response.text
    assert 'name="platform"' in create_response.text
    assert 'name="relation_target_ref"' in create_response.text
    assert 'name="data_json"' not in create_response.text
    assert 'value="host"' in create_response.text
    assert 'value="LXC"' in create_response.text
    assert 'value="VM"' in create_response.text
    assert 'value="WSL"' in create_response.text
    assert 'value="active"' in create_response.text
    assert 'value="inactive"' in create_response.text
    assert 'value="deleted"' in create_response.text


def test_create_form_schema_gates_fields_by_type(client: TestClient) -> None:
    response = client.get("/?create=1")

    assert response.status_code == 200
    assert "BLOCKWART_UI_SCHEMAS" in response.text
    assert 'data-create-field="kind"' in response.text
    assert 'data-create-field="platform"' in response.text
    assert 'data-create-field="relationship"' in response.text
    assert set(UI_SCHEMAS) == {"host", "system", "netzwerk", "service"}
    assert "platform" in UI_SCHEMAS["system"].create_fields
    assert "platform" in UI_SCHEMAS["service"].create_fields
    assert "platform" not in UI_SCHEMAS["host"].create_fields
    assert "platform" not in UI_SCHEMAS["netzwerk"].create_fields
    for schema in UI_SCHEMAS.values():
        assert schema.create_fields[0] == "kind"
        assert "object_id" in schema.create_fields
        assert "primary_name" in schema.create_fields
        assert "summary" in schema.create_fields


def test_schema_settings_page_shows_selected_type_schema(client: TestClient) -> None:
    response = client.get("/settings/schema?kind=service")

    assert response.status_code == 200
    assert "Schema Settings" in response.text
    assert '<option value="service" selected' in response.text
    assert "service Schema" in response.text
    assert "Service-Name" in response.text
    assert "primary_name_storage" in response.text
    assert "primary_name_storage_path" in response.text
    assert "Storage-Pfad" in response.text
    assert "catalog_objects.label" in response.text
    assert "data_json.platform" in response.text
    assert "Storage-Konvention" in response.text
    assert "data_json.hardware.*" in response.text
    assert "Sichtbarkeit" in response.text
    assert "Create-Felder" in response.text
    assert "Schema-Felder" in response.text
    assert "Detail-Panels" in response.text
    assert "<code>kind</code>" in response.text
    assert "<code>primary_name</code>" in response.text
    assert "<code>platform</code>" in response.text
    assert "<code>overview</code>" in response.text
    assert "<code>network</code>" in response.text
    assert 'method="post"' not in response.text
    assert "Speichern" not in response.text


def test_schema_settings_page_falls_back_to_system_for_invalid_kind(
    client: TestClient,
) -> None:
    response = client.get("/settings/schema?kind=credential_reference")

    assert response.status_code == 200
    assert '<option value="system" selected' in response.text
    assert "system Schema" in response.text
    assert "Hostname" in response.text


@pytest.mark.parametrize(
    ("kind", "primary_label", "storage", "platform_label"),
    [
        ("host", "Hostname", "network_hostname", False),
        ("system", "Hostname", "network_hostname", True),
        ("netzwerk", "Name", "label", False),
        ("service", "Service-Name", "label", True),
    ],
)
def test_schema_settings_type_matrix(
    client: TestClient,
    kind: str,
    primary_label: str,
    storage: str,
    platform_label: bool,
) -> None:
    response = client.get(f"/settings/schema?kind={kind}")

    assert response.status_code == 200
    assert f'<option value="{kind}" selected' in response.text
    assert primary_label in response.text
    assert storage in response.text
    assert ("<td>Plattform</td>" in response.text) is platform_label


def test_ui_schema_payload_matches_public_object_kinds() -> None:
    assert set(UI_SCHEMAS) == set(PUBLIC_OBJECT_KINDS)
    assert set(ui_schema_payload()) == set(PUBLIC_OBJECT_KINDS)
    for schema in UI_SCHEMAS.values():
        assert all(field_key in FIELD_DEFINITIONS for field_key in schema.create_fields)
        assert all(field_key in FIELD_DEFINITIONS for field_key in schema.fields)
        assert set(schema.create_fields).issubset(schema.fields)
        fields = create_field_payload(schema)
        assert fields[0]["key"] == "kind"
        assert all(field["visible_in_create"] is True for field in fields)
        assert all(field["storage_path"] for field in fields)
        primary_field = next(field for field in fields if field["key"] == "primary_name")
        assert primary_field["label"] == schema.primary_name_label
        assert primary_field["storage_path"] == schema.as_dict()["primary_name_storage_path"]


def test_host_and_system_schema_include_hardware_fields(client: TestClient) -> None:
    for kind in ("host", "system"):
        response = client.get(f"/settings/schema?kind={kind}")
        assert response.status_code == 200
        assert "CPU" in response.text
        assert "Memory" in response.text
        assert "GPU" in response.text
        assert "Storage / HDD" in response.text
        assert "data_json.hardware.cpu" in response.text
        assert "data_json.hardware.memory" in response.text
        assert "data_json.hardware.gpu" in response.text
        assert "data_json.hardware.storage" in response.text

        fields = schema_field_payload(UI_SCHEMAS[kind])
        hardware_fields = [field for field in fields if str(field["key"]).startswith("hardware_")]
        assert len(hardware_fields) == 4
        assert all(field["visible_in_create"] is False for field in hardware_fields)
        assert all(field["visible_in_detail"] is True for field in hardware_fields)

    for kind in ("netzwerk", "service"):
        fields = schema_field_payload(UI_SCHEMAS[kind])
        assert not any(str(field["key"]).startswith("hardware_") for field in fields)


def test_service_result_keeps_service_on_right_side(client: TestClient) -> None:
    response = client.get("/?q=n8n-web-ui")

    assert response.status_code == 200
    object_marker = '<span class="object-id">n8n-web-ui</span>'
    object_index = response.text.find(object_marker)
    assert object_index >= 0
    article_start = response.text.rfind("<article", 0, object_index)
    article_end = response.text.find("</article>", object_index)
    article = response.text[article_start:article_end]

    relationship_start = article.find('class="relationship-map"')
    relationship_end = article.find('class="relationship-detail-stack"')
    relationships = article[relationship_start:relationship_end]

    assert relationships.find("system:n8n") < relationships.find("service:n8n-web-ui")
    assert relationships.find("Typ: system") < relationships.find("Typ: service")


def test_object_detail_shows_data_and_relationships(client: TestClient) -> None:
    response = client.get("/objects/n8n")

    assert response.status_code == 200
    assert "n8n Web UI" in response.text
    assert "Relationships" in response.text
    assert "Created at" in response.text
    assert "Last changed" in response.text
    assert "Hostname" in response.text
    assert "Hostnames" not in response.text
    assert "n8n" in response.text
    assert "Ausgehend" in response.text
    assert "Zugriff" in response.text
    assert "Credential-Referenzen" not in response.text
    assert "credential_references" not in response.text
    assert "/objects/n8n-api-credential" not in response.text
    assert "Kommentar" in response.text
    assert "Audit" in response.text
    assert "Referenzdoku" not in response.text
    assert "references/n8n.md" not in response.text
    assert "Daten JSON" not in response.text
    assert "Bearbeiten" not in response.text
    assert 'href="/objects/n8n?edit=overview"' in response.text
    assert "Relationship anlegen" not in response.text
    assert 'data-theme-value="dark"' in response.text
    assert 'data-theme-value="light"' in response.text
    assert "/static/theme.js" in response.text


def test_comment_form_updates_object_and_audit(
    client: TestClient,
    session_factory,
) -> None:
    response = client.post(
        "/objects/n8n/comment",
        data={"comment": "Interner Kommentar"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/objects/n8n"
    detail = client.get("/objects/n8n")
    assert "Interner Kommentar" in detail.text
    assert "Feld Kommentar wurde von leer auf Interner Kommentar geändert" in detail.text
    with session_factory() as session:
        catalog_object = get_object(session, "n8n")
    assert catalog_object is not None
    assert catalog_object.data["comment"] == "Interner Kommentar"


def test_relationship_add_form_is_hidden_behind_add_button(client: TestClient) -> None:
    response = client.get("/objects/n8n")
    add_response = client.get("/objects/n8n?edit=relationship-add")

    assert response.status_code == 200
    assert 'href="/objects/n8n?edit=relationship-add"' in response.text
    assert "Relationship anlegen" not in response.text
    assert add_response.status_code == 200
    assert "Relationship anlegen" in add_response.text
    form_start = add_response.text.find('<form class="form-grid relation-form"')
    form_end = add_response.text.find("</form>", form_start)
    form_html = add_response.text[form_start:form_end]
    assert "Zielobjekt" in form_html
    assert '<select name="direction"' not in form_html
    assert '<select name="relation_type"' not in form_html
    assert ">Richtung" not in form_html
    assert "<label>Relation" not in form_html


def test_create_object_form_redirects_to_detail(
    client: TestClient,
    session_factory,
) -> None:
    response = client.post(
        "/objects",
        data={
            "object_id": "test-system",
            "kind": "system",
            "label": "Test System",
            "status": "active",
            "labels": "infra, docker\nintern",
            "platform": "LXC",
            "summary": "Created from UI test.",
            "data_json": '{"schema_version": 1}',
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/objects/test-system"
    detail = client.get("/objects/test-system")
    assert "Test System" in detail.text
    index = client.get("/?q=test-system")
    assert "infra" in index.text
    assert "docker" in index.text
    assert "intern" in index.text
    assert "Plattform: LXC" in index.text
    with session_factory() as session:
        catalog_object = get_object(session, "test-system")
    assert catalog_object is not None
    assert catalog_object.data["labels"] == ["infra", "docker", "intern"]
    assert catalog_object.data["platform"] == "LXC"
    assert catalog_object.data["network"]["hostnames"][0] == "Test System"


@pytest.mark.parametrize(
    ("kind", "primary_label", "stores_hostname", "supports_platform"),
    [
        ("host", "Hostname", True, False),
        ("system", "Hostname", True, True),
        ("netzwerk", "Name", False, False),
        ("service", "Service-Name", False, True),
    ],
)
def test_ui_schema_drives_primary_name_storage_by_kind(
    client: TestClient,
    session_factory,
    kind: str,
    primary_label: str,
    stores_hostname: bool,
    supports_platform: bool,
) -> None:
    object_id = f"ui-schema-{kind}"
    response = client.post(
        "/objects",
        data={
            "object_id": object_id,
            "kind": kind,
            "primary_name": f"UI Name {kind}",
            "status": "active",
            "labels": "infra, docker\ninfra",
            "platform": "LXC",
            "summary": "Created from schema matrix.",
            "data_json": '{"schema_version": 1}',
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    detail = client.get(f"/objects/{object_id}")
    assert primary_label in detail.text
    assert f"UI Name {kind}" in detail.text
    with session_factory() as session:
        catalog_object = get_object(session, object_id)
    assert catalog_object is not None
    assert catalog_object.label == f"UI Name {kind}"
    assert catalog_object.data["labels"] == ["infra", "docker"]
    if stores_hostname:
        assert catalog_object.data["network"]["hostnames"][0] == f"UI Name {kind}"
    else:
        assert catalog_object.data.get("network", {}).get("hostnames") is None
    if supports_platform:
        assert catalog_object.data["platform"] == "LXC"
    else:
        assert "platform" not in catalog_object.data


def test_create_service_form_can_set_host_system(
    client: TestClient,
    session_factory,
) -> None:
    response = client.post(
        "/objects",
        data={
            "object_id": "test-service",
            "kind": "service",
            "hosted_on_system_id": "fabrik",
            "label": "Test Service",
            "status": "active",
            "platform": "VM",
            "summary": "Created from UI test.",
            "data_json": '{"schema_version": 1}',
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    detail = client.get("/objects/test-service")
    assert "system:fabrik" in detail.text
    with session_factory() as session:
        catalog_object = get_object(session, "test-service")
        relationship = session.query(Relationship).filter_by(
            from_ref="system:fabrik",
            relation_type="hosts",
            to_ref="service:test-service",
        ).one_or_none()
    assert catalog_object is not None
    assert catalog_object.data["platform"] == "VM"
    assert catalog_object.label == "Test Service"
    assert catalog_object.data.get("network", {}).get("hostnames") is None
    assert relationship is not None


def test_create_object_form_rejects_secret_values(client: TestClient) -> None:
    response = client.post(
        "/objects",
        data={
            "object_id": "bad-system",
            "kind": "system",
            "label": "Bad System",
            "status": "active",
            "summary": "",
            "data_json": '{"schema_version": 1, "password": "not-allowed"}',
        },
    )

    assert response.status_code == 422
    assert "forbidden secret-shaped key" in response.text
    assert "not-allowed" not in response.text


def test_update_object_form_updates_detail(client: TestClient) -> None:
    response = client.post(
        "/objects/n8n",
        data={
            "label": "n8n Workflows",
            "status": "active",
            "summary": "Updated through UI.",
            "data_json": '{"schema_version": 1}',
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    detail = client.get("/objects/n8n")
    assert "n8n Workflows" in detail.text
    assert "Updated through UI." in detail.text


def test_overview_edit_updates_object_metadata(client: TestClient, session_factory) -> None:
    edit_response = client.get("/objects/n8n?edit=overview")

    assert edit_response.status_code == 200
    assert 'name="label"' not in edit_response.text
    assert 'name="primary_name"' in edit_response.text
    assert "Container ID" not in edit_response.text
    assert "Created at" in edit_response.text
    assert "Last changed" in edit_response.text
    assert "Bearbeiten" not in edit_response.text

    response = client.post(
        "/objects/n8n",
        data={
            "primary_name": "n8n-main",
            "kind": "system",
            "status": "inactive",
            "summary": "Updated through overview.",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    detail = client.get("/objects/n8n")
    assert "n8n-main" in detail.text
    assert "inactive" in detail.text
    assert "Updated through overview." in detail.text
    with session_factory() as session:
        catalog_object = get_object(session, "n8n")
    assert catalog_object is not None
    assert catalog_object.label == "n8n-main"
    assert catalog_object.data["network"]["hostnames"][0] == "n8n-main"


def test_detail_form_can_create_relationship(client: TestClient, session_factory) -> None:
    response = client.post(
        "/objects/n8n-web-ui/relationships",
        data={
            "direction": "inbound",
            "relation_type": "hosts",
            "target_ref": "system:fabrik",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    with session_factory() as session:
        relationship = session.query(Relationship).filter_by(
            from_ref="system:fabrik",
            relation_type="hosts",
            to_ref="service:n8n-web-ui",
        ).one_or_none()
    assert relationship is not None


def test_system_detail_labels_inherited_service_access(
    client: TestClient,
    session_factory,
) -> None:
    with session_factory() as session:
        upsert_object(
            session,
            CatalogObjectIn(
                id="demo-host",
                kind="system",
                label="Demo Host",
                status="active",
                summary="Host.",
                data={
                    "schema_version": 1,
                    "network": {"addresses": [{"ip": "192.168.50.210"}]},
                    "access_methods": [
                        {
                            "type": "ssh",
                            "endpoint": "ssh://192.168.50.210:22",
                            "auth_mode": "ssh-key",
                        }
                    ],
                },
            ),
        )
        upsert_object(
            session,
            CatalogObjectIn(
                id="demo-service",
                kind="service",
                label="Demo Service",
                status="active",
                summary="Service.",
                data={
                    "schema_version": 1,
                    "system_id": "system:demo-host",
                    "access_methods": [
                        {
                            "type": "web",
                            "endpoint": "http://192.168.50.210:8080",
                            "auth_mode": "configured-in-ui",
                        }
                    ],
                },
            ),
        )
        session.add(
            Relationship(
                from_ref="system:demo-host",
                relation_type="hosts",
                to_ref="service:demo-service",
            )
        )
        session.commit()

    response = client.get("/objects/demo-host")

    assert response.status_code == 200
    assert "system" in response.text
    assert "Demo Host" in response.text
    assert "ssh://192.168.50.210:22" in response.text
    assert "service" in response.text
    assert "Demo Service" in response.text
    assert "http://192.168.50.210:8080" in response.text
    assert "credential_references" not in response.text


def test_panel_edit_forms_update_existing_network_and_access(
    client: TestClient,
    session_factory,
) -> None:
    with session_factory() as session:
        upsert_object(
            session,
            CatalogObjectIn(
                id="edit-demo",
                kind="system",
                label="Edit Demo",
                status="active",
                summary="Editable object.",
                data={
                    "schema_version": 1,
                    "network": {
                        "hostnames": ["edit-demo"],
                        "addresses": [{"ip": "192.168.50.220", "scope": "lan"}],
                    },
                    "ports": [
                        {
                            "port": 22,
                            "protocol": "tcp",
                            "purpose": "SSH",
                            "exposure": "lan",
                        }
                    ],
                    "access_methods": [
                        {
                            "type": "ssh",
                            "endpoint": "ssh://192.168.50.220:22",
                            "auth_mode": "key",
                        }
                    ],
                },
            ),
        )

    network_edit = client.get("/objects/edit-demo?edit=network")
    access_edit = client.get("/objects/edit-demo?edit=access")

    assert network_edit.status_code == 200
    assert 'name="address_ip"' in network_edit.text
    assert access_edit.status_code == 200
    assert 'name="method_endpoint"' in access_edit.text

    network_response = client.post(
        "/objects/edit-demo/network",
        data={
            "address_ip": "192.168.50.221",
            "address_interface": "eth0",
            "address_scope": "lan",
            "port_value": "22",
            "port_protocol": "tcp",
            "port_purpose": "SSH admin",
            "port_exposure": "lan",
        },
        follow_redirects=False,
    )
    access_response = client.post(
        "/objects/edit-demo/access",
        data={
            "method_ref": "system:edit-demo",
            "method_index": "0",
            "method_type": "ssh",
            "method_endpoint": "ssh://192.168.50.221:22",
            "method_auth_mode": "key-only",
        },
        follow_redirects=False,
    )

    assert network_response.status_code == 303
    assert access_response.status_code == 303
    detail = client.get("/objects/edit-demo")
    assert "Hostname" in detail.text
    assert "edit-demo" in detail.text
    assert "Hostnames" not in detail.text
    assert "192.168.50.221" in detail.text
    assert "SSH admin" in detail.text
    assert "key-only" in detail.text


def test_update_object_form_does_not_echo_rejected_secret_values(client: TestClient) -> None:
    response = client.post(
        "/objects/n8n",
        data={
            "label": "n8n",
            "status": "active",
            "summary": "",
            "data_json": '{"schema_version": 1, "password": "not-allowed"}',
        },
    )

    assert response.status_code == 422
    assert "forbidden secret-shaped key" in response.text
    assert "not-allowed" not in response.text
