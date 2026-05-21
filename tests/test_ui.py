import re
from collections.abc import Generator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
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
from blockwart.models import AuditEvent, Relationship
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
    assert "relationship-chain" in response.text
    assert "relationship-pill" in response.text
    assert "<span>hosts</span>" not in response.text
    assert "<span>system</span>" in response.text
    assert "Status: active" in response.text
    assert "<span>service</span>" in response.text
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
    assert "<code>endpoint_type</code>" in response.text
    assert "<code>endpoint_url</code>" in response.text
    assert "<code>endpoint_port</code>" in response.text
    assert "data_json.endpoints[].type" in response.text
    assert "data_json.endpoints[].url" in response.text
    assert "data_json.endpoints[].port" in response.text
    assert "<code>overview</code>" in response.text
    assert "<code>network</code>" in response.text
    assert 'method="post"' in response.text
    assert "Speichern" in response.text
    assert 'name="field_label_primary_name"' in response.text
    assert 'name="field_placeholder_summary"' in response.text
    assert 'name="field_order_kind"' in response.text
    assert 'name="field_required_kind"' in response.text


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
    assert ('name="field_label_platform"' in response.text) is platform_label


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


def test_public_schemas_include_endpoint_fields_but_not_create_form(
    client: TestClient,
) -> None:
    for kind in PUBLIC_OBJECT_KINDS:
        response = client.get(f"/settings/schema?kind={kind}")

        assert response.status_code == 200
        for key in ("endpoint_type", "endpoint_url", "endpoint_port"):
            assert f"<code>{key}</code>" in response.text
            assert f'name="field_label_{key}"' in response.text
        assert "data_json.endpoints[].type" in response.text
        assert "data_json.endpoints[].url" in response.text
        assert "data_json.endpoints[].port" in response.text

        fields = schema_field_payload(UI_SCHEMAS[kind])
        endpoint_fields = [field for field in fields if str(field["key"]).startswith("endpoint_")]
        assert [field["key"] for field in endpoint_fields] == [
            "endpoint_type",
            "endpoint_url",
            "endpoint_port",
        ]
        assert all(field["visible_in_create"] is False for field in endpoint_fields)


def test_service_schema_includes_service_information_fields(client: TestClient) -> None:
    response = client.get("/settings/schema?kind=service")

    assert response.status_code == 200
    for expected in (
        "Service Information",
        "Sources",
        "Running Version",
        "data_json.service_information.sources[]",
        "data_json.service_information.running_version",
    ):
        assert expected in response.text

    fields = schema_field_payload(UI_SCHEMAS["service"])
    service_fields = [field for field in fields if str(field["key"]).startswith("service_")]
    assert [field["key"] for field in service_fields] == [
        "service_sources",
        "service_running_version",
    ]
    assert all(field["visible_in_create"] is False for field in service_fields)

    for kind in ("host", "system", "netzwerk"):
        fields = schema_field_payload(UI_SCHEMAS[kind])
        assert not any(str(field["key"]).startswith("service_") for field in fields)


def test_host_and_system_schema_include_hardware_fields(client: TestClient) -> None:
    host_response = client.get("/settings/schema?kind=host")
    assert host_response.status_code == 200
    for expected in (
        "Modell",
        "CPU Hersteller",
        "CPU Name",
        "CPU Cores",
        "Memory",
        "GPU",
        "Storage / HDD",
        "data_json.hardware.model",
        "data_json.hardware.cpu.vendor",
        "data_json.hardware.cpu.name",
        "data_json.hardware.cpu.cores",
        "data_json.hardware.memory",
        "data_json.hardware.gpu",
        "data_json.hardware.storage",
    ):
        assert expected in host_response.text

    system_response = client.get("/settings/schema?kind=system")
    assert system_response.status_code == 200
    for expected in (
        "CPU Cores",
        "Memory",
        "GPU",
        "Storage / HDD",
        "data_json.hardware.cpu.cores",
        "data_json.hardware.memory",
        "data_json.hardware.gpu",
        "data_json.hardware.storage",
    ):
        assert expected in system_response.text
    for inherited in (
        "Modell",
        "CPU Hersteller",
        "CPU Name",
        "data_json.hardware.model",
        "data_json.hardware.cpu.vendor",
        "data_json.hardware.cpu.name",
    ):
        assert inherited not in system_response.text

    for kind, expected_count in (("host", 7), ("system", 4)):
        fields = schema_field_payload(UI_SCHEMAS[kind])
        hardware_fields = [
            field for field in fields if str(field["key"]).startswith("hardware_")
        ]
        assert len(hardware_fields) == expected_count
        assert all(field["visible_in_create"] is False for field in hardware_fields)
        assert all(field["visible_in_detail"] is True for field in hardware_fields)

    for kind in ("netzwerk", "service"):
        fields = schema_field_payload(UI_SCHEMAS[kind])
        assert not any(str(field["key"]).startswith("hardware_") for field in fields)


def test_schema_settings_saves_safe_metadata_overrides(
    client: TestClient,
    tmp_path,
    monkeypatch,
) -> None:
    override_path = tmp_path / "ui_schema_overrides.json"
    monkeypatch.setenv("BLOCKWART_SCHEMA_OVERRIDES_PATH", str(override_path))
    fields = schema_field_payload(UI_SCHEMAS["system"])
    data = {"kind": "system"}
    for index, field in enumerate(fields, start=1):
        key = str(field["key"])
        data[f"field_order_{key}"] = str(index)
        data[f"field_label_{key}"] = str(field["label"])
        data[f"field_placeholder_{key}"] = str(field["placeholder"] or "")
        if field["required"]:
            data[f"field_required_{key}"] = "1"
        if field["visible_in_detail"]:
            data[f"field_visible_in_detail_{key}"] = "1"
    data["field_label_hardware_storage"] = "Disk"
    data["field_placeholder_hardware_storage"] = "z.B. 4 TB SSD"

    response = client.post("/settings/schema", data=data, follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/settings/schema?kind=system&saved=1"
    settings = client.get("/settings/schema?kind=system")
    detail = client.get("/objects/fabrik")
    edit = client.get("/objects/fabrik?edit=hardware")
    assert "Disk" in settings.text
    assert "z.B. 4 TB SSD" in settings.text
    assert "Disk" in detail.text
    assert "z.B. 4 TB SSD" in edit.text
    assert "data_json.hardware.storage" in settings.text
    assert "hardware_storage" in settings.text


def test_service_endpoint_schema_metadata_drives_endpoint_table(
    client: TestClient,
    tmp_path,
    monkeypatch,
) -> None:
    override_path = tmp_path / "ui_schema_overrides.json"
    monkeypatch.setenv("BLOCKWART_SCHEMA_OVERRIDES_PATH", str(override_path))
    fields = schema_field_payload(UI_SCHEMAS["service"])
    data = {"kind": "service"}
    for index, field in enumerate(fields, start=1):
        key = str(field["key"])
        data[f"field_order_{key}"] = str(index)
        data[f"field_label_{key}"] = str(field["label"])
        data[f"field_placeholder_{key}"] = str(field["placeholder"] or "")
        if field["required"]:
            data[f"field_required_{key}"] = "1"
        if field["visible_in_detail"]:
            data[f"field_visible_in_detail_{key}"] = "1"
    data["field_label_endpoint_url"] = "Endpoint URL"
    data["field_placeholder_endpoint_url"] = "https://service.local/api"

    response = client.post("/settings/schema", data=data, follow_redirects=False)

    assert response.status_code == 303
    settings = client.get("/settings/schema?kind=service")
    edit = client.get("/objects/n8n-web-ui?edit=network")
    detail = client.get("/objects/n8n-web-ui")
    assert "Endpoint URL" in settings.text
    assert "https://service.local/api" in settings.text
    assert "Endpoint URL" in edit.text
    assert "https://service.local/api" in edit.text
    assert "Endpoint URL" in detail.text


def test_host_detail_can_edit_host_hardware_fields(
    client: TestClient,
    session_factory,
) -> None:
    object_id = "hardware-host"
    with session_factory() as session:
        upsert_object(
            session,
            CatalogObjectIn(
                id=object_id,
                kind="host",
                label="Hardware host",
                status="active",
                summary="Hardware test object.",
                data={"schema_version": 1},
            ),
        )

    detail = client.get(f"/objects/{object_id}")
    edit = client.get(f"/objects/{object_id}?edit=hardware")

    assert detail.status_code == 200
    assert "Hardware" in detail.text
    assert "Modell" in detail.text
    assert "CPU Hersteller" in detail.text
    assert "CPU Name" in detail.text
    assert "CPU Cores" in detail.text
    assert "Storage / HDD" in detail.text
    assert edit.status_code == 200
    assert 'name="hardware_model"' in edit.text
    assert 'name="hardware_cpu_vendor"' in edit.text
    assert 'name="hardware_cpu_name"' in edit.text
    assert 'name="hardware_cpu_cores"' in edit.text
    assert 'name="hardware_memory"' in edit.text
    assert 'name="hardware_gpu"' in edit.text
    assert 'name="hardware_storage"' in edit.text

    response = client.post(
        f"/objects/{object_id}",
        data={
            "hardware_model": "Beelink SER5",
            "hardware_cpu_vendor": "AMD",
            "hardware_cpu_name": "Ryzen 7 7840U",
            "hardware_cpu_cores": "8",
            "hardware_memory": "64 GB",
            "hardware_gpu": "Radeon 780M",
            "hardware_storage": "2 TB NVMe",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    updated = client.get(f"/objects/{object_id}")
    assert "Beelink SER5" in updated.text
    assert "AMD" in updated.text
    assert "Ryzen 7 7840U" in updated.text
    assert "8" in updated.text
    assert "64 GB" in updated.text
    assert "Radeon 780M" in updated.text
    assert "2 TB NVMe" in updated.text
    assert "Feld Modell wurde von leer auf Beelink SER5 geändert" in updated.text
    assert "Feld CPU Hersteller wurde von leer auf AMD geändert" in updated.text
    assert "Feld CPU Name wurde von leer auf Ryzen 7 7840U geändert" in updated.text
    assert "Feld CPU Cores wurde von leer auf 8 geändert" in updated.text
    assert "Feld Memory wurde von leer auf 64 GB geändert" in updated.text
    assert "Feld GPU wurde von leer auf Radeon 780M geändert" in updated.text
    assert "Feld Storage / HDD wurde von leer auf 2 TB NVMe geändert" in updated.text
    with session_factory() as session:
        catalog_object = get_object(session, object_id)
    assert catalog_object is not None
    assert catalog_object.status == "active"
    assert catalog_object.summary == "Hardware test object."
    assert catalog_object.data["hardware"] == {
        "model": "Beelink SER5",
        "cpu": {
            "vendor": "AMD",
            "name": "Ryzen 7 7840U",
            "cores": "8",
        },
        "memory": "64 GB",
        "gpu": "Radeon 780M",
        "storage": "2 TB NVMe",
    }


def test_system_detail_can_edit_resource_hardware_fields(
    client: TestClient,
    session_factory,
) -> None:
    object_id = "hardware-system"
    with session_factory() as session:
        upsert_object(
            session,
            CatalogObjectIn(
                id=object_id,
                kind="system",
                label="Hardware system",
                status="active",
                summary="Hardware test object.",
                data={"schema_version": 1},
            ),
        )

    detail = client.get(f"/objects/{object_id}")
    edit = client.get(f"/objects/{object_id}?edit=hardware")

    assert detail.status_code == 200
    assert "Hardware" in detail.text
    assert "Modell" not in detail.text
    assert "CPU Hersteller" not in detail.text
    assert "CPU Name" not in detail.text
    assert "CPU Cores" in detail.text
    assert "Storage / HDD" in detail.text
    assert edit.status_code == 200
    assert 'name="hardware_model"' not in edit.text
    assert 'name="hardware_cpu_vendor"' not in edit.text
    assert 'name="hardware_cpu_name"' not in edit.text
    assert 'name="hardware_cpu_cores"' in edit.text
    assert 'name="hardware_memory"' in edit.text
    assert 'name="hardware_gpu"' in edit.text
    assert 'name="hardware_storage"' in edit.text

    response = client.post(
        f"/objects/{object_id}",
        data={
            "hardware_model": "Ignored model",
            "hardware_cpu_vendor": "Ignored vendor",
            "hardware_cpu_name": "Ignored CPU",
            "hardware_cpu_cores": "4",
            "hardware_memory": "16 GB",
            "hardware_gpu": "Shared GPU",
            "hardware_storage": "500 GB",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    updated = client.get(f"/objects/{object_id}")
    assert "Ignored model" not in updated.text
    assert "Ignored vendor" not in updated.text
    assert "Ignored CPU" not in updated.text
    assert "4" in updated.text
    assert "16 GB" in updated.text
    assert "Shared GPU" in updated.text
    assert "500 GB" in updated.text
    assert "Feld CPU Cores wurde von leer auf 4 geändert" in updated.text
    assert "Feld Memory wurde von leer auf 16 GB geändert" in updated.text
    assert "Feld GPU wurde von leer auf Shared GPU geändert" in updated.text
    assert "Feld Storage / HDD wurde von leer auf 500 GB geändert" in updated.text
    with session_factory() as session:
        catalog_object = get_object(session, object_id)
    assert catalog_object is not None
    assert catalog_object.data["hardware"] == {
        "cpu": {"cores": "4"},
        "memory": "16 GB",
        "gpu": "Shared GPU",
        "storage": "500 GB",
    }


@pytest.mark.parametrize("kind", ["host", "system", "service", "netzwerk"])
def test_object_data_updates_write_object_audit_for_public_kinds(
    session_factory,
    kind: str,
) -> None:
    object_id = f"audit-{kind}"
    with session_factory() as session:
        upsert_object(
            session,
            CatalogObjectIn(
                id=object_id,
                kind=kind,
                label=f"Audit {kind}",
                status="active",
                data={"schema_version": 1},
            ),
        )
        upsert_object(
            session,
            CatalogObjectIn(
                id=object_id,
                kind=kind,
                label=f"Audit {kind}",
                status="active",
                data={"schema_version": 1, "comment": f"{kind} changed"},
            ),
        )
        event = session.scalars(
            select(AuditEvent)
            .where(AuditEvent.object_id == object_id)
            .order_by(AuditEvent.id.desc())
        ).first()

    assert event is not None
    assert event.action == "update"
    assert event.summary == f"Feld Kommentar wurde von leer auf {kind} changed geändert"


@pytest.mark.parametrize("kind", ["netzwerk", "service"])
def test_network_and_service_detail_do_not_show_hardware_panel(
    client: TestClient,
    session_factory,
    kind: str,
) -> None:
    object_id = f"no-hardware-{kind}"
    with session_factory() as session:
        upsert_object(
            session,
            CatalogObjectIn(
                id=object_id,
                kind=kind,
                label=f"No Hardware {kind}",
                status="active",
                data={"schema_version": 1},
            ),
        )

    detail = client.get(f"/objects/{object_id}")
    edit = client.get(f"/objects/{object_id}?edit=hardware")

    assert detail.status_code == 200
    assert edit.status_code == 200
    assert 'name="hardware_cpu_name"' not in edit.text
    assert "Storage / HDD" not in detail.text


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
    relationships = article[relationship_start:]

    assert relationships.find('data-ref="system:fabrik"') < relationships.find(
        'data-ref="system:n8n"'
    )
    assert relationships.find("system:n8n") < relationships.find("service:n8n-web-ui")
    assert relationships.find("Systeme") < relationships.find("Services")
    assert "relationship-detail-stack" in article
    assert 'data-relationship-node' in relationships
    assert 'data-detail-target=' in relationships
    assert '<a class="relationship-pill' not in relationships
    assert 'href="/objects/n8n-web-ui"' in article


def test_host_result_groups_systems_and_services_in_one_relation_row(
    client: TestClient,
) -> None:
    response = client.get("/?q=fabrik")

    assert response.status_code == 200
    object_marker = '<span class="object-id">fabrik</span>'
    object_index = response.text.find(object_marker)
    assert object_index >= 0
    article_start = response.text.rfind("<article", 0, object_index)
    article_end = response.text.find("</article>", object_index)
    article = response.text[article_start:article_end]

    relationship_start = article.find('class="relationship-map"')
    relationships = article[relationship_start:]

    assert relationships.count('class="relationship-chain"') == 1
    assert relationships.find("Host") < relationships.find("Systeme")
    assert relationships.find("Systeme") < relationships.find("Services")
    assert 'data-ref="system:fabrik"' in relationships
    assert 'data-ref="system:n8n"' in relationships
    assert 'data-ref="service:n8n-web-ui"' in relationships


def test_object_detail_shows_data_and_relationships(client: TestClient) -> None:
    response = client.get("/objects/n8n")

    assert response.status_code == 200
    assert "n8n Web UI" in response.text
    assert "Relationships" in response.text
    assert "CREATED AT" in response.text
    assert "LAST CHANGED" in response.text
    assert re.search(
        r"\d{2}\.\d{2}\.\d{4}, \d{2}:\d{2} Uhr - (vor|gerade eben)",
        response.text,
    )
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


def test_object_detail_header_only_shows_navigation_and_theme(
    client: TestClient,
) -> None:
    response = client.get("/objects/n8n")

    assert response.status_code == 200
    header_match = re.search(r"<header class=\"topbar\">(.*?)</header>", response.text, re.S)
    assert header_match is not None
    header = header_match.group(1)

    assert "Zur Suche" in header
    assert 'data-theme-value="dark"' in header
    assert 'data-theme-value="light"' in header
    assert "n8n Web UI" not in header
    assert "system:n8n" not in header
    assert "active" not in header


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
    assert "CREATED AT" in edit_response.text
    assert "LAST CHANGED" in edit_response.text
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
    assert 'name="port_value"' not in network_edit.text
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
    assert "SSH admin" not in detail.text
    assert "key-only" in detail.text


def test_service_network_edit_only_exposes_and_updates_endpoints(
    client: TestClient,
    session_factory,
) -> None:
    with session_factory() as session:
        upsert_object(
            session,
            CatalogObjectIn(
                id="service-network-scope",
                kind="service",
                label="Service Network Scope",
                status="active",
                summary="Endpoint-only network edit.",
                data={
                    "schema_version": 1,
                    "network": {"addresses": [{"ip": "192.168.50.10", "scope": "lan"}]},
                    "ports": [{"port": 443, "protocol": "tcp", "purpose": "HTTPS"}],
                    "endpoints": [
                        {
                            "type": "Web",
                            "url": "https://192.168.50.10",
                            "port": 443,
                        }
                    ],
                },
            ),
        )

    edit_response = client.get("/objects/service-network-scope?edit=network")

    assert edit_response.status_code == 200
    assert "ENDPOINT TYPE" in edit_response.text
    assert '<select name="endpoint_type">' in edit_response.text
    for endpoint_type in ("Web", "REST API", "MCP", "HEC", "SSH"):
        assert f'<option value="{endpoint_type}"' in edit_response.text
    assert 'name="endpoint_type"' in edit_response.text
    assert 'value="Web" selected' in edit_response.text
    assert 'name="endpoint_name"' not in edit_response.text
    assert 'name="endpoint_url"' in edit_response.text
    assert 'name="endpoint_port"' in edit_response.text
    assert 'name="address_ip"' not in edit_response.text
    assert 'name="port_value"' not in edit_response.text

    update_response = client.post(
        "/objects/service-network-scope/network",
        data={
            "address_ip": "10.0.0.1",
            "address_interface": "eth9",
            "address_scope": "wan",
            "port_value": "8443",
            "port_protocol": "tcp",
            "port_purpose": "Injected",
            "port_exposure": "public",
            "endpoint_type": "REST API",
            "endpoint_url": "https://192.168.50.10/api",
            "endpoint_port": "443",
        },
        follow_redirects=False,
    )

    assert update_response.status_code == 303
    with session_factory() as session:
        updated = get_object(session, "service-network-scope")

    assert updated is not None
    assert updated.data["network"]["addresses"] == [{"ip": "192.168.50.10", "scope": "lan"}]
    assert updated.data["ports"] == [{"port": 443, "protocol": "tcp", "purpose": "HTTPS"}]
    assert updated.data["endpoints"] == [
        {"type": "REST API", "url": "https://192.168.50.10/api", "port": 443}
    ]

    invalid_response = client.post(
        "/objects/service-network-scope/network",
        data={
            "endpoint_type": "SMTP",
            "endpoint_url": "smtp://192.168.50.10:25",
            "endpoint_port": "25",
        },
        follow_redirects=False,
    )

    assert invalid_response.status_code == 422
    assert "endpoint type must be one of: Web, REST API, MCP, HEC, SSH" in invalid_response.text


def test_service_detail_can_edit_service_information_fields(
    client: TestClient,
    session_factory,
) -> None:
    object_id = "service-information-scope"
    with session_factory() as session:
        upsert_object(
            session,
            CatalogObjectIn(
                id=object_id,
                kind="service",
                label="Service Information Scope",
                status="active",
                summary="Service information edit.",
                data={
                    "schema_version": 1,
                    "service_information": {
                        "sources": ["https://github.com/example/service"],
                        "running_version": "0.0.1 beta rc-1",
                    },
                    "endpoints": [
                        {
                            "type": "Web",
                            "url": "https://192.168.50.10",
                            "port": 443,
                        }
                    ],
                },
            ),
        )

    detail_response = client.get(f"/objects/{object_id}")

    assert detail_response.status_code == 200
    service_info_index = detail_response.text.index("Service Information")
    network_index = detail_response.text.index("Netzwerk")
    assert service_info_index < network_index
    assert "https://github.com/example/service" in detail_response.text
    assert "0.0.1 beta rc-1" in detail_response.text

    edit_response = client.get(f"/objects/{object_id}?edit=service-information")

    assert edit_response.status_code == 200
    assert 'name="service_sources"' in edit_response.text
    assert 'name="service_running_version"' in edit_response.text
    assert 'name="endpoint_url"' not in edit_response.text

    update_response = client.post(
        f"/objects/{object_id}",
        data={
            "service_sources": "https://github.com/example/service\nhttps://vendor.example",
            "service_running_version": "0.0.1 beta rc-2",
        },
        follow_redirects=False,
    )

    assert update_response.status_code == 303
    with session_factory() as session:
        updated = get_object(session, object_id)

    assert updated is not None
    assert updated.data["service_information"] == {
        "sources": [
            "https://github.com/example/service",
            "https://vendor.example",
        ],
        "running_version": "0.0.1 beta rc-2",
    }
    assert updated.data["endpoints"] == [
        {"type": "Web", "url": "https://192.168.50.10", "port": 443}
    ]


@pytest.mark.parametrize("kind", ["host", "system", "netzwerk"])
def test_public_network_edit_exposes_and_updates_endpoints(
    client: TestClient,
    session_factory,
    kind: str,
) -> None:
    object_id = f"{kind}-endpoint-scope"
    data = {
        "schema_version": 1,
        "network": {"addresses": [{"ip": "192.168.50.20", "scope": "lan"}]},
        "endpoints": [{"type": "Web", "url": "https://192.168.50.20", "port": 443}],
    }
    if kind in {"host", "system"}:
        data["ports"] = [{"port": 443, "protocol": "tcp", "purpose": "Legacy HTTPS"}]
    with session_factory() as session:
        upsert_object(
            session,
            CatalogObjectIn(
                id=object_id,
                kind=kind,
                label=f"{kind} endpoint scope",
                status="active",
                summary="Network endpoint edit.",
                data=data,
            ),
        )

    edit_response = client.get(f"/objects/{object_id}?edit=network")

    assert edit_response.status_code == 200
    assert "ENDPOINT TYPE" in edit_response.text
    assert '<select name="endpoint_type">' in edit_response.text
    assert '<option value="SSH"' in edit_response.text
    assert 'value="Web" selected' in edit_response.text
    assert 'name="endpoint_name"' not in edit_response.text
    assert 'name="address_ip"' in edit_response.text
    assert 'name="port_value"' not in edit_response.text

    form_data = {
        "address_ip": "192.168.50.20",
        "address_interface": "eth0",
        "address_scope": "lan",
        "endpoint_type": "SSH",
        "endpoint_url": "ssh://192.168.50.20:22",
        "endpoint_port": "22",
        "port_value": "8443",
        "port_protocol": "tcp",
        "port_purpose": "Ignored",
        "port_exposure": "private",
    }

    update_response = client.post(
        f"/objects/{object_id}/network",
        data=form_data,
        follow_redirects=False,
    )

    assert update_response.status_code == 303
    with session_factory() as session:
        updated = get_object(session, object_id)

    assert updated is not None
    assert updated.data["network"]["addresses"] == [
        {"ip": "192.168.50.20", "scope": "lan", "interface": "eth0"}
    ]
    if kind in {"host", "system"}:
        assert updated.data["ports"] == [
            {
                "port": 443,
                "protocol": "tcp",
                "purpose": "Legacy HTTPS",
            }
        ]
    assert updated.data["endpoints"] == [
        {"type": "SSH", "url": "ssh://192.168.50.20:22", "port": 22}
    ]


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
