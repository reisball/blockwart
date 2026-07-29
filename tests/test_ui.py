import json
import re
from collections.abc import Generator
from pathlib import Path
from string import Formatter

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.config import Settings
from blockwart.db.session import transaction
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
from blockwart.services.catalog import get_object
from blockwart.services.catalog import upsert_object as flush_object
from blockwart.services.seeds import import_seed_file
from blockwart.ui.i18n import load_catalog, validate_locale_catalogs

SEED_PATH = Path(__file__).resolve().parents[1] / "seeds" / "pilot_objects.yaml"
TEST_ADMIN_TOKEN = "test-admin-token-with-at-least-32-characters"


def upsert_object(session: Session, payload: CatalogObjectIn):
    """Persist test setup explicitly; production helpers only flush."""

    with transaction(session):
        return flush_object(session, payload)


@pytest.fixture
def session_factory(alembic_session_factory):
    with alembic_session_factory() as session:
        with transaction(session):
            import_seed_file(session, SEED_PATH)
    return alembic_session_factory


@pytest.fixture
def client(session_factory) -> Generator[TestClient, None, None]:
    app = create_app(settings=Settings(admin_token=TEST_ADMIN_TOKEN))

    def override_get_session() -> Generator[Session, None, None]:
        with session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    with TestClient(app) as test_client:
        unlock = test_client.post(
            "/admin/unlock",
            data={"admin_token": TEST_ADMIN_TOKEN},
            follow_redirects=False,
        )
        assert unlock.status_code == 303
        yield test_client


def test_index_lists_seeded_objects_and_filters_search(client: TestClient) -> None:
    response = client.get("/?q=brieftraeger&kind=system")

    assert response.status_code == 200
    assert "brieftraeger" in response.text
    assert "Referenzdoku" not in response.text
    assert "brieftraeger-ocr-worker" in response.text


def test_ui_assets_resolve_from_package_outside_repo_root(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.chdir(tmp_path)

    index_response = client.get("/")
    static_response = client.get("/static/app.css")

    assert index_response.status_code == 200
    assert "Blockwart" in index_response.text
    assert static_response.status_code == 200
    assert "text/css" in static_response.headers["content-type"]


def test_index_uses_english_as_the_fallback_locale(client: TestClient) -> None:
    response = client.get(
        "/",
        headers={"Accept-Language": "fr-FR,fr;q=0.9"},
    )

    assert response.status_code == 200
    assert '<html lang="en" data-view="catalog">' in response.text
    assert "Asset catalog" in response.text
    assert "Asset-Katalog" not in response.text


def test_explicit_german_locale_translates_the_explorer(client: TestClient) -> None:
    response = client.get(
        "/?lang=de",
        headers={"Accept-Language": "en-US,en;q=0.9"},
    )

    assert response.status_code == 200
    assert '<html lang="de" data-view="catalog">' in response.text
    assert "Objektkatalog" in response.text
    assert "Netzwerke" in response.text
    assert "Asset catalog" not in response.text
    assert response.cookies["blockwart-language"] == "de"


def test_language_cookie_covers_all_ui_surfaces(client: TestClient) -> None:
    client.get("/?lang=de")

    schema = client.get("/settings/schema?kind=host")
    detail = client.get("/objects/fabrik")
    admin = client.get("/admin")

    assert '<html lang="de">' in schema.text
    assert "Schema-Einstellungen" in schema.text
    assert "CPU-Hersteller" in schema.text
    assert '<html lang="de">' in detail.text
    assert "Zurück zum Katalog" in detail.text
    assert "Netzwerk" in detail.text
    assert "Aktiv" in detail.text
    assert '<html lang="de">' in admin.text
    assert "Schreibzugriff aktiv" in admin.text

    english = client.get("/?lang=en")
    assert '<html lang="en" data-view="catalog">' in english.text
    assert "Asset catalog" in english.text


def test_german_ui_localizes_status_and_lifecycle_values(
    client: TestClient,
) -> None:
    catalog = client.get("/?lang=de&view=topology")
    detail = client.get("/objects/fabrik?lang=de")
    edit = client.get("/objects/fabrik?lang=de&edit=overview")

    assert "AKTIV" in catalog.text
    assert "<strong>Aktiv</strong>" in detail.text
    assert '<option value="active" selected>Aktiv</option>' in edit.text
    assert '<option value="inactive">Inaktiv</option>' in edit.text
    assert '<option value="deleted">Gelöscht</option>' in edit.text


def test_locale_catalogs_have_identical_keys_and_format_contracts() -> None:
    validate_locale_catalogs()
    english = load_catalog("en")
    german = load_catalog("de")

    assert set(english) == set(german)
    for key in english:
        english_fields = {
            field_name
            for _, field_name, _, _ in Formatter().parse(english[key])
            if field_name is not None
        }
        german_fields = {
            field_name
            for _, field_name, _, _ in Formatter().parse(german[key])
            if field_name is not None
        }
        assert german_fields == english_fields, key


def test_topology_is_a_real_second_view(client: TestClient) -> None:
    response = client.get("/?view=topology")

    assert response.status_code == 200
    assert '<html lang="en" data-view="topology">' in response.text
    assert "Hardware, hosts, and services" in response.text
    assert 'class="topology-canvas"' in response.text
    assert 'data-asset-ref="system:fabrik"' in response.text
    assert 'data-asset-ref="service:fabrik-proxmox"' in response.text
    assert 'data-inspector' in response.text


def test_topology_keeps_network_assets_visible(
    client: TestClient,
    session_factory,
) -> None:
    with session_factory() as session:
        upsert_object(
            session,
            CatalogObjectIn(
                id="topology-network",
                kind="network",
                label="Topology Network",
                data={
                    "schema_version": 1,
                    "network": {
                        "addresses": [
                            {
                                "ip": "192.168.99.1",
                                "family": "ipv4",
                                "scope": "lan",
                            }
                        ]
                    },
                },
            ),
        )

    response = client.get("/?view=topology&kind=network")

    assert response.status_code == 200
    assert "Network inventory" in response.text
    assert "Network segments: 1" in response.text
    assert 'data-asset-ref="network:topology-network"' in response.text
    assert "No matching placement topology." not in response.text


def test_index_shows_kind_counts(client: TestClient) -> None:
    response = client.get("/")

    assert response.status_code == 200
    assert '<html lang="en" data-view="catalog">' in response.text
    assert "Asset catalog" in response.text
    assert "All assets" in response.text
    assert "<b>25</b>" in response.text
    assert "system" in response.text
    assert "network" in response.text
    assert "service" in response.text
    assert "host" in response.text
    assert 'value="decision"' not in response.text
    assert 'value="project"' not in response.text
    assert 'value="runbook"' not in response.text
    assert "credential_reference" not in response.text
    assert "Add asset" in response.text
    assert 'href="/?view=topology' in response.text
    assert 'href="/settings/schema"' in response.text
    assert 'class="panel panel-sticky"' not in response.text
    assert 'data-theme-value="dark"' in response.text
    assert 'data-theme-value="light"' in response.text
    assert "/static/theme.js" in response.text


def test_create_object_form_is_hidden_behind_button(client: TestClient) -> None:
    response = client.get("/")
    create_response = client.get("/?create=1")

    assert response.status_code == 200
    assert "create=1" in response.text
    assert 'name="object_id"' not in response.text
    assert 'data-asset-ref="system:fabrik"' in response.text
    assert 'class="asset-table"' in response.text
    assert 'data-inspector' in response.text
    assert "Host" in response.text
    assert "Service" in response.text
    assert "/static/index.js" in response.text
    assert "/static/explorer.css" in response.text
    assert create_response.status_code == 200
    assert "Create asset" in create_response.text
    assert 'role="dialog"' in create_response.text
    assert 'class="modal-overlay explorer-modal"' in create_response.text
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
    assert set(UI_SCHEMAS) == {"host", "system", "network", "service"}
    assert "platform" in UI_SCHEMAS["system"].create_fields
    assert "platform" not in UI_SCHEMAS["service"].create_fields
    assert "platform" not in UI_SCHEMAS["host"].create_fields
    assert "platform" not in UI_SCHEMAS["network"].create_fields
    for schema in UI_SCHEMAS.values():
        assert schema.create_fields[0] == "kind"
        assert "object_id" in schema.create_fields
        assert "primary_name" in schema.create_fields
        assert "summary" in schema.create_fields


def test_schema_settings_page_shows_selected_type_schema(client: TestClient) -> None:
    response = client.get("/settings/schema?kind=service")

    assert response.status_code == 200
    assert "Schema settings" in response.text
    assert '<option value="service" selected' in response.text
    assert "Service · Schema settings" in response.text
    assert "Service name" in response.text
    assert "primary_name_storage" in response.text
    assert "primary_name_storage_path" in response.text
    assert "Storage path" in response.text
    assert "catalog_objects.label" in response.text
    assert "data_json.platform" not in response.text
    assert "Storage convention" in response.text
    assert "data_json.hardware.*" in response.text
    assert "Visibility" in response.text
    assert "Create fields" in response.text
    assert "Schema fields" in response.text
    assert "Detail panels" in response.text
    assert "<code>kind</code>" in response.text
    assert "<code>primary_name</code>" in response.text
    assert "<code>platform</code>" not in response.text
    assert "<code>endpoint_type</code>" in response.text
    assert "<code>endpoint_url</code>" in response.text
    assert "<code>endpoint_port</code>" in response.text
    assert "data_json.endpoints[].type" in response.text
    assert "data_json.endpoints[].url" in response.text
    assert "data_json.endpoints[].port" in response.text
    assert "<code>overview</code>" in response.text
    assert "<code>network</code>" in response.text
    assert 'method="post"' in response.text
    assert "Save" in response.text
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
    assert "Host · Schema settings" in response.text
    assert "Hostname" in response.text


@pytest.mark.parametrize(
    ("kind", "primary_label", "storage", "platform_label"),
    [
        ("host", "Hostname", "network_hostname", False),
        ("system", "Hostname", "network_hostname", True),
        ("network", "Name", "label", False),
        ("service", "Service name", "label", False),
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
        assert primary_field["label_key"] == schema.primary_name_label_key
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
        "Service information",
        "Sources",
        "Running version",
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

    for kind in ("host", "system", "network"):
        fields = schema_field_payload(UI_SCHEMAS[kind])
        assert not any(str(field["key"]).startswith("service_") for field in fields)


def test_host_and_system_schema_include_hardware_fields(client: TestClient) -> None:
    host_response = client.get("/settings/schema?kind=host")
    assert host_response.status_code == 200
    for expected in (
        "Model",
        "CPU vendor",
        "CPU name",
        "CPU cores",
        "Memory",
        "GPU",
        "Storage",
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
        "CPU cores",
        "Memory",
        "GPU",
        "Storage",
        "data_json.hardware.cpu.cores",
        "data_json.hardware.memory",
        "data_json.hardware.gpu",
        "data_json.hardware.storage",
    ):
        assert expected in system_response.text
    for inherited in (
        "Model",
        "CPU vendor",
        "CPU name",
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

    for kind in ("network", "service"):
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
        data[f"field_label_{key}"] = load_catalog("en")[str(field["label_key"])]
        placeholder_key = str(field["placeholder_key"])
        data[f"field_placeholder_{key}"] = (
            load_catalog("en")[placeholder_key] if placeholder_key else ""
        )
        if field["required"]:
            data[f"field_required_{key}"] = "1"
        if field["visible_in_detail"]:
            data[f"field_visible_in_detail_{key}"] = "1"
    data["field_label_hardware_storage"] = "Disk"
    data["field_placeholder_hardware_storage"] = "z.B. 4 TB SSD"

    response = client.post("/settings/schema", data=data, follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/settings/schema?kind=system&saved=1&lang=en"
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
        data[f"field_label_{key}"] = load_catalog("en")[str(field["label_key"])]
        placeholder_key = str(field["placeholder_key"])
        data[f"field_placeholder_{key}"] = (
            load_catalog("en")[placeholder_key] if placeholder_key else ""
        )
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
    assert "Model" in detail.text
    assert "CPU vendor" in detail.text
    assert "CPU name" in detail.text
    assert "CPU cores" in detail.text
    assert "Storage" in detail.text
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
    assert "Changed Model from empty to Beelink SER5" in updated.text
    assert "Changed CPU vendor from empty to AMD" in updated.text
    assert "Changed CPU name from empty to Ryzen 7 7840U" in updated.text
    assert "Changed CPU cores from empty to 8" in updated.text
    assert "Changed Memory from empty to 64 GB" in updated.text
    assert "Changed GPU from empty to Radeon 780M" in updated.text
    assert "Changed Storage from empty to 2 TB NVMe" in updated.text
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
    assert "Model" not in detail.text
    assert "CPU vendor" not in detail.text
    assert "CPU name" not in detail.text
    assert "CPU cores" in detail.text
    assert "Storage" in detail.text
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
    assert "Changed CPU cores from empty to 4" in updated.text
    assert "Changed Memory from empty to 16 GB" in updated.text
    assert "Changed GPU from empty to Shared GPU" in updated.text
    assert "Changed Storage from empty to 500 GB" in updated.text
    with session_factory() as session:
        catalog_object = get_object(session, object_id)
    assert catalog_object is not None
    assert catalog_object.data["hardware"] == {
        "cpu": {"cores": "4"},
        "memory": "16 GB",
        "gpu": "Shared GPU",
        "storage": "500 GB",
    }


@pytest.mark.parametrize("kind", ["host", "system", "service", "network"])
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
    assert event.summary == "update"
    assert json.loads(event.details_json) == {
        "changes": [
            {
                "field": "comment",
                "new": f"{kind} changed",
                "old": "",
                "value_change": True,
            }
        ],
        "event": "update",
        "object_ref": f"{kind}:{object_id}",
        "version": 1,
    }


def test_object_detail_renders_multi_change_audit_summary_as_lines(
    client: TestClient,
    session_factory,
) -> None:
    with session_factory() as session:
        upsert_object(
            session,
            CatalogObjectIn(
                id="audit-lines",
                kind="system",
                label="Audit Lines",
                status="active",
                summary="Before",
                data={"schema_version": 1},
            ),
        )
        upsert_object(
            session,
            CatalogObjectIn(
                id="audit-lines",
                kind="system",
                label="Audit Lines",
                status="active",
                summary="After",
                data={"schema_version": 1, "comment": "Readable"},
            ),
        )

    response = client.get("/objects/audit-lines")

    assert response.status_code == 200
    audit_match = re.search(r"<ul class=\"audit-summary-lines\">(.*?)</ul>", response.text, re.S)
    assert audit_match is not None
    audit_summary = audit_match.group(1)
    assert "Changed Summary from Before to After" in audit_summary
    assert "Changed Comment from empty to Readable" in audit_summary
    assert "</li>" in audit_summary


@pytest.mark.parametrize("kind", ["network", "service"])
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
    assert '<th>Storage</th>' not in detail.text


def test_service_result_keeps_service_on_right_side(client: TestClient) -> None:
    response = client.get("/?view=topology&q=n8n-web-ui")

    assert response.status_code == 200
    assert '<html lang="en" data-view="topology">' in response.text
    assert "Infrastructure Map" not in response.text
    assert "Topology" in response.text
    assert response.text.find('data-asset-ref="system:n8n"') < response.text.find(
        'data-asset-ref="service:n8n-web-ui"'
    )
    assert re.search(
        r'class="map-node service-node selected"\s+'
        r'type="button"\s+data-asset-ref="service:n8n-web-ui"',
        response.text,
    )
    assert "service:paperless-api" not in response.text


def test_host_result_groups_systems_and_services_in_one_relation_row(
    client: TestClient,
    session_factory,
) -> None:
    with session_factory() as session:
        with transaction(session):
            for payload in (
                CatalogObjectIn(
                    id="hardware-ui",
                    kind="host",
                    label="Hardware UI",
                    data={"schema_version": 1},
                ),
                CatalogObjectIn(
                    id="runtime-ui",
                    kind="system",
                    label="Runtime UI",
                    data={"schema_version": 1},
                ),
                CatalogObjectIn(
                    id="service-ui",
                    kind="service",
                    label="Service UI",
                    data={"schema_version": 1},
                ),
            ):
                flush_object(session, payload)
            session.add_all(
                [
                    Relationship(
                        from_ref="host:hardware-ui",
                        relation_type="hosts",
                        to_ref="system:runtime-ui",
                    ),
                    Relationship(
                        from_ref="system:runtime-ui",
                        relation_type="hosts",
                        to_ref="service:service-ui",
                    ),
                ]
            )

    response = client.get("/?view=topology&q=hardware-ui")

    assert response.status_code == 200
    host_index = response.text.find('data-asset-ref="host:hardware-ui"')
    system_index = response.text.find('data-asset-ref="system:runtime-ui"')
    service_index = response.text.find('data-asset-ref="service:service-ui"')
    assert 0 <= host_index < system_index < service_index
    assert response.text.count('class="topology-cluster') == 1


def test_catalog_tree_starts_collapsed_and_keeps_filtered_results_visible(
    client: TestClient,
    session_factory,
) -> None:
    with session_factory() as session:
        with transaction(session):
            for payload in (
                CatalogObjectIn(
                    id="tree-hardware",
                    kind="host",
                    label="Tree Hardware",
                    data={"schema_version": 1},
                ),
                CatalogObjectIn(
                    id="tree-host",
                    kind="system",
                    label="Tree Host",
                    data={"schema_version": 1},
                ),
                CatalogObjectIn(
                    id="tree-service",
                    kind="service",
                    label="Tree Service",
                    data={"schema_version": 1},
                ),
            ):
                flush_object(session, payload)
            session.add_all(
                [
                    Relationship(
                        from_ref="host:tree-hardware",
                        relation_type="hosts",
                        to_ref="system:tree-host",
                    ),
                    Relationship(
                        from_ref="system:tree-host",
                        relation_type="hosts",
                        to_ref="service:tree-service",
                    ),
                ]
            )

    catalog = client.get("/")

    assert catalog.status_code == 200
    assert "tree-controls" in catalog.text
    assert "Collapse all" in catalog.text
    assert "Expand through hosts" in catalog.text
    assert "Expand through services" in catalog.text
    assert re.search(
        r'data-asset-ref="host:tree-hardware"\s+data-tree-node="host:tree-hardware"',
        catalog.text,
    )
    assert re.search(
        r'data-asset-ref="system:tree-host"\s+data-tree-row '
        r'data-tree-parent="host:tree-hardware" data-tree-depth="1" hidden\s+'
        r'data-tree-node="system:tree-host"',
        catalog.text,
    )
    assert re.search(
        r'data-asset-ref="service:tree-service"\s+data-tree-row '
        r'data-tree-parent="system:tree-host" data-tree-depth="2" hidden',
        catalog.text,
    )

    filtered = client.get("/?q=tree-service")

    assert filtered.status_code == 200
    assert 'data-tree-level="0"' not in filtered.text
    assert 'data-asset-ref="service:tree-service"' in filtered.text
    assert 'data-tree-parent="system:tree-host"' not in filtered.text


def test_catalog_tree_localizes_its_controls_in_german(client: TestClient) -> None:
    response = client.get("/?lang=de")

    assert response.status_code == 200
    assert "Alles zuklappen" in response.text
    assert "Bis Hosts aufklappen" in response.text
    assert "Bis Dienste aufklappen" in response.text
    assert 'aria-label="Nicht zugeordnet einklappen"' not in response.text
    assert 'aria-label="Nicht zugeordnet aufklappen"' in response.text


def test_object_detail_shows_data_and_relationships(client: TestClient) -> None:
    response = client.get("/objects/n8n")

    assert response.status_code == 200
    assert "n8n Web UI" in response.text
    assert "Relationships" in response.text
    assert "CREATED AT" in response.text
    assert "LAST CHANGED" in response.text
    assert re.search(
        r"\d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC · "
        r"(just now|\d+ (minute|minutes|hour|hours|day|days) ago)",
        response.text,
    )
    assert "Hostname" in response.text
    assert "Hostnames" not in response.text
    assert "n8n" in response.text
    assert "Outbound" in response.text
    assert "Access" in response.text
    assert "Credential-Referenzen" not in response.text
    assert "credential_references" not in response.text
    assert "/objects/n8n-api-credential" not in response.text
    assert "Comment" in response.text
    assert "Audit" in response.text
    assert "Referenzdoku" not in response.text
    assert "references/n8n.md" not in response.text
    assert "Daten JSON" not in response.text
    assert "Bearbeiten" not in response.text
    assert 'href="/objects/n8n?edit=overview"' in response.text
    assert "Create relationship" not in response.text
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

    assert "Back to catalog" in header
    assert 'data-theme-value="dark"' in header
    assert 'data-theme-value="light"' in header
    assert "n8n Web UI" not in header
    assert "system:n8n" not in header
    assert "n8n Web UI" not in header


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
    assert "Changed Comment from empty to Interner Kommentar" in detail.text
    with session_factory() as session:
        catalog_object = get_object(session, "n8n")
    assert catalog_object is not None
    assert catalog_object.data["comment"] == "Interner Kommentar"
    assert (catalog_object.status, catalog_object.lifecycle, catalog_object.health) == (
        "active",
        "active",
        "unknown",
    )


def test_relationship_add_form_is_hidden_behind_add_button(client: TestClient) -> None:
    response = client.get("/objects/n8n")
    add_response = client.get("/objects/n8n?edit=relationship-add")

    assert response.status_code == 200
    assert 'href="/objects/n8n?edit=relationship-add"' in response.text
    assert "Create relationship" not in response.text
    assert add_response.status_code == 200
    assert "Create relationship" in add_response.text
    form_start = add_response.text.find('<form class="form-grid relation-form"')
    form_end = add_response.text.find("</form>", form_start)
    form_html = add_response.text[form_start:form_end]
    assert "Target asset" in form_html
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
    assert "LXC" in index.text
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
        ("network", "Name", False, False),
        ("service", "Service name", False, False),
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
    assert "platform" not in catalog_object.data
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
    assert 'name="platform"' in edit_response.text
    assert "CREATED AT" in edit_response.text
    assert "LAST CHANGED" in edit_response.text
    assert "Bearbeiten" not in edit_response.text

    response = client.post(
        "/objects/n8n",
        data={
            "primary_name": "n8n-main",
            "kind": "system",
            "status": "inactive",
            "platform": "LXC",
            "summary": "Updated through overview.",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    detail = client.get("/objects/n8n")
    assert "n8n-main" in detail.text
    assert "Inactive" in detail.text
    assert "Updated through overview." in detail.text
    with session_factory() as session:
        catalog_object = get_object(session, "n8n")
    assert catalog_object is not None
    assert catalog_object.label == "n8n-main"
    assert (catalog_object.status, catalog_object.lifecycle, catalog_object.health) == (
        "inactive",
        "planned",
        "unknown",
    )
    assert catalog_object.data["platform"] == "LXC"
    assert catalog_object.data["network"]["hostnames"][0] == "n8n-main"


def test_repeating_identical_overview_update_is_noop(
    client: TestClient,
    session_factory,
) -> None:
    form = {
        "primary_name": "n8n-idempotent",
        "kind": "system",
        "status": "active",
        "platform": "LXC",
        "summary": "Stable UI state.",
    }
    first_response = client.post(
        "/objects/n8n",
        data=form,
        follow_redirects=False,
    )
    assert first_response.status_code == 303

    with session_factory() as session:
        after_first = get_object(session, "n8n")
        audits_after_first = session.scalars(
            select(AuditEvent).where(AuditEvent.object_id == "n8n").order_by(AuditEvent.id)
        ).all()
    assert after_first is not None
    first_audit_ids = [audit.id for audit in audits_after_first]

    second_response = client.post(
        "/objects/n8n",
        data=form,
        follow_redirects=False,
    )
    assert second_response.status_code == 303

    with session_factory() as session:
        after_second = get_object(session, "n8n")
        audits_after_second = session.scalars(
            select(AuditEvent).where(AuditEvent.object_id == "n8n").order_by(AuditEvent.id)
        ).all()

    assert after_second is not None
    assert after_second.updated_at == after_first.updated_at
    assert [audit.id for audit in audits_after_second] == first_audit_ids


def test_overview_edit_hides_platform_for_service(client: TestClient, session_factory) -> None:
    with session_factory() as session:
        upsert_object(
            session,
            CatalogObjectIn(
                id="service-overview-platform",
                kind="service",
                label="Service Overview Platform",
                status="active",
                data={"schema_version": 1, "platform": "Legacy"},
            ),
        )

    response = client.post(
        "/objects/service-overview-platform",
        data={
            "primary_name": "Service Without Platform",
            "kind": "service",
            "status": "active",
            "platform": "Docker",
            "summary": "Service overview update.",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    edit_response = client.get("/objects/service-overview-platform?edit=overview")
    assert edit_response.status_code == 200
    assert 'name="platform"' not in edit_response.text
    with session_factory() as session:
        catalog_object = get_object(session, "service-overview-platform")
    assert catalog_object is not None
    assert "platform" not in catalog_object.data


def test_detail_form_can_create_relationship(client: TestClient, session_factory) -> None:
    with session_factory() as session:
        with transaction(session):
            flush_object(
                session,
                CatalogObjectIn(
                    id="detail-hardware",
                    kind="host",
                    label="Detail Hardware",
                    data={"schema_version": 1},
                ),
            )
            flush_object(
                session,
                CatalogObjectIn(
                    id="detail-service",
                    kind="service",
                    label="Detail Service",
                    data={"schema_version": 1},
                ),
            )

    response = client.post(
        "/objects/detail-service/relationships",
        data={
            "direction": "inbound",
            "relation_type": "hosts",
            "target_ref": "host:detail-hardware",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    with session_factory() as session:
        relationship = session.query(Relationship).filter_by(
            from_ref="host:detail-hardware",
            relation_type="hosts",
            to_ref="service:detail-service",
        ).one_or_none()
    assert relationship is not None


def test_detail_form_rejects_second_placement_parent(
    client: TestClient,
    session_factory,
) -> None:
    response = client.post(
        "/objects/n8n-web-ui/relationships",
        data={
            "direction": "inbound",
            "relation_type": "hosts",
            "target_ref": "system:fabrik",
        },
        follow_redirects=False,
    )

    assert response.status_code == 422
    assert "already has placement parent system:n8n" in response.json()["detail"]
    with session_factory() as session:
        parents = session.scalars(
            select(Relationship).where(
                Relationship.relation_type == "hosts",
                Relationship.to_ref == "service:n8n-web-ui",
            )
        ).all()
    assert [(row.from_ref, row.to_ref) for row in parents] == [
        ("system:n8n", "service:n8n-web-ui")
    ]


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
    assert "Endpoint type" in edit_response.text
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
    service_info_index = detail_response.text.index("Service information")
    network_index = detail_response.text.index("Network")
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


@pytest.mark.parametrize("kind", ["host", "system", "network"])
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
    assert "Endpoint type" in edit_response.text
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
