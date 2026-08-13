import json
import re
from collections.abc import Generator
from html import unescape
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
from blockwart.models import AuditEvent, CatalogObject, Relationship
from blockwart.schemas.catalog import PUBLIC_OBJECT_KINDS, CatalogObjectIn
from blockwart.services.catalog import get_object
from blockwart.services.catalog import upsert_object as flush_object
from blockwart.services.commands import revision_etag
from blockwart.services.seeds import import_seed_file
from blockwart.ui.i18n import load_catalog, validate_locale_catalogs

SEED_PATH = Path(__file__).resolve().parents[1] / "seeds" / "pilot_objects.yaml"


def integrated_detail_html(document: str) -> str:
    marker = 'class="integrated-detail"'
    assert marker in document
    return unescape(document.split(marker, maxsplit=1)[1])


def upsert_object(session: Session, payload: CatalogObjectIn):
    """Persist test setup explicitly; production helpers only flush."""

    with transaction(session):
        return flush_object(session, payload)


class BrowserFormTestClient(TestClient):
    def __init__(self, app, session_factory) -> None:
        super().__init__(app)
        self._session_factory = session_factory

    def post(self, url, *, data=None, **kwargs):
        submitted = dict(data) if isinstance(data, dict) else data
        path = str(url).split("?", 1)[0]
        parts = path.strip("/").split("/")
        if (
            isinstance(submitted, dict)
            and len(parts) >= 2
            and parts[0] == "objects"
            and "if_match" not in submitted
        ):
            with self._session_factory() as session:
                catalog_object = session.get(CatalogObject, parts[1])
                if catalog_object is not None:
                    submitted["if_match"] = revision_etag(catalog_object.revision)
        return super().post(url, data=submitted, **kwargs)


@pytest.fixture
def session_factory(alembic_session_factory):
    with alembic_session_factory() as session:
        with transaction(session):
            import_seed_file(session, SEED_PATH)
    return alembic_session_factory


@pytest.fixture
def client(
    session_factory,
    install_unrestricted_read_access,
) -> Generator[TestClient, None, None]:
    app = create_app(settings=Settings())
    install_unrestricted_read_access(app)

    def override_get_session() -> Generator[Session, None, None]:
        with session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    with BrowserFormTestClient(app, session_factory) as test_client:
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
    assert '<html lang="en" data-view="catalog" data-page="catalog">' in response.text
    assert "Asset catalog" in response.text
    assert "Asset-Katalog" not in response.text


def test_explicit_german_locale_translates_the_explorer(client: TestClient) -> None:
    response = client.get(
        "/?lang=de",
        headers={"Accept-Language": "en-US,en;q=0.9"},
    )

    assert response.status_code == 200
    assert '<html lang="de" data-view="catalog" data-page="catalog">' in response.text
    assert "Objektkatalog" in response.text
    assert "Netzwerke" in response.text
    assert "Asset catalog" not in response.text
    assert response.cookies["blockwart-language"] == "de"


def test_language_cookie_covers_all_ui_surfaces(client: TestClient) -> None:
    client.get("/?lang=de")

    settings = client.get("/settings")
    schema = client.get("/settings/schema?kind=host")
    detail = client.get("/objects/fabrik")

    assert '<html lang="de">' in settings.text
    assert "Darstellung und Sprache" in settings.text
    assert '<html lang="de">' in schema.text
    assert "Schema-Einstellungen" in schema.text
    assert "CPU-Hersteller" in schema.text
    assert '<html lang="de" data-view="catalog" data-page="detail">' in detail.text
    assert "Zurück zum Katalog" in detail.text
    assert "Netzwerk" in detail.text
    assert "Aktiv" in detail.text

    english = client.get("/?lang=en")
    assert '<html lang="en" data-view="catalog" data-page="catalog">' in english.text
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
    assert '<html lang="en" data-view="topology" data-page="topology">' in response.text
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
                        "category": "segment",
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
    assert '<html lang="en" data-view="catalog" data-page="catalog">' in response.text
    assert "Asset catalog" in response.text
    assert "All assets" in response.text
    assert "<b>28</b>" in response.text
    assert "system" in response.text
    assert "network" in response.text
    assert "service" in response.text
    assert "host" in response.text
    assert "kind=decision" in response.text
    assert 'value="project"' not in response.text
    assert 'value="runbook"' not in response.text
    assert "Add asset" in response.text
    assert 'href="/?view=topology' in response.text
    assert 'href="/settings"' in response.text
    assert 'href="/settings/schema"' not in response.text
    assert 'class="panel panel-sticky"' not in response.text
    assert 'data-theme-value="dark"' not in response.text
    assert 'data-theme-value="light"' not in response.text
    assert "/static/theme.js" in response.text


def test_settings_page_bundles_configuration_controls(client: TestClient) -> None:
    response = client.get("/settings")
    schema = client.get("/settings/schema")

    assert response.status_code == 200
    assert "Settings" in response.text
    assert "Appearance and language" in response.text
    assert 'href="/settings/schema"' in response.text
    assert 'href="/admin/principals"' not in response.text
    assert 'class="language-switcher"' in response.text
    assert 'data-theme-value="dark"' in response.text
    assert 'data-theme-value="light"' in response.text
    assert 'aria-labelledby="settings-appearance-title"' in response.text
    assert 'aria-labelledby="settings-schema-title"' in response.text
    assert schema.status_code == 200
    assert 'href="/settings"' in schema.text
    assert 'class="language-switcher"' not in schema.text
    assert 'data-theme-value="dark"' not in schema.text
    assert 'data-theme-value="light"' not in schema.text


def test_installed_software_detail_editor_is_localized_ordered_and_safe(
    client: TestClient,
    session_factory,
) -> None:
    with session_factory() as session:
        upsert_object(
            session,
            CatalogObjectIn(
                id="ui-installed-software",
                kind="host",
                label="Software host",
                data={
                    "installed_software": [
                        {"name": "First", "version": "2026.08"},
                        {
                            "name": "Docker Engine",
                            "version": "1:27.5.1-1~ubuntu.24.04",
                            "url": "https://docs.docker.com/engine/release-notes/27/",
                        },
                    ]
                },
            ),
        )

    detail = client.get("/objects/ui-installed-software?lang=en")
    assert detail.status_code == 200
    html = integrated_detail_html(detail.text)
    assert "Installed software" in html
    assert html.find("First") < html.find("Docker Engine")
    assert "1:27.5.1-1~ubuntu.24.04" in html
    assert (
        'href="https://docs.docker.com/engine/release-notes/27/" '
        'target="_blank" rel="noopener noreferrer"'
    ) in html

    editor = client.get("/objects/ui-installed-software?lang=en&edit=installed-software")
    assert editor.status_code == 200
    assert 'data-row-list="installed-software"' in editor.text
    assert 'data-row-template="installed-software"' in editor.text
    assert 'name="software_name" value="Docker Engine"' in editor.text
    assert 'name="software_version" value="1:27.5.1-1~ubuntu.24.04"' in editor.text
    assert "Entries stay in the order shown" in editor.text
    assert "Add software" in editor.text
    assert "Remove" in editor.text

    german = client.get("/objects/ui-installed-software?lang=de")
    assert german.status_code == 200
    assert "Installierte Software" in german.text
    assert "Release-Informationen öffnen" in german.text


def test_installed_software_ui_empty_state_write_etag_revision_and_audit(
    client: TestClient,
    session_factory,
) -> None:
    with session_factory() as session:
        upsert_object(
            session,
            CatalogObjectIn(
                id="ui-empty-software",
                kind="system",
                label="Empty software system",
            ),
        )

    empty = client.get("/objects/ui-empty-software?lang=en")
    assert empty.status_code == 200
    assert "No installed software recorded." in empty.text
    assert "edit=installed-software" in empty.text

    updated = client.post(
        "/objects/ui-empty-software/installed-software?lang=en",
        data={
            "software_name": ["Second", "First"],
            "software_version": ["vendor build+rev_7 / exact", "2026.08"],
            "software_url": ["", "https://example.invalid/releases?q=%3Cscript%3E"],
        },
        follow_redirects=False,
    )
    assert updated.status_code == 303

    with session_factory() as session:
        stored = get_object(session, "ui-empty-software")
        assert stored is not None
        assert stored.revision == 2
        assert stored.data["installed_software"] == [
            {"name": "Second", "version": "vendor build+rev_7 / exact"},
            {
                "name": "First",
                "version": "2026.08",
                "url": "https://example.invalid/releases?q=%3Cscript%3E",
            },
        ]
        audits = list(
            session.scalars(
                select(AuditEvent)
                .where(AuditEvent.object_id == "ui-empty-software")
                .order_by(AuditEvent.id.desc())
            )
        )
        assert audits[0].action == "update"
        details = json.loads(audits[0].details_json)
        assert details["old_revision"] == 1
        assert details["new_revision"] == 2
        assert details["channel"] == "ui"

    rendered = client.get("/objects/ui-empty-software?lang=en")
    assert rendered.text.find("Second") < rendered.text.find("First")
    assert 'href="https://example.invalid/releases?q=%3Cscript%3E"' in rendered.text
    assert "q=<script>" not in rendered.text
    assert 'rel="noopener noreferrer"' in rendered.text

    conflict = client.post(
        "/objects/ui-empty-software/installed-software?lang=en",
        data={
            "if_match": '"rev-1"',
            "software_name": "Stale",
            "software_version": "1",
            "software_url": "",
        },
        follow_redirects=False,
    )
    assert conflict.status_code == 412

    removed = client.post(
        "/objects/ui-empty-software/installed-software?lang=en",
        data={"if_match": '"rev-2"'},
        follow_redirects=False,
    )
    assert removed.status_code == 303
    with session_factory() as session:
        stored = get_object(session, "ui-empty-software")
        assert stored is not None
        assert stored.revision == 3
        assert "installed_software" not in stored.data


def test_installed_software_ui_edit_marks_discovered_object_manual_and_audits(
    client: TestClient,
    session_factory,
) -> None:
    with session_factory() as session:
        upsert_object(
            session,
            CatalogObjectIn(
                id="ui-discovered-software",
                kind="host",
                label="Discovered software host",
                provenance={
                    "source_type": "discovery",
                    "source_ref": "agent:inventory-fixture",
                    "managed_by": "test-agent",
                    "observed_at": "2026-08-08T12:00:00Z",
                    "manual_override": False,
                },
            ),
        )

    updated = client.post(
        "/objects/ui-discovered-software/installed-software?lang=en",
        data={
            "if_match": '"rev-1"',
            "software_name": "Docker Engine",
            "software_version": "27.5.1",
            "software_url": "https://example.invalid/releases",
        },
        follow_redirects=False,
    )
    assert updated.status_code == 303

    with session_factory() as session:
        stored = get_object(session, "ui-discovered-software")
        assert stored is not None
        assert stored.revision == 2
        assert stored.provenance.source_type == "manual"
        assert stored.provenance.manual_override is True
        assert stored.provenance.source_ref is None
        assert stored.provenance.managed_by is None
        assert stored.provenance.observed_at is None
        audit = session.scalars(
            select(AuditEvent)
            .where(AuditEvent.object_id == "ui-discovered-software")
            .order_by(AuditEvent.id.desc())
        ).first()
        assert audit is not None
        details = json.loads(audit.details_json)
        assert audit.action == "update"
        assert details["channel"] == "ui"
        assert details["old_revision"] == 1
        assert details["new_revision"] == 2
        assert details["changes"] == [
            {
                "field": "installed_software",
                "before": None,
                "after": [
                    {
                        "name": "Docker Engine",
                        "version": "27.5.1",
                        "url": "https://example.invalid/releases",
                    }
                ],
                "old": "",
                "new": "",
                "value_change": False,
            }
        ]


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
    assert set(UI_SCHEMAS) == {
        "host",
        "system",
        "network",
        "device",
        "service",
        "runbook",
        "decision",
        "project",
    }
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
    assert 'method="post"' not in response.text
    assert 'name="field_label_primary_name"' not in response.text
    assert 'name="field_placeholder_summary"' not in response.text


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
    assert ("<code>platform</code>" in response.text) is platform_label


def test_ui_schema_payload_matches_ui_object_kinds() -> None:
    ui_kinds = {*PUBLIC_OBJECT_KINDS, "runbook", "decision", "project"}
    assert set(UI_SCHEMAS) == ui_kinds
    assert set(ui_schema_payload()) == ui_kinds
    for schema in UI_SCHEMAS.values():
        # Every declared field resolves either from the shared registry or from
        # the kind's own definitions; nothing may be left unresolvable.
        known = set(FIELD_DEFINITIONS) | set(schema.field_overrides)
        assert all(field_key in known for field_key in schema.create_fields)
        assert all(field_key in known for field_key in schema.fields)
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
            assert f'name="field_label_{key}"' not in response.text
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


def test_schema_settings_http_is_read_only(
    client: TestClient,
    tmp_path,
    monkeypatch,
) -> None:
    override_path = tmp_path / "ui_schema_overrides.json"
    monkeypatch.setenv("BLOCKWART_SCHEMA_OVERRIDES_PATH", str(override_path))
    response = client.post(
        "/settings/schema",
        data={"kind": "system", "field_label_hardware_storage": "Disk"},
        follow_redirects=False,
    )

    assert response.status_code == 405
    assert not override_path.exists()


def test_service_endpoint_schema_metadata_drives_endpoint_table(
    client: TestClient,
    tmp_path,
    monkeypatch,
) -> None:
    override_path = tmp_path / "ui_schema_overrides.json"
    monkeypatch.setenv("BLOCKWART_SCHEMA_OVERRIDES_PATH", str(override_path))
    settings = client.get("/settings/schema?kind=service")
    edit = client.get("/objects/n8n-web-ui?edit=network")
    detail = client.get("/objects/n8n-web-ui")
    assert "data_json.endpoints[].url" in settings.text
    assert "URL" in edit.text
    assert "URL" in detail.text
    assert not override_path.exists()


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

    assert response.status_code == 303, response.text
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
    detail_content = integrated_detail_html(detail.text)

    assert detail.status_code == 200
    assert "Hardware" in detail_content
    assert "Model" not in detail_content
    assert "CPU vendor" not in detail_content
    assert "CPU name" not in detail_content
    assert "CPU cores" in detail_content
    assert "Storage" in detail_content
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


@pytest.mark.parametrize("kind", ["host", "system", "service", "network", "device"])
def test_object_data_updates_write_object_audit_for_public_kinds(
    session_factory,
    kind: str,
) -> None:
    object_id = f"audit-{kind}"
    base_data: dict[str, object] = {"schema_version": 1}
    if kind == "network":
        base_data["network"] = {"category": "segment"}
    elif kind == "device":
        base_data["device"] = {"category": "other"}
    with session_factory() as session:
        upsert_object(
            session,
            CatalogObjectIn(
                id=object_id,
                kind=kind,
                label=f"Audit {kind}",
                status="active",
                data=base_data,
            ),
        )
        upsert_object(
            session,
            CatalogObjectIn(
                id=object_id,
                kind=kind,
                label=f"Audit {kind}",
                status="active",
                data={**base_data, "comment": f"{kind} changed"},
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
    data: dict[str, object] = {"schema_version": 1}
    if kind == "network":
        data["network"] = {"category": "segment"}
    with session_factory() as session:
        upsert_object(
            session,
            CatalogObjectIn(
                id=object_id,
                kind=kind,
                label=f"No Hardware {kind}",
                status="active",
                data=data,
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
    assert '<html lang="en" data-view="topology" data-page="topology">' in response.text
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


def test_catalog_tree_toggle_overrides_global_button_minimum_size(
    client: TestClient,
) -> None:
    catalog_response = client.get("/")
    stylesheet_response = client.get("/static/explorer.css")

    assert catalog_response.status_code == 200
    assert '/static/explorer.css?v=010"' in catalog_response.text
    assert stylesheet_response.status_code == 200
    tree_toggle_rule = re.search(
        r"\.tree-toggle\s*\{(?P<body>[^}]*)\}",
        stylesheet_response.text,
    )
    assert tree_toggle_rule is not None
    assert re.search(r"\bmin-width:\s*19px;", tree_toggle_rule["body"])
    assert re.search(r"\bmin-height:\s*19px;", tree_toggle_rule["body"])


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
    assert "/objects/n8n-api-credential" not in response.text
    assert "Comment" in response.text
    assert "Audit" in response.text
    assert "Referenzdoku" not in response.text
    assert "references/n8n.md" not in response.text
    assert "Daten JSON" not in response.text
    assert "Bearbeiten" not in response.text
    assert (
        'href="/objects/n8n?view=catalog&q=&kind=&edit=overview"'
        in unescape(response.text)
    )
    assert "Create relationship" not in response.text
    assert 'href="/settings"' in response.text
    assert 'data-theme-value="dark"' not in response.text
    assert 'data-theme-value="light"' not in response.text
    assert "/static/theme.js" in response.text


def test_object_detail_is_integrated_into_the_explorer_shell(
    client: TestClient,
) -> None:
    response = client.get("/objects/n8n")

    assert response.status_code == 200
    document = unescape(response.text)

    assert '<html lang="en" data-view="catalog" data-page="detail">' in document
    assert '<header class="explorer-topbar">' in document
    assert 'class="filter-rail"' in document
    assert 'class="asset-inspector"' in document
    assert 'class="integrated-detail"' in document
    assert 'href="/?view=catalog&q=&kind="' in document
    assert "← Back to catalog" in document
    assert 'href="/settings"' in document
    assert 'data-theme-value="dark"' not in document
    assert 'data-theme-value="light"' not in document
    assert '<header class="topbar">' not in document


def test_object_detail_preserves_catalog_context_in_links_and_forms(
    client: TestClient,
) -> None:
    state_token = "CatalogState_123456"
    response = client.get(
        "/objects/n8n"
        f"?view=catalog&q=n8n&kind=system&return_state={state_token}"
    )

    assert response.status_code == 200
    document = unescape(response.text)
    assert 'data-return-state="CatalogState_123456"' in document
    assert (
        'href="/?view=catalog&q=n8n&kind=system&restore=CatalogState_123456"'
        in document
    )
    assert (
        'href="/objects/n8n?view=catalog&q=n8n&kind=system'
        '&return_state=CatalogState_123456&edit=overview"'
        in document
    )
    assert (
        'action="/objects/n8n/comments?view=catalog&q=n8n&kind=system'
        '&return_state=CatalogState_123456"'
        in document
    )
    assert (
        'href="/objects/fabrik?view=catalog&q=n8n&kind=system'
        '&return_state=CatalogState_123456"'
        in document
    )


def test_object_detail_replaces_only_the_topology_middle_region(
    client: TestClient,
) -> None:
    state_token = "TopologyState_12345"
    response = client.get(
        "/objects/n8n"
        f"?view=topology&q=n8n&kind=system&return_state={state_token}"
    )

    assert response.status_code == 200
    document = unescape(response.text)
    assert '<html lang="en" data-view="topology" data-page="detail">' in document
    assert 'class="topology-shell"' in document
    assert 'class="map-heading"' in document
    assert 'class="map-workbench"' in document
    assert 'class="topology-detail-main"' in document
    assert 'class="map-inspector"' in document
    assert 'class="topology-canvas"' not in document
    assert "← Back to topology" in document
    assert (
        'href="/?view=topology&q=n8n&kind=system&restore=TopologyState_12345"'
        in document
    )


def test_object_detail_normalizes_untrusted_navigation_context(
    client: TestClient,
) -> None:
    response = client.get(
        "/objects/n8n"
        "?view=https%3A%2F%2Fevil.example"
        "&kind=credential"
        "&q=needle"
        "&return_state=..%2F..%2Fevil"
    )

    assert response.status_code == 200
    document = unescape(response.text)
    assert 'data-view="catalog" data-page="detail"' in document
    assert 'href="/?view=catalog&q=needle&kind="' in document
    assert "restore=" not in integrated_detail_html(response.text)
    assert 'href="https://evil.example' not in document
    assert 'action="https://evil.example' not in document


def test_detail_validation_error_stays_in_topology_context(
    client: TestClient,
) -> None:
    state_token = "ValidationState_12"
    response = client.post(
        "/objects/fabrik"
        f"?view=topology&q=fabrik&kind=host&return_state={state_token}",
        data={"platform": "unsupported-platform"},
        follow_redirects=False,
    )

    assert response.status_code == 422
    document = unescape(response.text)
    assert 'data-view="topology" data-page="detail"' in document
    assert "Unsupported platform" in document
    assert 'name="platform"' in integrated_detail_html(response.text)
    assert (
        'href="/?view=topology&q=fabrik&kind=host'
        '&restore=ValidationState_12"'
        in document
    )


def test_explorer_history_state_is_small_and_session_scoped() -> None:
    source = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "blockwart"
        / "ui"
        / "static"
        / "index.js"
    ).read_text()

    assert 'const stateStoragePrefix = "blockwart-explorer-state:"' in source
    assert "sessionStorage.setItem" in source
    assert "history.replaceState" in source
    assert 'target.searchParams.set("return_state", token)' in source
    assert "selectedRef: triggerAsset" in source
    assert "maximumTreeDepth" in source
    assert "expandedTreeNodes" in source
    assert "scrollTop" in source
    assert "windowScrollY" in source
    assert "focusDetailHeading()" in source
    assert 'window.addEventListener("pageshow"' in source
    assert 'searchParams.set("state"' not in source


def test_topology_asset_buttons_are_not_blocked_by_nested_control_guard() -> None:
    source = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "blockwart"
        / "ui"
        / "static"
        / "index.js"
    ).read_text()

    assert "const interactiveTarget = event.target.closest" in source
    assert "interactiveTarget && interactiveTarget !== node" in source


def test_comment_form_updates_object_and_audit(
    client: TestClient,
    session_factory,
) -> None:
    response = client.post(
        "/objects/n8n/comments"
        "?view=topology&q=n8n&kind=system&return_state=CommentState_123",
        data={
            "comment": "**Interner Kommentar**",
            "idempotency_key": "ui-comment-test-0001",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303, response.text
    assert (
        response.headers["location"]
        == "/objects/n8n?view=topology&q=n8n&kind=system"
        "&return_state=CommentState_123"
    )
    detail = client.get("/objects/n8n")
    assert "<strong>Interner Kommentar</strong>" in detail.text
    assert "Added object comment" in detail.text
    with session_factory() as session:
        catalog_object = get_object(session, "n8n")
    assert catalog_object is not None
    assert "comment" not in catalog_object.data
    assert (catalog_object.status, catalog_object.lifecycle, catalog_object.health) == (
        "active",
        "active",
        "unknown",
    )


def test_comment_markdown_is_safe_in_recent_and_full_timeline(
    client: TestClient,
) -> None:
    body = (
        "<script>alert(1)</script>\n\n"
        "![tracker](https://tracker.invalid/pixel)\n\n"
        "[safe](https://example.com/runbook)"
    )
    created = client.post(
        "/objects/n8n/comments",
        data={
            "comment": body,
            "idempotency_key": "ui-comment-markdown-safety-0001",
        },
        follow_redirects=False,
    )
    assert created.status_code == 303

    for response in (
        client.get("/objects/n8n"),
        client.get("/objects/n8n/comments"),
    ):
        assert response.status_code == 200
        assert "<script>alert(1)</script>" not in response.text
        assert "<img" not in response.text
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in response.text
        assert 'href="https://example.com/runbook"' in response.text
        assert 'rel="noopener noreferrer nofollow"' in response.text


def test_comment_timeline_preserves_navigation_context_on_next_and_back(
    client: TestClient,
) -> None:
    for index in range(21):
        response = client.post(
            "/objects/n8n/comments",
            data={
                "comment": f"Timeline entry {index}",
                "idempotency_key": f"ui-comment-navigation-{index:04d}",
            },
            follow_redirects=False,
        )
        assert response.status_code == 303

    state_token = "CommentTimelineState_123"
    response = client.get(
        "/objects/n8n/comments"
        f"?view=topology&q=n8n&kind=system&return_state={state_token}"
    )
    assert response.status_code == 200
    document = unescape(response.text)
    assert (
        'href="/objects/n8n?view=topology&q=n8n&kind=system'
        f'&return_state={state_token}"'
        in document
    )
    assert (
        'href="/objects/n8n/comments?view=topology&q=n8n&kind=system'
        f'&return_state={state_token}&cursor='
        in document
    )


def test_relationship_add_form_is_hidden_behind_add_button(client: TestClient) -> None:
    response = client.get("/objects/n8n")
    add_response = client.get("/objects/n8n?edit=relationship-add")

    assert response.status_code == 200
    assert (
        'href="/objects/n8n?view=catalog&q=&kind=&edit=relationship-add"'
        in unescape(response.text)
    )
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


def test_network_uplink_form_creates_and_replaces_metadata_through_commands(
    client: TestClient,
    session_factory,
) -> None:
    for object_id, category in (("ui-switch", "switch"), ("ui-router", "router")):
        with session_factory() as session:
            upsert_object(
                session,
                CatalogObjectIn(
                    id=object_id,
                    kind="network",
                    label=object_id.replace("-", " ").title(),
                    data={
                        "schema_version": 1,
                        "network": {"category": category},
                    },
                ),
            )

    form = client.get("/objects/ui-switch?edit=relationship-add")
    assert form.status_code == 200
    assert 'name="relation_type" value="uplinks_to"' in form.text
    assert 'name="mode"' in form.text
    assert "Ui Router" in form.text

    created = client.post(
        "/objects/ui-switch/relationships",
        data={
            "direction": "outbound",
            "relation_type": "uplinks_to",
            "target_ref": "network:ui-router",
            "link_kind": "ethernet",
            "mode": "trunk",
            "source_interface": "eth0",
            "target_interface_or_port": "port-1",
            "primary": "true",
            "note": "Primary lab uplink",
        },
        follow_redirects=False,
    )
    assert created.status_code == 303
    assert created.headers["location"].endswith("notice=relationship-saved")

    replaced = client.post(
        "/objects/ui-switch/relationships",
        data={
            "direction": "outbound",
            "relation_type": "uplinks_to",
            "target_ref": "network:ui-router",
            "link_kind": "ethernet",
            "mode": "routed",
            "source_interface": "eth1",
            "target_interface_or_port": "wan",
            "note": "Routed lab uplink",
        },
        follow_redirects=False,
    )
    assert replaced.status_code == 303

    with session_factory() as session:
        relationship = session.scalar(
            select(Relationship).where(
                Relationship.from_ref == "network:ui-switch",
                Relationship.relation_type == "uplinks_to",
                Relationship.to_ref == "network:ui-router",
            )
        )
        actions = session.scalars(
            select(AuditEvent.action)
            .where(AuditEvent.object_id == "ui-switch")
            .order_by(AuditEvent.id)
        ).all()

    assert relationship is not None
    assert json.loads(relationship.metadata_json) == {
        "link_kind": "ethernet",
        "mode": "routed",
        "note": "Routed lab uplink",
        "source_interface": "eth1",
        "target_interface_or_port": "wan",
    }
    assert actions[-2:] == ["relationship_create", "relationship_metadata_replace"]


def test_create_object_form_redirects_to_detail(
    client: TestClient,
    session_factory,
) -> None:
    response = client.post(
        "/objects",
        data={
            "object_id": "test-system",
            "kind": "service",
            "label": "Test System",
            "status": "active",
            "labels": "infra, docker\nintern",
            "summary": "Created from UI test.",
            "data_json": '{"schema_version": 1}',
            "relation_target_ref": "system:fabrik",
            "relation_type": "hosts",
            "idempotency_key": "ui-test-create-system",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert (
        response.headers["location"]
        == "/objects/test-system?view=catalog&q=&kind="
    )
    detail = client.get("/objects/test-system")
    assert "Test System" in detail.text
    index = client.get("/?q=test-system")
    assert "infra" in index.text
    assert "docker" in index.text
    assert "intern" in index.text
    with session_factory() as session:
        catalog_object = get_object(session, "test-system")
    assert catalog_object is not None
    assert catalog_object.data["labels"] == ["infra", "docker", "intern"]
    assert "platform" not in catalog_object.data


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
            "data_json": (
                '{"network":{"category":"segment"},"schema_version":1}'
                if kind == "network"
                else '{"schema_version":1}'
            ),
            "relation_target_ref": "system:fabrik",
            "relation_type": "hosts",
            "idempotency_key": f"ui-schema-create-{kind}",
        },
        follow_redirects=False,
    )

    if kind != "service":
        assert response.status_code == 409
        with session_factory() as session:
            assert get_object(session, object_id) is None
        return
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
            "idempotency_key": "ui-test-create-service",
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
    document = unescape(response.text)
    assert 'data-page="detail"' in document
    assert 'class="form-grid relation-form"' in document
    assert "already has placement parent system:n8n" in document
    assert 'href="/?view=catalog&q=&kind="' in document
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


def test_empty_detail_panels_offer_explicit_first_row_actions(
    client: TestClient,
    session_factory,
) -> None:
    with session_factory() as session:
        upsert_object(
            session,
            CatalogObjectIn(
                id="empty-detail-panels",
                kind="service",
                label="Empty Detail Panels",
                status="active",
                summary="No endpoint or access rows yet.",
                data={"schema_version": 1},
            ),
        )

    detail = client.get("/objects/empty-detail-panels")
    network_edit = client.get("/objects/empty-detail-panels?edit=network")
    access_edit = client.get("/objects/empty-detail-panels?edit=access")

    assert detail.status_code == 200
    assert "No network data recorded." in detail.text
    assert "No access data recorded." in detail.text
    detail_document = unescape(detail.text)
    assert re.search(
        r'href="/objects/empty-detail-panels\?view=catalog&q=&kind=&edit=network"'
        r"[^>]*>Add</a>",
        detail_document,
    )
    assert re.search(
        r'href="/objects/empty-detail-panels\?view=catalog&q=&kind=&edit=access"'
        r"[^>]*>Add</a>",
        detail_document,
    )
    assert "/static/detail.js" in network_edit.text
    assert 'data-row-list="network-endpoints"' in network_edit.text
    assert 'data-add-row="network-endpoints"' in network_edit.text
    assert "Add endpoint" in network_edit.text
    assert 'name="endpoint_type" data-required-when-row-filled' in network_edit.text
    assert '<span class="required-marker" aria-hidden="true">*</span>' in network_edit.text
    assert '<span class="visually-hidden">Required</span>' in network_edit.text
    assert 'data-row-list="access-methods"' in access_edit.text
    assert 'data-add-row="access-methods"' in access_edit.text
    assert "Add access method" in access_edit.text
    assert (
        'href="/objects/empty-detail-panels?view=catalog&q=&kind=">Cancel</a>'
        in unescape(access_edit.text)
    )


def test_first_endpoint_and_access_rows_persist_from_empty_panels(
    client: TestClient,
    session_factory,
) -> None:
    object_id = "first-detail-rows"
    with session_factory() as session:
        upsert_object(
            session,
            CatalogObjectIn(
                id=object_id,
                kind="service",
                label="First Detail Rows",
                status="active",
                data={"schema_version": 1},
            ),
        )

    network_response = client.post(
        f"/objects/{object_id}/network",
        data={
            "endpoint_type": "REST API",
            "endpoint_url": "https://first-detail-rows.example/api",
            "endpoint_port": "",
        },
        follow_redirects=False,
    )
    access_response = client.post(
        f"/objects/{object_id}/access",
        data={
            "method_ref": f"service:{object_id}",
            "method_index": "0",
            "method_type": "admin_web",
            "method_endpoint": "https://first-detail-rows.example",
            "method_auth_mode": "",
        },
        follow_redirects=False,
    )

    assert network_response.status_code == 303
    assert access_response.status_code == 303
    with session_factory() as session:
        updated = get_object(session, object_id)
    assert updated is not None
    assert updated.data["endpoints"] == [
        {
            "type": "REST API",
            "url": "https://first-detail-rows.example/api",
        }
    ]
    assert len(updated.data["access_methods"]) == 1
    assert updated.data["access_methods"][0]["type"] == "admin_web"
    assert (
        updated.data["access_methods"][0]["endpoint"]
        == "https://first-detail-rows.example"
    )
    assert "auth_mode" not in updated.data["access_methods"][0]

    detail = client.get(f"/objects/{object_id}")
    detail_document = unescape(detail.text)
    assert "https://first-detail-rows.example/api" in detail.text
    assert "https://first-detail-rows.example" in detail.text
    assert re.search(
        rf'href="/objects/{object_id}\?view=catalog&q=&kind=&edit=network"'
        rf"[^>]*>Edit</a>",
        detail_document,
    )
    assert re.search(
        rf'href="/objects/{object_id}\?view=catalog&q=&kind=&edit=access"'
        rf"[^>]*>Edit</a>",
        detail_document,
    )


def test_network_address_edit_preserves_unrelated_network_fields(
    client: TestClient,
    session_factory,
) -> None:
    object_id = "preserve-network-fields"
    with session_factory() as session:
        upsert_object(
            session,
            CatalogObjectIn(
                id=object_id,
                kind="system",
                label="Preserve Network Fields",
                status="active",
                data={
                    "schema_version": 1,
                    "network": {
                        "addresses": [{"ip": "192.0.2.10", "scope": "test"}],
                        "dns": ["192.0.2.53"],
                    },
                },
            ),
        )

    response = client.post(
        f"/objects/{object_id}/network",
        data={
            "address_ip": "",
            "address_interface": "",
            "address_scope": "",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    with session_factory() as session:
        updated = get_object(session, object_id)
    assert updated is not None
    assert updated.data["network"]["dns"] == ["192.0.2.53"]
    assert "addresses" not in updated.data["network"]


def test_access_edit_preserves_existing_rows_and_appends_next_row(
    client: TestClient,
    session_factory,
) -> None:
    object_id = "multi-access-rows"
    object_ref = f"service:{object_id}"
    endpoints = [
        "ssh://multi-access.example:22",
        "https://multi-access.example",
        "https://multi-access.example/api",
    ]
    with session_factory() as session:
        upsert_object(
            session,
            CatalogObjectIn(
                id=object_id,
                kind="service",
                label="Multi Access Rows",
                status="active",
                data={
                    "schema_version": 1,
                    "access_methods": [
                        {
                            "type": "ssh",
                            "endpoint": endpoints[0],
                            "auth_mode": "key",
                        },
                        {
                            "type": "admin_web",
                            "endpoint": endpoints[1],
                            "auth_mode": "session",
                        },
                    ],
                },
            ),
        )

    response = client.post(
        f"/objects/{object_id}/access",
        data={
            "method_ref": [object_ref, object_ref, object_ref],
            "method_index": ["0", "1", "2"],
            "method_type": ["ssh", "admin_web", "admin_api"],
            "method_endpoint": endpoints,
            "method_auth_mode": ["key-only", "session", "token"],
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    with session_factory() as session:
        updated = get_object(session, object_id)
    assert updated is not None
    assert [
        (method["type"], method["endpoint"], method.get("auth_mode"))
        for method in updated.data["access_methods"]
    ] == [
        ("ssh", endpoints[0], "key-only"),
        ("admin_web", endpoints[1], "session"),
        ("admin_api", endpoints[2], "token"),
    ]


def test_access_edit_rejects_out_of_range_index_without_mutation(
    client: TestClient,
    session_factory,
) -> None:
    object_id = "invalid-access-index"
    object_ref = f"service:{object_id}"
    original_method = {
        "type": "admin_web",
        "endpoint": "https://invalid-access-index.example",
        "auth_mode": "session",
    }
    with session_factory() as session:
        upsert_object(
            session,
            CatalogObjectIn(
                id=object_id,
                kind="service",
                label="Invalid Access Index",
                status="active",
                data={
                    "schema_version": 1,
                    "access_methods": [original_method],
                },
            ),
        )

    response = client.post(
        f"/objects/{object_id}/access",
        data={
            "method_ref": object_ref,
            "method_index": "5",
            "method_type": "ssh",
            "method_endpoint": "ssh://must-not-persist.example",
            "method_auth_mode": "key",
        },
        follow_redirects=False,
    )

    assert response.status_code == 422
    assert "Access row 1 is invalid." in response.text
    assert "ssh://must-not-persist.example" in response.text
    with session_factory() as session:
        unchanged = get_object(session, object_id)
    assert unchanged is not None
    assert unchanged.data["access_methods"] == [original_method]


@pytest.mark.parametrize(
    ("path", "data", "message", "preserved_value"),
    [
        (
            "/objects/invalid-first-rows/network",
            {
                "endpoint_type": "",
                "endpoint_url": "https://preserved.example",
                "endpoint_port": "",
            },
            "Endpoint row 1: Type is required.",
            "https://preserved.example",
        ),
        (
            "/objects/invalid-first-rows/access",
            {
                "method_ref": "service:invalid-first-rows",
                "method_index": "0",
                "method_type": "",
                "method_endpoint": "ssh://preserved.example",
                "method_auth_mode": "key",
            },
            "Access row 1: Type is required.",
            "ssh://preserved.example",
        ),
        (
            "/objects/invalid-first-rows/network",
            {
                "endpoint_type": "REST API",
                "endpoint_url": "https://preserved.example",
                "endpoint_port": "70000",
            },
            "Endpoint row 1: Port must be an integer from 1 to 65535.",
            "70000",
        ),
    ],
)
def test_first_row_validation_preserves_submitted_values(
    client: TestClient,
    session_factory,
    path: str,
    data: dict[str, str],
    message: str,
    preserved_value: str,
) -> None:
    with session_factory() as session:
        upsert_object(
            session,
            CatalogObjectIn(
                id="invalid-first-rows",
                kind="service",
                label="Invalid First Rows",
                status="active",
                data={"schema_version": 1},
            ),
        )

    response = client.post(path, data=data, follow_redirects=False)

    assert response.status_code == 422
    assert message in response.text
    assert preserved_value in response.text
    assert 'role="alert"' in response.text
    with session_factory() as session:
        unchanged = get_object(session, "invalid-first-rows")
    assert unchanged is not None
    assert "endpoints" not in unchanged.data
    assert "access_methods" not in unchanged.data


def test_invalid_first_address_row_is_rejected_without_mutation(
    client: TestClient,
    session_factory,
) -> None:
    object_id = "invalid-first-address"
    with session_factory() as session:
        upsert_object(
            session,
            CatalogObjectIn(
                id=object_id,
                kind="system",
                label="Invalid First Address",
                status="active",
                data={"schema_version": 1},
            ),
        )

    response = client.post(
        f"/objects/{object_id}/network",
        data={
            "address_ip": "not-an-ip",
            "address_interface": "eth0",
            "address_scope": "lan",
        },
        follow_redirects=False,
    )

    assert response.status_code == 422
    assert "Address row 1: IP must be a valid IPv4 or IPv6 address." in response.text
    assert "not-an-ip" in response.text
    with session_factory() as session:
        unchanged = get_object(session, object_id)
    assert unchanged is not None
    assert "network" not in unchanged.data


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
    assert '<select name="endpoint_type" data-required-when-row-filled>' in edit_response.text
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
    assert (
        "Endpoint row 1: Type must be one of: Web, REST API, MCP, HEC, SSH."
        in invalid_response.text
    )


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
    detail_content = integrated_detail_html(detail_response.text)
    service_info_index = detail_content.index("Service information")
    network_index = detail_content.index("Network")
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


def test_service_components_detail_topology_editor_localization_and_noop(
    client: TestClient,
    session_factory,
) -> None:
    object_id = "service-component-ui"
    with session_factory() as session:
        upsert_object(
            session,
            CatalogObjectIn(
                id=object_id,
                kind="service",
                label="Component UI service",
                status="active",
                summary="Service-local structure.",
                data={
                    "schema_version": 1,
                    "placement": {
                        "state": "unassigned",
                        "reason": "UI component test has no placement parent.",
                    },
                    "components": {
                        "items": [
                            {
                                "id": "database",
                                "name": "Embedded database",
                                "role": "database",
                                "description": "Stores local records.",
                            },
                            {
                                "id": "api",
                                "name": "Public API",
                                "role": "api",
                                "description": "Handles HTTP requests.",
                            },
                        ],
                        "dependencies": [
                            {
                                "component_id": "api",
                                "depends_on": "database",
                                "description": "Reads and writes records.",
                            }
                        ],
                    },
                },
            ),
        )

    detail = client.get(f"/objects/{object_id}")
    assert detail.status_code == 200
    assert "Internal service components" in detail.text
    assert "Embedded database" in detail.text
    assert "Public API" in detail.text
    assert "depends on" in detail.text
    assert "Cycles are allowed" in detail.text

    german = client.get(f"/objects/{object_id}?lang=de")
    assert german.status_code == 200
    assert "Interne Service-Komponenten" in german.text
    assert "hängt ab von" in german.text

    topology = client.get(f"/?lang=en&view=topology&q={object_id}&kind=service")
    assert topology.status_code == 200
    assert 'class="topology-components"' in topology.text
    assert "Internal structure (2 components)" in topology.text
    assert "Public API" in topology.text
    assert "Embedded database" in topology.text
    assert "service:service-component-ui" in topology.text

    editor = client.get(f"/objects/{object_id}?edit=components")
    assert editor.status_code == 200
    assert 'name="component_id"' in editor.text
    assert 'name="component_role"' in editor.text
    assert 'name="depends_on"' in editor.text
    assert "Remove component and incident dependencies" in editor.text

    added = client.post(
        f"/objects/{object_id}/components",
        data={
            "component_id": "worker",
            "component_name": "Async worker",
            "component_role": "worker",
            "component_description": "Processes bounded background jobs.",
        },
        follow_redirects=False,
    )
    assert added.status_code == 303
    dependency = client.post(
        f"/objects/{object_id}/component-dependencies",
        data={
            "component_id": "worker",
            "depends_on": "database",
            "dependency_description": "Stores job results.",
        },
        follow_redirects=False,
    )
    assert dependency.status_code == 303

    with session_factory() as session:
        after_change = get_object(session, object_id)
        audits_after_change = list(
            session.scalars(
                select(AuditEvent).where(
                    AuditEvent.object_id == object_id,
                    AuditEvent.action == "update",
                )
            )
        )
    assert after_change is not None
    assert [
        component["id"]
        for component in after_change.data["components"]["items"]
    ] == ["api", "database", "worker"]
    assert after_change.data["components"]["dependencies"][-1] == {
        "component_id": "worker",
        "depends_on": "database",
        "description": "Stores job results.",
    }

    repeated = client.post(
        f"/objects/{object_id}/component-dependencies",
        data={
            "component_id": "worker",
            "depends_on": "database",
            "dependency_description": " Stores job results. ",
        },
        follow_redirects=False,
    )
    assert repeated.status_code == 303
    with session_factory() as session:
        after_noop = get_object(session, object_id)
        audits_after_noop = list(
            session.scalars(
                select(AuditEvent).where(
                    AuditEvent.object_id == object_id,
                    AuditEvent.action == "update",
                )
            )
        )
    assert after_noop is not None
    assert after_noop.revision == after_change.revision
    assert [event.id for event in audits_after_noop] == [
        event.id for event in audits_after_change
    ]

    leaked = "postgresql://operator:do-not-echo@db.internal/catalog"
    rejected = client.post(
        f"/objects/{object_id}/components",
        data={
            "component_id": "bad",
            "component_name": "Bad component",
            "component_role": "database",
            "component_description": leaked,
        },
    )
    assert rejected.status_code == 422
    assert leaked not in rejected.text
    assert "do-not-echo" not in rejected.text


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
    if kind == "network":
        data["network"]["category"] = "segment"
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
    assert '<select name="endpoint_type" data-required-when-row-filled>' in edit_response.text
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
