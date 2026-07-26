from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from blockwart.models import CatalogObject, Relationship
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services.catalog import upsert_object
from blockwart.services.markdown_import import build_tools_import_plan, import_tools_markdown


def _session(alembic_session_factory) -> Session:
    return alembic_session_factory()


def test_build_tools_import_plan_parses_infrastructure_rows(tmp_path: Path) -> None:
    tools_path = tmp_path / "TOOLS.md"
    tools_path.write_text(
        "\n".join(
            [
                "| System | Typ | IP:Port | Status | Access | Auth | Nutzung | Ref | Skill |",
                "|--------|-----|---------|--------|--------|------|---------|-----|-------|",
                (
                    "| Demo Box | CT 200 | 192.168.50.200:22 · :8080 | ✅ | "
                    "SSH(key): demo · Web | SSH key-only; Web login in Vaultwarden | "
                    "Demo service host | [Details](references/demo.md) | - |"
                ),
            ]
        ),
        encoding="utf-8",
    )

    plan = build_tools_import_plan(tools_path, references_root=tmp_path)

    assert plan.source_rows == 1
    assert plan.object_count == 2
    assert plan.credential_reference_count == 0
    system = plan.payload["objects"][0]
    service = plan.payload["objects"][1]
    assert system["id"] == "ct-200"
    assert system["kind"] == "system"
    assert (system["status"], system["lifecycle"], system["health"]) == (
        "active",
        "active",
        "unknown",
    )
    assert system["data"]["platform"] == "LXC"
    assert system["data"]["placement"]["state"] == "unassigned"
    assert system["data"]["related_services"] == ["service:ct-200_demo-box"]
    assert system["data"]["container"] == {
        "id": "ct-200",
        "type": "ct",
        "number": "200",
        "label": "CT 200",
    }
    assert service["id"] == "ct-200_demo-box"
    assert service["kind"] == "service"
    assert (service["status"], service["lifecycle"], service["health"]) == (
        "active",
        "active",
        "unknown",
    )
    assert "platform" not in service["data"]
    assert "system_id" not in service["data"]
    assert system["data"]["network"]["addresses"][0]["ip"] == "192.168.50.200"
    assert {item["port"] for item in system["data"]["ports"]} == {22}
    assert {item["port"] for item in service["data"]["endpoints"]} == {8080}
    assert "credential_references" not in system["data"]
    assert {method["type"] for method in system["data"]["access_methods"]} == {"ssh"}
    assert {method["type"] for method in service["data"]["access_methods"]} == {"web"}
    assert all(
        "credential_references" not in method
        for method in system["data"]["access_methods"] + service["data"]["access_methods"]
    )
    assert plan.payload["relationships"] == [
        {
            "from_ref": "system:ct-200",
            "relation_type": "hosts",
            "to_ref": "service:ct-200_demo-box",
        }
    ]


def test_import_tools_markdown_writes_valid_objects(
    tmp_path: Path,
    alembic_session_factory,
) -> None:
    tools_path = tmp_path / "TOOLS.md"
    tools_path.write_text(
        "\n".join(
            [
                "| System | Typ | IP:Port | Status | Access | Auth | Nutzung | Ref | Skill |",
                "|--------|-----|---------|--------|--------|------|---------|-----|-------|",
                (
                    "| No Auth API | Service | 192.168.50.201:9000 | ✅ | API | "
                    "API LAN-only/no auth | Open API | [Details](references/open.md) | - |"
                ),
            ]
        ),
        encoding="utf-8",
    )

    with _session(alembic_session_factory) as session:
        result = import_tools_markdown(session, tools_path, references_root=tmp_path)
        rows = session.scalars(select(CatalogObject)).all()

    assert result.objects_imported == 1
    assert {row.id for row in rows} == {"no-auth-api"}
    assert rows[0].kind == "service"


def test_build_tools_import_plan_sets_wsl_platform(tmp_path: Path) -> None:
    tools_path = tmp_path / "TOOLS.md"
    tools_path.write_text(
        "\n".join(
            [
                "| System | Typ | IP:Port | Status | Access | Auth | Nutzung | Ref | Skill |",
                "|--------|-----|---------|--------|--------|------|---------|-----|-------|",
                (
                    "| Demo WSL | WSL2 service | 192.168.50.210:8080 | ✅ | "
                    "Web | no auth | Demo WSL service | [Details](references/wsl.md) | - |"
                ),
            ]
        ),
        encoding="utf-8",
    )

    plan = build_tools_import_plan(tools_path, references_root=tmp_path)
    system = plan.payload["objects"][0]

    assert system["kind"] == "service"
    assert system["data"]["platform"] == "WSL"
    assert system["data"]["placement"] == {
        "state": "unassigned",
        "reason": "No canonical parent is defined by the workspace import.",
    }


def test_import_tools_markdown_creates_hosted_service_relationship(
    tmp_path: Path,
    alembic_session_factory,
) -> None:
    tools_path = tmp_path / "TOOLS.md"
    tools_path.write_text(
        "\n".join(
            [
                "| System | Typ | IP:Port | Status | Access | Auth | Nutzung | Ref | Skill |",
                "|--------|-----|---------|--------|--------|------|---------|-----|-------|",
                (
                    "| Agent Zero | CT 121 | 192.168.50.78:80 | ✅ | "
                    "SSH(key): zoe · Web | zoe key-only; Agent Zero auth configured in UI | "
                    "LAN-only Agent Zero AI framework test instance | "
                    "[Details](references/agent-zero.md) | - |"
                ),
            ]
        ),
        encoding="utf-8",
    )

    with _session(alembic_session_factory) as session:
        result = import_tools_markdown(session, tools_path, references_root=tmp_path)
        objects = {row.id: row for row in session.scalars(select(CatalogObject)).all()}
        relationships = session.scalars(select(Relationship)).all()

    assert result.objects_imported == 2
    assert result.relationships_imported == 1
    assert objects["ct-121"].kind == "system"
    assert objects["ct-121"].label == "Agent Zero"
    assert '"platform": "LXC"' in objects["ct-121"].data_json
    assert objects["ct-121_agent-zero"].kind == "service"
    assert '"platform": "LXC"' not in objects["ct-121_agent-zero"].data_json
    assert "system:ct-121" not in objects["ct-121_agent-zero"].data_json
    assert [
        {
            "from_ref": relationship.from_ref,
            "relation_type": relationship.relation_type,
            "to_ref": relationship.to_ref,
        }
        for relationship in relationships
    ] == [
        {
            "from_ref": "system:ct-121",
            "relation_type": "hosts",
            "to_ref": "service:ct-121_agent-zero",
        }
    ]


def test_import_tools_markdown_updates_previous_workspace_import_shape(
    tmp_path: Path,
    alembic_session_factory,
) -> None:
    tools_path = tmp_path / "TOOLS.md"
    tools_path.write_text(
        "\n".join(
            [
                "| System | Typ | IP:Port | Status | Access | Auth | Nutzung | Ref | Skill |",
                "|--------|-----|---------|--------|--------|------|---------|-----|-------|",
                (
                    "| Agent Zero | CT 121 | 192.168.50.78:80 | ✅ | "
                    "SSH(key): zoe · Web | zoe key-only | Agent Zero service | "
                    "[Details](references/agent-zero.md) | - |"
                ),
            ]
        ),
        encoding="utf-8",
    )

    with _session(alembic_session_factory) as session:
        session.add(
            CatalogObject(
                id="agent-zero",
                kind="service",
                label="Agent Zero",
                status="active",
                lifecycle="active",
                health="unknown",
                summary="Old import.",
                data_json=(
                    '{"schema_version":1,"source":"workspace_markdown_import",'
                    '"system_id":"system:agent-zero-lxc"}'
                ),
            )
        )
        session.flush()
        import_tools_markdown(session, tools_path, references_root=tmp_path)
        row = session.get(CatalogObject, "ct-121_agent-zero")

    assert row is not None
    assert "system:ct-121" not in row.data_json
    assert "system:agent-zero-lxc" not in row.data_json


def test_import_tools_markdown_removes_stale_workspace_host_relationship(
    tmp_path: Path,
    alembic_session_factory,
) -> None:
    tools_path = tmp_path / "TOOLS.md"
    tools_path.write_text(
        "\n".join(
            [
                "| System | Typ | IP:Port | Status | Access | Auth | Nutzung | Ref | Skill |",
                "|--------|-----|---------|--------|--------|------|---------|-----|-------|",
                (
                    "| Agent Zero | CT 121 | 192.168.50.78:80 | ✅ | "
                    "SSH(key): zoe · Web | zoe key-only | Agent Zero service | "
                    "[Details](references/agent-zero.md) | - |"
                ),
            ]
        ),
        encoding="utf-8",
    )

    with _session(alembic_session_factory) as session:
        upsert_object(
            session,
            CatalogObjectIn(
                id="agent-zero-lxc",
                kind="system",
                label="Agent Zero CT 121",
                status="active",
                summary="Old generated host.",
                data={"schema_version": 1, "source": "workspace_markdown_import"},
            ),
        )
        upsert_object(
            session,
            CatalogObjectIn(
                id="agent-zero",
                kind="service",
                label="Agent Zero",
                status="active",
                summary="Agent Zero service.",
                data={"schema_version": 1, "source": "workspace_markdown_import"},
            ),
        )
        session.add(
            Relationship(
                from_ref="system:agent-zero-lxc",
                relation_type="hosts",
                to_ref="service:agent-zero",
            )
        )
        session.commit()

        import_tools_markdown(session, tools_path, references_root=tmp_path)
        relationships = session.scalars(select(Relationship)).all()

    assert [
        (relationship.from_ref, relationship.relation_type, relationship.to_ref)
        for relationship in relationships
    ] == [("system:ct-121", "hosts", "service:ct-121_agent-zero")]


def test_import_tools_markdown_merges_canonical_existing_objects(
    tmp_path: Path,
    alembic_session_factory,
) -> None:
    tools_path = tmp_path / "TOOLS.md"
    tools_path.write_text(
        "\n".join(
            [
                "| System | Typ | IP:Port | Status | Access | Auth | Nutzung | Ref | Skill |",
                "|--------|-----|---------|--------|--------|------|---------|-----|-------|",
                (
                    "| Fabrik (Proxmox) | Host | 192.168.50.20:8006 | ✅ | "
                    "SSH(key): zoe | SSH key-only | Proxmox Host | "
                    "[Details](references/fabrik.md) | - |"
                ),
            ]
        ),
        encoding="utf-8",
    )

    with _session(alembic_session_factory) as session:
        upsert_object(
            session,
            CatalogObjectIn(
                id="fabrik-proxmox",
                kind="service",
                label="Fabrik Proxmox",
                status="active",
                data={"schema_version": 1},
            ),
        )
        upsert_object(
            session,
            CatalogObjectIn(
                id="fabrik",
                kind="system",
                label="Fabrik",
                status="active",
                summary="Existing seed object.",
                data={"schema_version": 1, "related_services": ["service:fabrik-proxmox"]},
            ),
        )
        result = import_tools_markdown(session, tools_path, references_root=tmp_path)
        row = session.get(CatalogObject, "fabrik")

    assert result.objects_imported == 1
    assert row is not None
    assert row.label == "Fabrik"
    assert "workspace_markdown_import" in row.data_json


@pytest.mark.parametrize(
    ("source_status", "expected"),
    [
        ("planned", ("inactive", "planned", "unknown")),
        ("partial", ("active", "active", "degraded")),
        ("unknown", ("active", "active", "unknown")),
        ("", ("active", "active", "unknown")),
        ("maintenance", ("inactive", "active", "maintenance")),
        ("offline", ("inactive", "active", "down")),
    ],
)
def test_markdown_import_preserves_lifecycle_and_health_semantics(
    tmp_path: Path,
    source_status: str,
    expected: tuple[str, str, str],
) -> None:
    tools_path = tmp_path / "TOOLS.md"
    tools_path.write_text(
        "\n".join(
            [
                "| System | Typ | IP:Port | Status | Access | Auth | Nutzung | Ref | Skill |",
                "|--------|-----|---------|--------|--------|------|---------|-----|-------|",
                (
                    f"| State Demo | Service | 192.168.50.210:8080 | {source_status} | "
                    "Web | no auth | State demo | - | - |"
                ),
            ]
        ),
        encoding="utf-8",
    )

    plan = build_tools_import_plan(tools_path, references_root=tmp_path)
    catalog_object = plan.payload["objects"][0]

    assert (
        catalog_object["status"],
        catalog_object["lifecycle"],
        catalog_object["health"],
    ) == expected
