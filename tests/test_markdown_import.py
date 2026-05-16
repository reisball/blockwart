from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from blockwart.db.base import Base
from blockwart.db.session import build_engine
from blockwart.models import CatalogObject
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services.catalog import upsert_object
from blockwart.services.markdown_import import build_tools_import_plan, import_tools_markdown


def _session() -> Session:
    engine = build_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    return session_factory()


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
    assert plan.credential_reference_count == 1
    system = plan.payload["objects"][0]
    assert system["id"] == "demo-box"
    assert system["kind"] == "system"
    assert system["data"]["network"]["addresses"][0]["ip"] == "192.168.50.200"
    assert {item["port"] for item in system["data"]["ports"]} == {22, 8080}
    assert system["data"]["credential_references"] == [
        "credential_reference:demo-box-access-reference"
    ]


def test_import_tools_markdown_writes_valid_objects(tmp_path: Path) -> None:
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

    with _session() as session:
        result = import_tools_markdown(session, tools_path, references_root=tmp_path)
        rows = session.scalars(select(CatalogObject)).all()

    assert result.objects_imported == 1
    assert {row.id for row in rows} == {"no-auth-api"}
    assert rows[0].kind == "system"


def test_import_tools_markdown_merges_canonical_existing_objects(tmp_path: Path) -> None:
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

    with _session() as session:
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

    assert result.objects_imported == 2
    assert row is not None
    assert row.label == "Fabrik"
    assert "related_services" in row.data_json
    assert "workspace_markdown_import" in row.data_json
