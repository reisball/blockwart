from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sysconfig
import time
from datetime import timedelta
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from sqlalchemy import select
from sqlalchemy.orm import Session

from blockwart.db.session import build_engine, transaction
from blockwart.domain.attention import (
    ATTENTION_CATEGORY_VALUES,
    ATTENTION_REASON_VALUES,
    ATTENTION_SEVERITY_VALUES,
)
from blockwart.domain.auth import CatalogRole, GrantScope, PlatformRole, Role
from blockwart.models import CatalogObject
from blockwart.services.access import create_object_grant
from blockwart.services.identity import (
    create_human_principal,
    create_service_account,
    issue_browser_session,
    issue_service_token,
)
from blockwart.ui.security import AUTH_SESSION_COOKIE_NAME

BASE_URL = "http://127.0.0.1:8000"


def fetch_json(path: str, *, token: str | None = None) -> dict:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    request = Request(f"{BASE_URL}{path}", headers=headers)
    with urlopen(request, timeout=7) as response:
        return json.load(response)


def wait_until_ready() -> dict:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            payload = fetch_json("/api/health/ready")
        except URLError:
            time.sleep(0.25)
            continue
        if payload.get("ok") is True:
            return payload
        time.sleep(0.25)
    raise RuntimeError("installed package did not become ready")


def prepare_authorized_readers() -> tuple[str, str, str]:
    engine = build_engine(os.environ["BLOCKWART_DATABASE_URL"])
    try:
        with Session(engine) as session:
            with transaction(session):
                service_principal = create_service_account(
                    session,
                    login="package-smoke.service",
                    display_name="Package Smoke Service",
                    platform_role=PlatformRole.ADMIN,
                    catalog_role=CatalogRole.CATALOG_OWNER,
                )
                browser_principal = create_human_principal(
                    session,
                    login="package-smoke.browser",
                    display_name="Package Smoke Browser",
                    password="package-smoke-browser-password",
                )
                grant_candidate = create_service_account(
                    session,
                    login="package-smoke.candidate",
                    display_name="Package Smoke Grant Candidate",
                )
                for object_id in session.scalars(
                    select(CatalogObject.id).order_by(CatalogObject.id)
                ):
                    create_object_grant(
                        session,
                        principal_id=service_principal.id,
                        object_id=object_id,
                        role=Role.OWNER,
                        scope=GrantScope.SELF,
                    )
                    create_object_grant(
                        session,
                        principal_id=browser_principal.id,
                        object_id=object_id,
                        role=Role.VIEWER,
                        scope=GrantScope.SELF,
                    )
                service_token = issue_service_token(
                    session,
                    principal_id=service_principal.id,
                    name="package-smoke",
                    audience="mcp",
                )
                browser_session = issue_browser_session(
                    session,
                    principal_id=browser_principal.id,
                    ttl_seconds=3600,
                )
        return service_token.value, browser_session.value, grant_candidate.id
    finally:
        engine.dispose()


async def check_mcp(
    object_id: str,
    *,
    token: str,
    grant_candidate_id: str,
) -> str:
    scripts_dir = Path(sysconfig.get_path("scripts"))
    entrypoint = scripts_dir / "blockwart-mcp"
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env["BLOCKWART_API_BASE_URL"] = BASE_URL
    env["BLOCKWART_API_TOKEN"] = token
    params = StdioServerParameters(command=str(entrypoint), env=env)

    async with stdio_client(params) as (read_stream, write_stream):
        async with ClientSession(
            read_stream,
            write_stream,
            read_timeout_seconds=timedelta(seconds=10),
        ) as session:
            initialized = await session.initialize()
            await session.send_ping()
            listed = await session.list_tools()
            tools = {tool.name: tool for tool in listed.tools}
            assert set(tools) == {
                "blockwart.describe_schema",
                "blockwart.search",
                "blockwart.get_object_context",
                "blockwart.get_object_contexts",
                "blockwart.list_projects",
                "blockwart.list_project_chronology",
                "blockwart.append_project_chronology",
                "blockwart.list_comments",
                "blockwart.list_audit_events",
                "blockwart.add_comment",
                "blockwart.get_context",
                "blockwart.get_source_coverage",
                "blockwart.get_attention",
                "blockwart.create_child",
                "blockwart.create_root",
                "blockwart.update_object",
                "blockwart.preview_object_update",
                "blockwart.delete_object",
                "blockwart.create_relationship",
                "blockwart.delete_relationship",
                "blockwart.create_attached_device",
                "blockwart.get_device_graph",
                "blockwart.get_network_topology",
                "blockwart.get_object_access",
                "blockwart.search_principals",
                "blockwart.list_admin_principals",
                "blockwart.get_admin_principal",
                "blockwart.preview_grant_scope",
                "blockwart.create_grant",
                "blockwart.update_grant",
                "blockwart.revoke_grant",
            }
            assert all(
                tool.annotations
                and (
                    tool.annotations.readOnlyHint
                    if name
                    in {
                        "blockwart.describe_schema",
                        "blockwart.search",
                        "blockwart.get_object_context",
                        "blockwart.get_object_contexts",
                        "blockwart.list_projects",
                        "blockwart.list_project_chronology",
                        "blockwart.list_comments",
                        "blockwart.list_audit_events",
                        "blockwart.get_context",
                        "blockwart.get_source_coverage",
                        "blockwart.get_attention",
                        "blockwart.get_object_access",
                        "blockwart.search_principals",
                        "blockwart.list_admin_principals",
                        "blockwart.get_admin_principal",
                        "blockwart.preview_grant_scope",
                        "blockwart.get_device_graph",
                        "blockwart.get_network_topology",
                        "blockwart.preview_object_update",
                    }
                    else not tool.annotations.readOnlyHint
                )
                for name, tool in tools.items()
            )
            schema_contract = _tool_payload(
                await session.call_tool("blockwart.describe_schema", {})
            )
            schema_kinds = {kind["kind"]: kind for kind in schema_contract["kinds"]}
            assert set(schema_kinds) == {
                "host",
                "system",
                "network",
                "device",
                "service",
                "credential_reference",
                "runbook",
                "decision",
                "project",
            }
            project_contract = schema_kinds["project"]["project"]
            assert project_contract["category"]["values"] == [
                "implementation",
                "migration",
                "research",
                "experiment",
                "incident_review",
                "other",
            ]
            assert project_contract["project_status"]["values"] == [
                "planned",
                "active",
                "paused",
                "completed",
                "cancelled",
                "archived",
            ]
            assert project_contract["external_sources"]["live_fetch"] is False
            assert project_contract["evidence"]["contradictory_findings_allowed"] is True
            search_properties = tools["blockwart.search"].inputSchema["properties"]
            assert {
                "match",
                "operational_only",
                "project_category",
                "project_status",
                "related_object",
            } <= set(search_properties)
            assert search_properties["match"]["enum"] == [
                "normal",
                "exact_ref",
                "exact_label",
            ]
            assert search_properties["sort"]["enum"] == [
                "id",
                "label",
                "kind",
                "relevance",
                "updated_at",
            ]
            assert tools["blockwart.search"].inputSchema["properties"]["limit"] == {
                "type": "integer",
                "minimum": 1,
                "maximum": 50,
                "default": 10,
            }
            device_category = next(
                field
                for field in schema_kinds["device"]["data"]["fields"]
                if field["path"] == "device.category"
            )
            assert device_category["requirement"] == "required"
            assert device_category["enum"] == [
                "adapter",
                "antenna",
                "controller",
                "other",
                "sensor",
                "ups",
            ]
            assert {intent["tool"] for intent in schema_contract["write_intents"]} == {
                "blockwart.create_child",
                "blockwart.create_root",
                "blockwart.update_object",
                "blockwart.create_attached_device",
            }
            relationships = schema_contract["relationships"]
            relationship_types = {
                entry["relation_type"]: entry for entry in relationships["types"]
            }
            assert relationships["relation_types"] == [
                "hosts",
                "depends_on",
                "supports",
                "feeds",
                "exposes",
                "documents",
                "uses",
                "related_to",
                "attached_to",
                "uplinks_to",
            ]
            assert set(relationship_types) == set(relationships["relation_types"])
            assert relationship_types["depends_on"]["metadata"]["fields"] == []
            assert [
                field["name"]
                for field in relationship_types["uplinks_to"]["metadata"]["fields"]
            ] == [
                "source_interface",
                "target_interface_or_port",
                "link_kind",
                "primary",
                "note",
                "mode",
            ]
            assert "mode" not in {
                field["name"]
                for field in relationship_types["attached_to"]["metadata"]["fields"]
            }
            rejected_relationship = await session.call_tool(
                "blockwart.create_relationship",
                {
                    "object_id": "n8n-web-ui",
                    "if_match": '"rev-1"',
                    "from_ref": "service:n8n-web-ui",
                    "relation_type": "depends_on",
                    "to_ref": "service:other",
                    "metadata": {"link_kind": "ethernet"},
                },
            )
            assert rejected_relationship.isError
            rejection = json.loads(rejected_relationship.content[0].text)["error"]
            assert rejection["code"] == "invalid_arguments"
            assert [detail["path"] for detail in rejection["details"]] == [
                "metadata.link_kind"
            ]
            admin_first_page = await session.call_tool(
                "blockwart.list_admin_principals",
                {"query": "package-smoke", "limit": 1},
            )
            admin_first_payload = _tool_payload(admin_first_page)
            admin_cursor = admin_first_payload["next_cursor"]
            assert isinstance(admin_cursor, str) and admin_cursor
            admin_second_page = await session.call_tool(
                "blockwart.list_admin_principals",
                {
                    "query": "package-smoke",
                    "limit": 1,
                    "cursor": admin_cursor,
                },
            )
            admin_second_payload = _tool_payload(admin_second_page)
            assert {
                item["id"] for item in admin_first_payload["items"]
            }.isdisjoint(item["id"] for item in admin_second_payload["items"])
            read_results = [
                await session.call_tool("blockwart.search", {"limit": 1}),
                await session.call_tool(
                    "blockwart.get_object_context",
                    {"object_id": object_id},
                ),
                await session.call_tool(
                    "blockwart.get_object_contexts",
                    {"object_ids": [object_id]},
                ),
                await session.call_tool("blockwart.get_context", {"limit": 1}),
                await session.call_tool("blockwart.get_source_coverage", {"limit": 1}),
                await session.call_tool(
                    "blockwart.get_attention",
                    {"limit": 1, "include_total": True},
                ),
                admin_first_page,
                admin_second_page,
                await session.call_tool(
                    "blockwart.get_admin_principal",
                    {"principal_id": grant_candidate_id},
                ),
            ]
            assert all(not result.isError for result in read_results)
            # The installed wrapper must project the same closed attention
            # vocabulary the application resolver owns, not a wrapper-local copy.
            attention_payload = _tool_payload(read_results[5])
            assert attention_payload["sort"] == "priority"
            assert set(attention_payload["summary"]["signals"]) == set(
                ATTENTION_CATEGORY_VALUES
            )
            assert set(attention_payload["summary"]["by_reason"]) == set(
                ATTENTION_REASON_VALUES
            )
            assert set(attention_payload["summary"]["by_severity"]) == set(
                ATTENTION_SEVERITY_VALUES
            )
            assert attention_payload["summary"]["coverage_snapshot_state"] == (
                "not_collected"
            )
            batch_payload = _tool_payload(read_results[2])
            assert batch_payload["count"] == 1
            assert batch_payload["objects"][0]["id"] == object_id
            standalone_project = await session.call_tool(
                "blockwart.create_root",
                {
                    "idempotency_key": "package-smoke-project-0001",
                    "object": {
                        "id": "package-smoke-project",
                        "kind": "project",
                        "label": "Package Smoke Project",
                        "data": {
                            "schema_version": 1,
                            "category": "implementation",
                            "project_status": "planned",
                            "objective": "Prove the installed standalone Project path.",
                        },
                    },
                },
            )
            standalone_payload = _tool_payload(standalone_project)
            assert standalone_payload["catalog_object"]["parent_path"] == []
            project_entry = await session.call_tool(
                "blockwart.append_project_chronology",
                {
                    "object_id": "package-smoke-project",
                    "kind": "intent",
                    "body": "Record the installed-package proof intent.",
                    "idempotency_key": "package-smoke-project-entry-0001",
                },
            )
            assert _tool_payload(project_entry)["entry"]["kind"] == "intent"
            project_chronology = await session.call_tool(
                "blockwart.list_project_chronology",
                {"object_id": "package-smoke-project", "include_total": True},
            )
            assert _tool_payload(project_chronology)["total"] == 1
            project_overview = await session.call_tool(
                "blockwart.list_projects",
                {"project_status": "planned", "include_total": True},
            )
            assert any(
                item["id"] == "package-smoke-project"
                for item in _tool_payload(project_overview)["items"]
            )
            comment_created = await session.call_tool(
                "blockwart.add_comment",
                {
                    "object_id": object_id,
                    "body": "**Package smoke** comment",
                    "idempotency_key": "package-smoke-comment-0001",
                },
            )
            comment_payload = _tool_payload(comment_created)
            assert comment_payload["comment"]["format"] == "markdown"
            assert comment_payload["comment"]["origin"] == "mcp"
            comments = await session.call_tool(
                "blockwart.list_comments",
                {"object_id": object_id, "limit": 5},
            )
            assert _tool_payload(comments)["items"] == [comment_payload["comment"]]
            audits = await session.call_tool(
                "blockwart.list_audit_events",
                {"object_id": object_id, "limit": 5, "include_total": True},
            )
            audit_payload = _tool_payload(audits)
            assert audit_payload["direction"] == "desc"
            assert audit_payload["total"] >= 1
            assert comment_payload["comment"]["body"] not in json.dumps(audit_payload)
            access = await session.call_tool(
                "blockwart.get_object_access",
                {"object_id": object_id},
            )
            access_payload = _tool_payload(access)
            principal_search = await session.call_tool(
                "blockwart.search_principals",
                {
                    "object_id": object_id,
                    "query": "package-smoke.candidate",
                    "limit": 3,
                },
            )
            principal_search_payload = _tool_payload(principal_search)
            assert {
                principal["id"]
                for principal in principal_search_payload["items"]
            } == {grant_candidate_id}
            preview = await session.call_tool(
                "blockwart.preview_grant_scope",
                {"object_id": object_id, "scope": "self"},
            )
            preview_payload = _tool_payload(preview)
            assert [item["id"] for item in preview_payload["affected_objects"]] == [
                object_id
            ]
            grant_created = await session.call_tool(
                "blockwart.create_grant",
                {
                    "object_id": object_id,
                    "principal_id": grant_candidate_id,
                    "role": "viewer",
                    "scope": "self",
                    "if_match": access_payload["etag"],
                },
            )
            grant_created_payload = _tool_payload(grant_created)
            grant_updated = await session.call_tool(
                "blockwart.update_grant",
                {
                    "object_id": object_id,
                    "grant_id": grant_created_payload["grant"]["id"],
                    "role": "editor",
                    "scope": "self",
                    "if_match": grant_created_payload["etag"],
                },
            )
            grant_updated_payload = _tool_payload(grant_updated)
            grant_revoked = await session.call_tool(
                "blockwart.revoke_grant",
                {
                    "object_id": object_id,
                    "grant_id": grant_created_payload["grant"]["id"],
                    "if_match": grant_updated_payload["etag"],
                },
            )
            assert not grant_revoked.isError
            child_create_args = {
                "parent_id": "fabrik",
                "idempotency_key": "package-smoke-create-0001",
                "object": {
                    "id": "package-smoke-child",
                    "kind": "service",
                    "label": "Package Smoke Child",
                    "status": "active",
                    "data": {"schema_version": 1},
                },
            }
            created = await session.call_tool("blockwart.create_child", child_create_args)
            created_payload = _tool_payload(created)
            assert created_payload["parent_ref"] == "system:fabrik"
            assert created_payload["relationship"] == {
                "from_ref": "system:fabrik",
                "relation_type": "hosts",
                "to_ref": "service:package-smoke-child",
                "metadata": {},
            }
            assert created_payload["owner_assignment"] == {
                "principal": "authenticated_caller",
                "role": "owner",
                "scope": "self",
            }
            assert created_payload["revision"] == (
                created_payload["catalog_object"]["revision"]
            )
            assert created_payload["etag"] == f'"rev-{created_payload["revision"]}"'
            assert created_payload["changed"] is True
            assert created_payload["replayed"] is False
            created_replay = await session.call_tool(
                "blockwart.create_child",
                child_create_args,
            )
            assert _tool_payload(created_replay) == {
                **created_payload,
                "replayed": True,
            }
            created_etag = str(created_payload["etag"])
            relationship_args = {
                "object_id": "package-smoke-child",
                "if_match": created_etag,
                "from_ref": "service:package-smoke-child",
                "relation_type": "depends_on",
                "to_ref": "service:n8n-web-ui",
            }
            relationship_created = await session.call_tool(
                "blockwart.create_relationship",
                relationship_args,
            )
            relationship_payload = _tool_payload(relationship_created)
            relationship_args["if_match"] = str(relationship_payload["etag"])
            relationship_deleted = await session.call_tool(
                "blockwart.delete_relationship",
                relationship_args,
            )
            relationship_deleted_payload = _tool_payload(relationship_deleted)
            update_args = {
                "object_id": "package-smoke-child",
                "if_match": str(relationship_deleted_payload["etag"]),
                "object": {
                    "id": "package-smoke-child",
                    "kind": "service",
                    "label": "Package Smoke Child Updated",
                    "status": "active",
                    "data": {"schema_version": 1},
                },
            }
            previewed = await session.call_tool(
                "blockwart.preview_object_update",
                update_args,
            )
            previewed_payload = _tool_payload(previewed)
            assert previewed_payload["changed"] is True
            assert previewed_payload["base_etag"] == update_args["if_match"]
            assert previewed_payload["diff"]
            assert previewed_payload["preview_digest"].startswith("sha256:")
            updated = await session.call_tool("blockwart.update_object", update_args)
            updated_payload = _tool_payload(updated)
            assert updated_payload["etag"] == previewed_payload["expected_result_etag"]
            placement_deleted = await session.call_tool(
                "blockwart.delete_relationship",
                {
                    "object_id": "package-smoke-child",
                    "if_match": str(updated_payload["etag"]),
                    "from_ref": "system:fabrik",
                    "relation_type": "hosts",
                    "to_ref": "service:package-smoke-child",
                },
            )
            placement_deleted_payload = _tool_payload(placement_deleted)
            deleted = await session.call_tool(
                "blockwart.delete_object",
                {
                    "object_id": "package-smoke-child",
                    "if_match": str(placement_deleted_payload["etag"]),
                },
            )
            assert not deleted.isError
            attached_device_args = {
                "parent_id": "fabrik",
                "idempotency_key": "package-smoke-device-0001",
                "device": {
                    "id": "package-smoke-device",
                    "kind": "device",
                    "label": "Package Smoke Device",
                    "status": "active",
                    "data": {
                        "schema_version": 1,
                        "device": {"category": "sensor"},
                    },
                },
                "metadata": {"link_kind": "zigbee", "primary": True},
            }
            attached_device = await session.call_tool(
                "blockwart.create_attached_device",
                attached_device_args,
            )
            attached_device_payload = _tool_payload(attached_device)
            assert attached_device_payload["parent_ref"] == "system:fabrik"
            assert attached_device_payload["relationship"] == {
                "from_ref": "device:package-smoke-device",
                "relation_type": "attached_to",
                "to_ref": "system:fabrik",
                "metadata": {"link_kind": "zigbee", "primary": True},
            }
            assert attached_device_payload["owner_assignment"] == {
                "principal": "authenticated_caller",
                "role": "owner",
                "scope": "self",
            }
            assert attached_device_payload["revision"] == (
                attached_device_payload["catalog_object"]["revision"]
            )
            assert attached_device_payload["etag"] == (
                f'"rev-{attached_device_payload["revision"]}"'
            )
            assert attached_device_payload["changed"] is True
            assert attached_device_payload["replayed"] is False
            attached_device_replay = await session.call_tool(
                "blockwart.create_attached_device",
                attached_device_args,
            )
            assert _tool_payload(attached_device_replay) == {
                **attached_device_payload,
                "replayed": True,
            }
            device_graph = await session.call_tool(
                "blockwart.get_device_graph",
                {"object_id": "package-smoke-device"},
            )
            device_graph_payload = _tool_payload(device_graph)
            assert device_graph_payload["object_ref"] == "device:package-smoke-device"
            assert device_graph_payload["edges"] == [
                {
                    "from_ref": "device:package-smoke-device",
                    "relation_type": "attached_to",
                    "to_ref": "system:fabrik",
                    "metadata": {"link_kind": "zigbee", "primary": True},
                }
            ]
            network_topology = await session.call_tool(
                "blockwart.get_network_topology",
                {"object_id": "package-smoke-device"},
            )
            network_topology_payload = _tool_payload(network_topology)
            assert network_topology_payload["object_ref"] == (
                "device:package-smoke-device"
            )
            assert network_topology_payload["status"] == "unconnected"
            assert network_topology_payload["paths"] == []
            device_detached = await session.call_tool(
                "blockwart.delete_relationship",
                {
                    "object_id": "package-smoke-device",
                    "if_match": str(attached_device_payload["etag"]),
                    "from_ref": "device:package-smoke-device",
                    "relation_type": "attached_to",
                    "to_ref": "system:fabrik",
                },
            )
            device_detached_payload = _tool_payload(device_detached)
            device_deleted = await session.call_tool(
                "blockwart.delete_object",
                {
                    "object_id": "package-smoke-device",
                    "if_match": str(device_detached_payload["etag"]),
                },
            )
            assert not device_deleted.isError
            return str(initialized.protocolVersion)


def _tool_payload(result) -> dict:
    assert not result.isError
    content = result.content[0]
    return json.loads(content.text)


def main() -> None:
    readiness = wait_until_ready()
    api_token, browser_session, grant_candidate_id = prepare_authorized_readers()
    index_request = Request(
        f"{BASE_URL}/",
        headers={
            "Cookie": f"{AUTH_SESSION_COOKIE_NAME}={browser_session}",
        },
    )
    with urlopen(index_request, timeout=7) as response:
        index = response.read().decode()
    with urlopen(f"{BASE_URL}/static/app.css", timeout=7) as response:
        static_content_type = response.headers.get_content_type()
    openapi = fetch_json("/openapi.json")
    mcp_entrypoint = Path(sysconfig.get_path("scripts")) / "blockwart-mcp"
    wrapper_metadata = json.loads(
        subprocess.check_output([str(mcp_entrypoint), "--metadata"], text=True)
    )
    api_contract_metadata = fetch_json("/api/v1/mcp-contract", token=api_token)
    search = fetch_json("/api/agent/search?limit=1", token=api_token)
    service = fetch_json(
        "/api/agent/objects/n8n-web-ui",
        token=api_token,
    )["objects"][0]

    assert readiness["revision"] == "20260818_0018"
    assert "Blockwart" in index
    assert static_content_type == "text/css"
    assert not any(
        path.startswith(("/admin", "/objects", "/settings"))
        for path in openapi["paths"]
    )
    assert search["count"] == 1
    assert service["endpoints"]
    assert wrapper_metadata == api_contract_metadata
    assert {
        "id",
        "type",
        "protocol",
        "transport",
        "exposure",
    }.issubset(service["endpoints"][0])
    protocol = asyncio.run(
        check_mcp(
            search["results"][0]["id"],
            token=api_token,
            grant_candidate_id=grant_candidate_id,
        )
    )
    print(
        "installed_package=ok "
        f"cwd={Path.cwd()} revision={readiness['revision']} "
        f"openapi_paths={len(openapi['paths'])} mcp_protocol={protocol} mcp_calls=38 "
        "mcp_contract=compatible"
    )


if __name__ == "__main__":
    main()
