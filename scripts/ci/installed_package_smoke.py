from __future__ import annotations

import asyncio
import json
import os
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
from blockwart.domain.auth import GrantScope, PlatformRole, Role
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
                "blockwart.search",
                "blockwart.get_object_context",
                "blockwart.get_context",
                "blockwart.create_child",
                "blockwart.update_object",
                "blockwart.delete_object",
                "blockwart.create_relationship",
                "blockwart.delete_relationship",
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
                        "blockwart.search",
                        "blockwart.get_object_context",
                        "blockwart.get_context",
                        "blockwart.get_object_access",
                        "blockwart.search_principals",
                        "blockwart.list_admin_principals",
                        "blockwart.get_admin_principal",
                        "blockwart.preview_grant_scope",
                    }
                    else not tool.annotations.readOnlyHint
                )
                for name, tool in tools.items()
            )
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
                await session.call_tool("blockwart.get_context", {"limit": 1}),
                admin_first_page,
                admin_second_page,
                await session.call_tool(
                    "blockwart.get_admin_principal",
                    {"principal_id": grant_candidate_id},
                ),
            ]
            assert all(not result.isError for result in read_results)
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
            created = await session.call_tool(
                "blockwart.create_child",
                {
                    "parent_id": "fabrik",
                    "idempotency_key": "package-smoke-create-0001",
                    "object": {
                        "id": "package-smoke-child",
                        "kind": "service",
                        "label": "Package Smoke Child",
                        "status": "active",
                        "data": {"schema_version": 1},
                    },
                },
            )
            created_payload = _tool_payload(created)
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
            updated = await session.call_tool(
                "blockwart.update_object",
                {
                    "object_id": "package-smoke-child",
                    "if_match": str(relationship_deleted_payload["etag"]),
                    "object": {
                        "id": "package-smoke-child",
                        "kind": "service",
                        "label": "Package Smoke Child Updated",
                        "status": "active",
                        "data": {"schema_version": 1},
                    },
                },
            )
            updated_payload = _tool_payload(updated)
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
    search = fetch_json("/api/agent/search?limit=1", token=api_token)
    service = fetch_json(
        "/api/agent/objects/n8n-web-ui",
        token=api_token,
    )["objects"][0]

    assert readiness["revision"] == "20260731_0012"
    assert "Blockwart" in index
    assert static_content_type == "text/css"
    assert not any(
        path.startswith(("/admin", "/objects", "/settings"))
        for path in openapi["paths"]
    )
    assert search["count"] == 1
    assert service["endpoints"]
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
        f"openapi_paths={len(openapi['paths'])} mcp_protocol={protocol} mcp_calls=18"
    )


if __name__ == "__main__":
    main()
