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
from blockwart.domain.auth import GrantScope, Role
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


def prepare_authorized_readers() -> tuple[str, str]:
    engine = build_engine(os.environ["BLOCKWART_DATABASE_URL"])
    try:
        with Session(engine) as session:
            with transaction(session):
                service_principal = create_service_account(
                    session,
                    login="package-smoke.service",
                    display_name="Package Smoke Service",
                )
                browser_principal = create_human_principal(
                    session,
                    login="package-smoke.browser",
                    display_name="Package Smoke Browser",
                    password="package-smoke-browser-password",
                )
                for object_id in session.scalars(
                    select(CatalogObject.id).order_by(CatalogObject.id)
                ):
                    for principal_id in (
                        service_principal.id,
                        browser_principal.id,
                    ):
                        create_object_grant(
                            session,
                            principal_id=principal_id,
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
        return service_token.value, browser_session.value
    finally:
        engine.dispose()


async def check_mcp(object_id: str, *, token: str) -> str:
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
            }
            assert all(
                tool.annotations
                and tool.annotations.readOnlyHint
                and not tool.annotations.destructiveHint
                for tool in tools.values()
            )
            results = [
                await session.call_tool("blockwart.search", {"limit": 1}),
                await session.call_tool(
                    "blockwart.get_object_context",
                    {"object_id": object_id},
                ),
                await session.call_tool("blockwart.get_context", {"limit": 1}),
            ]
            assert all(not result.isError for result in results)
            return str(initialized.protocolVersion)


def main() -> None:
    readiness = wait_until_ready()
    api_token, browser_session = prepare_authorized_readers()
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

    assert readiness["revision"] == "20260730_0009"
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
        )
    )
    print(
        "installed_package=ok "
        f"cwd={Path.cwd()} revision={readiness['revision']} "
        f"openapi_paths={len(openapi['paths'])} mcp_protocol={protocol} mcp_calls=3"
    )


if __name__ == "__main__":
    main()
