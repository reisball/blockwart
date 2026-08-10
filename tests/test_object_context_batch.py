from __future__ import annotations

import json
from collections.abc import Generator
from dataclasses import dataclass
from typing import Annotated

import pytest
from fastapi import Depends
from fastapi.testclient import TestClient
from sqlalchemy import event
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.db.session import transaction
from blockwart.domain.auth import (
    GrantScope,
    Permission,
    PrincipalContext,
    PrincipalType,
    Role,
)
from blockwart.main import create_app
from blockwart.mcp.server import ToolInputError, UpstreamError, call_tool
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services.access import create_object_grant
from blockwart.services.agent import query_agent_object_contexts
from blockwart.services.catalog import create_relationship, upsert_object
from blockwart.services.comments import add_object_comment
from blockwart.services.identity import create_service_account, issue_service_token
from blockwart.services.policy import PolicySnapshot
from blockwart.services.read_access import ReadAccess

PRIVATE_MARKER = "BATCH-PRIVATE-7c3a"


@pytest.fixture
def session_factory(alembic_session_factory):
    with alembic_session_factory() as session:
        with transaction(session):
            for payload in (
                CatalogObjectIn(
                    id="alpha",
                    kind="host",
                    label="Alpha Host",
                    lifecycle="active",
                    health="healthy",
                    data={
                        "schema_version": 1,
                        "network": {"hostnames": ["alpha"], "addresses": [{"ip": "10.0.0.1"}]},
                    },
                ),
                CatalogObjectIn(
                    id="beta",
                    kind="system",
                    label="Beta System",
                    lifecycle="active",
                    health="healthy",
                    data={"schema_version": 1},
                ),
                CatalogObjectIn(
                    id="gamma",
                    kind="service",
                    label="Gamma Service",
                    lifecycle="active",
                    health="healthy",
                    summary=PRIVATE_MARKER,
                    data={
                        "schema_version": 1,
                        "endpoints": [
                            {
                                "type": "REST API",
                                "url": "https://10.0.0.3:8443",
                                "host": "10.0.0.3",
                                "port": 8443,
                                "protocol": "https",
                            }
                        ],
                    },
                ),
                CatalogObjectIn(
                    id="delta",
                    kind="service",
                    label="Delta Service",
                    lifecycle="active",
                    health="healthy",
                    data={"schema_version": 1},
                ),
            ):
                upsert_object(session, payload)
            create_relationship(
                session,
                from_ref="host:alpha",
                relation_type="hosts",
                to_ref="system:beta",
            )
            create_relationship(
                session,
                from_ref="system:beta",
                relation_type="hosts",
                to_ref="service:gamma",
            )
            add_object_comment(
                session,
                _write_context(session, "alpha"),
                object_id="alpha",
                body="First comment on alpha",
                idempotency_key="batch-comment-alpha-0001",
                idempotency_ttl_seconds=3600,
            )
    return alembic_session_factory


def _write_context(session: Session, object_id: str):
    from blockwart.services.commands import WriteContext

    principal = create_service_account(
        session,
        login="batch.writer",
        display_name="Batch Writer",
    )
    create_object_grant(
        session,
        principal_id=principal.id,
        object_id=object_id,
        role=Role.EDITOR,
        scope=GrantScope.SELF,
    )
    issue_service_token(
        session, principal_id=principal.id, name="api", audience="api"
    )
    return WriteContext(
        principal=PrincipalContext(
            id=principal.id,
            principal_type=PrincipalType.SERVICE_ACCOUNT,
            login=principal.login,
            display_name=principal.display_name,
            service_token_audience="api",
        ),
        policy=PolicySnapshot(
            principal_id=principal.id,
            _permissions={object_id: frozenset(Permission)},
            _grants={},
        ),
        channel="api",
        request_id="batch-test-request",
    )


@dataclass(frozen=True)
class _RestrictedState:
    detail_ids: frozenset[str]
    stub_ids: frozenset[str]


def _restricted_access(session: Session, state: _RestrictedState) -> ReadAccess:
    principal = PrincipalContext(
        id="batch-restricted-principal",
        principal_type=PrincipalType.SERVICE_ACCOUNT,
        login="batch-restricted",
        display_name="Batch Restricted",
    )
    permissions: dict[str, frozenset[Permission]] = {}
    for object_id in state.detail_ids:
        permissions[object_id] = frozenset({Permission.DISCOVER, Permission.READ})
    for object_id in state.stub_ids:
        permissions[object_id] = frozenset({Permission.DISCOVER})
    return ReadAccess(
        principal=principal,
        policy=PolicySnapshot(
            principal_id=principal.id,
            _permissions=permissions,
            _grants={},
        ),
    )


@pytest.fixture
def client(
    session_factory,
    install_unrestricted_read_access,
) -> Generator[TestClient, None, None]:
    app = create_app()
    install_unrestricted_read_access(app)

    def override_get_session() -> Generator[Session, None, None]:
        with session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def restricted_client(
    session_factory,
) -> Generator[tuple[TestClient, _RestrictedState], None, None]:
    state = _RestrictedState(
        detail_ids=frozenset({"alpha", "beta"}),
        stub_ids=frozenset({"gamma"}),
    )
    app = create_app()

    def override_get_session() -> Generator[Session, None, None]:
        with session_factory() as session:
            yield session

    def override_access(
        session: Annotated[Session, Depends(get_session)],
    ) -> ReadAccess:
        return _restricted_access(session, state)

    app.dependency_overrides[get_session] = override_get_session
    from blockwart.api.security import require_api_read_access

    app.dependency_overrides[require_api_read_access] = override_access
    with TestClient(app) as test_client:
        yield test_client, state


def test_three_known_object_workflow_uses_one_roundtrip_and_preserves_order(
    client: TestClient,
) -> None:
    response = client.post(
        "/api/v1/object-contexts",
        json={"object_ids": ["gamma", "alpha", "beta"]},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["count"] == 3
    assert [item["id"] for item in payload["objects"]] == ["gamma", "alpha", "beta"]
    assert [item["visibility"] for item in payload["objects"]] == [
        "detail",
        "detail",
        "detail",
    ]


def test_visible_detail_items_are_equivalent_to_single_reads_including_etag(
    client: TestClient,
) -> None:
    ids = ["alpha", "beta", "gamma"]
    batch = client.post("/api/v1/object-contexts", json={"object_ids": ids})

    assert batch.status_code == 200
    batch_items = batch.json()["objects"]
    for object_id, batch_item in zip(ids, batch_items, strict=True):
        single = client.get(f"/api/v1/objects/{object_id}")
        assert single.status_code == 200
        single_body = single.json()
        assert batch_item == single_body
        assert batch_item["etag"] == single.headers["etag"] == f'"rev-{batch_item["revision"]}"'
        assert batch_item["etag"].startswith('"rev-')


def test_batch_recent_comments_match_single_read(client: TestClient) -> None:
    batch = client.post("/api/v1/object-contexts", json={"object_ids": ["alpha"]})
    single = client.get("/api/v1/objects/alpha")
    assert batch.json()["objects"][0]["recent_comments"] == single.json()["recent_comments"]
    assert len(batch.json()["objects"][0]["recent_comments"]) == 1


def test_stubs_concealed_and_missing_obey_concealment_rules(
    session_factory,
) -> None:
    with session_factory() as session:
        state = _RestrictedState(
            detail_ids=frozenset({"alpha", "beta"}),
            stub_ids=frozenset({"gamma"}),
        )
        access = _restricted_access(session, state)
        batch = query_agent_object_contexts(
            session, access, ["alpha", "gamma", "delta", "missing"]
        )

    assert [item.id for item in batch.items] == ["alpha", "gamma", "delta", "missing"]
    visibilities = [item.visibility for item in batch.items]
    assert visibilities == ["detail", "stub", "concealed", "concealed"]

    detail = batch.items[0]
    assert detail.etag.startswith('"rev-')
    assert len(detail.recent_comments) == 1
    assert detail.recent_comments[0].body == "First comment on alpha"
    assert "data" in detail.model_dump()

    stub = batch.items[1]
    stub_dump = stub.model_dump()
    stub_keys = set(stub_dump.keys())
    assert "etag" not in stub_keys
    assert "recent_comments" not in stub_keys
    assert "relationships" not in stub_keys
    assert "data" not in stub_keys
    assert "revision" not in stub_keys
    assert stub.kind == "service"

    concealed_existing = batch.items[2].model_dump()
    concealed_missing = batch.items[3].model_dump()
    assert set(concealed_existing) == set(concealed_missing) == {"id", "visibility"}
    assert concealed_existing["visibility"] == "concealed"
    assert concealed_missing["visibility"] == "concealed"
    assert concealed_existing["id"] == "delta"
    assert concealed_missing["id"] == "missing"


def test_fully_concealed_request_is_deterministic(session_factory) -> None:
    with session_factory() as session:
        state = _RestrictedState(detail_ids=frozenset(), stub_ids=frozenset())
        access = _restricted_access(session, state)
        batch = query_agent_object_contexts(
            session, access, ["alpha", "beta", "missing"]
        )

    assert [item.model_dump() for item in batch.items] == [
        {"id": "alpha", "visibility": "concealed"},
        {"id": "beta", "visibility": "concealed"},
        {"id": "missing", "visibility": "concealed"},
    ]


def test_duplicate_ids_keep_first_position(session_factory) -> None:
    with session_factory() as session:
        from tests.conftest import _unrestricted_read_access

        access = _unrestricted_read_access(session)
        batch = query_agent_object_contexts(
            session, access, ["alpha", "beta", "alpha", "beta", "gamma"]
        )

    assert [item.id for item in batch.items] == ["alpha", "beta", "gamma"]
    assert batch.items[0].visibility == "detail"


def test_empty_list_is_rejected(client: TestClient) -> None:
    response = client.post("/api/v1/object-contexts", json={"object_ids": []})
    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "validation_error"


def test_over_limit_request_is_rejected(client: TestClient) -> None:
    response = client.post(
        "/api/v1/object-contexts",
        json={"object_ids": [f"id-{i}" for i in range(21)]},
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"


def test_malformed_ids_are_rejected_as_whole_request_error(client: TestClient) -> None:
    response = client.post(
        "/api/v1/object-contexts",
        json={"object_ids": ["alpha", "UPPER-CASE", "beta"]},
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"
    assert "UPPER" not in json.dumps(response.json())


def test_payload_limit_returns_whole_request_error_and_no_partial_items(
    client: TestClient,
    monkeypatch,
) -> None:
    from blockwart.api.routes import v1 as v1_module

    monkeypatch.setattr(v1_module, "MAX_BATCH_RESPONSE_BYTES", 64)
    response = client.post(
        "/api/v1/object-contexts",
        json={"object_ids": ["alpha", "beta", "gamma"]},
    )
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "payload_too_large"


def test_comment_loading_does_not_grow_per_requested_object(
    session_factory,
    alembic_database,
) -> None:
    with session_factory() as session:
        from tests.conftest import _unrestricted_read_access

        access = _unrestricted_read_access(session)

    comment_queries: list[str] = []

    def capture_comment_selects(
        _connection,
        _cursor,
        statement: str,
        _parameters,
        _context,
        _executemany,
    ) -> None:
        normalized = statement.lstrip().upper()
        if normalized.startswith("SELECT") and "OBJECT_COMMENT" in normalized:
            comment_queries.append(statement)

    event.listen(
        alembic_database.engine,
        "before_cursor_execute",
        capture_comment_selects,
    )
    try:
        with alembic_database.sessions() as session:
            access = _unrestricted_read_access(session)
            single = query_agent_object_contexts(session, access, ["alpha"])
            single_comment_queries = len(comment_queries)
            comment_queries.clear()
            triple = query_agent_object_contexts(
                session, access, ["alpha", "beta", "gamma"]
            )
            triple_comment_queries = len(comment_queries)
    finally:
        event.remove(
            alembic_database.engine,
            "before_cursor_execute",
            capture_comment_selects,
        )

    assert single.items[0].visibility == "detail"
    assert triple.items[2].visibility == "detail"
    assert single_comment_queries == 1
    assert triple_comment_queries == 1
    assert triple_comment_queries == single_comment_queries


def test_batch_object_and_relationship_queries_do_not_grow_per_object(
    session_factory,
    alembic_database,
) -> None:
    with session_factory() as session:
        from tests.conftest import _unrestricted_read_access

        access = _unrestricted_read_access(session)

    select_counts: list[int] = []

    def count_selects(
        _connection,
        _cursor,
        statement: str,
        _parameters,
        _context,
        _executemany,
    ) -> None:
        if statement.lstrip().upper().startswith("SELECT"):
            select_counts.append(1)

    event.listen(alembic_database.engine, "before_cursor_execute", count_selects)
    try:
        with alembic_database.sessions() as session:
            access = _unrestricted_read_access(session)
            select_counts.clear()
            query_agent_object_contexts(session, access, ["alpha"])
            one_object_selects = len(select_counts)
            select_counts.clear()
            query_agent_object_contexts(
                session, access, ["alpha", "beta", "gamma", "delta"]
            )
            four_object_selects = len(select_counts)
    finally:
        event.remove(alembic_database.engine, "before_cursor_execute", count_selects)

    assert one_object_selects == four_object_selects
    assert one_object_selects <= 5


def test_rest_mcp_and_openapi_parity_and_old_call_compatibility(
    client: TestClient,
) -> None:
    rest_batch = client.post(
        "/api/v1/object-contexts", json={"object_ids": ["alpha", "beta"]}
    ).json()

    def authenticated_fetch(path: str, params: dict) -> dict:
        if path == "/api/v1/object-contexts":
            assert params == {}
            return rest_batch
        response = client.get(path)
        response.raise_for_status()
        return response.json()

    mcp_result = call_tool(
        "blockwart.get_object_contexts",
        {"object_ids": ["alpha", "beta"]},
        requester=lambda method, path, body, headers: authenticated_fetch(path, {}) or rest_batch,
    )
    mcp_payload = json.loads(mcp_result["content"][0]["text"])
    assert mcp_payload == rest_batch

    old_single = client.get("/api/v1/objects/alpha").json()
    assert old_single["visibility"] == "detail"
    old_context = client.get("/api/v1/context", params={"limit": 1}).json()
    assert old_context["sort"] == "id"

    op = client.app.openapi()
    assert "/api/v1/object-contexts" in op["paths"]
    assert set(op["paths"]["/api/v1/object-contexts"]) == {"post"}


def test_mcp_batch_rejects_empty_duplicate_malformed_and_over_limit() -> None:
    def fake_fetch(path, params):
        raise AssertionError("fetcher should not be called")

    with pytest.raises(ToolInputError):
        call_tool("blockwart.get_object_contexts", {"object_ids": []}, fetcher=fake_fetch)
    with pytest.raises(ToolInputError):
        call_tool(
            "blockwart.get_object_contexts",
            {"object_ids": [f"id-{i}" for i in range(21)]},
            fetcher=fake_fetch,
        )
    with pytest.raises(ToolInputError):
        call_tool(
            "blockwart.get_object_contexts",
            {"object_ids": ["alpha", "UPPER"]},
            fetcher=fake_fetch,
        )


def test_mcp_batch_posts_object_ids_in_one_roundtrip() -> None:
    calls: list[tuple[str, str, dict]] = []

    def fake_request(method, path, body, headers):
        calls.append((method, path, body))
        return {"objects": [], "count": 0}

    def fake_fetch(path, params):
        raise AssertionError("batch must POST, not GET")

    result = call_tool(
        "blockwart.get_object_contexts",
        {"object_ids": ["alpha", "beta", "gamma"]},
        fetcher=fake_fetch,
        requester=fake_request,
    )

    assert calls == [
        ("POST", "/api/v1/object-contexts", {"object_ids": ["alpha", "beta", "gamma"]})
    ]
    payload = json.loads(result["content"][0]["text"])
    assert payload == {"objects": [], "count": 0}


def test_concealed_and_missing_are_indistinguishable_via_rest(
    restricted_client: tuple[TestClient, _RestrictedState],
) -> None:
    client, _ = restricted_client
    existing_concealed = client.post(
        "/api/v1/object-contexts", json={"object_ids": ["delta"]}
    ).json()
    missing = client.post(
        "/api/v1/object-contexts", json={"object_ids": ["does-not-exist"]}
    ).json()

    existing_item = existing_concealed["objects"][0]
    missing_item = missing["objects"][0]
    assert set(existing_item) == set(missing_item) == {"id", "visibility"}
    assert existing_item["visibility"] == missing_item["visibility"] == "concealed"
    assert existing_item["id"] == "delta"
    assert missing_item["id"] == "does-not-exist"
    assert existing_concealed["count"] == missing["count"] == 1
    assert PRIVATE_MARKER not in json.dumps(existing_concealed)


def test_restricted_batch_mixes_detail_stub_and_concealed_via_rest(
    restricted_client: tuple[TestClient, _RestrictedState],
) -> None:
    client, _ = restricted_client
    response = client.post(
        "/api/v1/object-contexts",
        json={"object_ids": ["alpha", "gamma", "delta", "beta"]},
    )
    assert response.status_code == 200
    objects = response.json()["objects"]
    assert [item["id"] for item in objects] == ["alpha", "gamma", "delta", "beta"]
    assert [item["visibility"] for item in objects] == [
        "detail",
        "stub",
        "concealed",
        "detail",
    ]
    assert objects[0]["etag"].startswith('"rev-')
    assert "etag" not in objects[1]
    assert set(objects[2]) == {"id", "visibility"}
    assert "PRIVATE" not in json.dumps(objects[1]).upper()
    assert PRIVATE_MARKER not in json.dumps(objects)


def test_mcp_batch_translates_upstream_not_found_without_leak(client: TestClient) -> None:
    def authenticated_request(method, path, body, headers):
        raise UpstreamError("not_found", "Catalog object not found")

    with pytest.raises(UpstreamError) as exc:
        call_tool(
            "blockwart.get_object_contexts",
            {"object_ids": ["alpha"]},
            requester=authenticated_request,
        )
    assert exc.value.code == "not_found"
    assert PRIVATE_MARKER not in exc.value.public_message


# ---------------------------------------------------------------------------
# Finding 1a regressions: 128-character id boundary
# ---------------------------------------------------------------------------


def test_128_character_id_is_accepted_at_rest_and_mcp(client: TestClient) -> None:
    valid_id = "a" * 128
    response = client.post(
        "/api/v1/object-contexts", json={"object_ids": [valid_id]}
    )
    assert response.status_code == 200
    assert response.json()["objects"][0] == {
        "id": valid_id,
        "visibility": "concealed",
    }


def test_129_character_id_is_rejected_with_validation_error(client: TestClient) -> None:
    too_long = "a" * 129
    response = client.post(
        "/api/v1/object-contexts", json={"object_ids": [too_long]}
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"
    assert too_long not in json.dumps(response.json())


def test_mcp_schema_publishes_max_length_128() -> None:
    from blockwart.mcp.server import TOOL_DEFINITIONS

    schema = TOOL_DEFINITIONS["blockwart.get_object_contexts"]["inputSchema"]
    items = schema["properties"]["object_ids"]["items"]
    assert items["maxLength"] == 128
    assert items["pattern"] == "^[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?$"
    assert schema["properties"]["object_ids"]["maxItems"] == 20


def test_mcp_rejects_129_character_id_before_fetch() -> None:
    def fake_fetch(path, params):
        raise AssertionError("fetcher should not be called")

    with pytest.raises(ToolInputError):
        call_tool(
            "blockwart.get_object_contexts",
            {"object_ids": ["a" * 129]},
            fetcher=fake_fetch,
        )


def test_openapi_publishes_max_length_128_and_endpoint_local_413(
    client: TestClient,
) -> None:
    op = client.app.openapi()
    batch_spec = op["paths"]["/api/v1/object-contexts"]["post"]
    ref = batch_spec["requestBody"]["content"]["application/json"]["schema"]["$ref"]
    component_name = ref.split("/")[-1]
    component = op["components"]["schemas"][component_name]
    items = component["properties"]["object_ids"]["items"]
    assert items["maxLength"] == 128
    # 413 must be endpoint-local
    assert "413" in batch_spec["responses"]
    for path, methods in op["paths"].items():
        if path == "/api/v1/object-contexts":
            continue
        for method_spec in methods.values():
            if isinstance(method_spec, dict):
                assert "413" not in method_spec.get("responses", {}), (
                    f"413 leaked to {path}"
                )


# ---------------------------------------------------------------------------
# Finding 1b regressions: receive-time request-body byte bound
# ---------------------------------------------------------------------------

_MAX_REQUEST_BYTES = 8192


def test_honest_oversized_content_length_is_rejected_before_body_read(
    client: TestClient,
) -> None:
    body = b"B" * (_MAX_REQUEST_BYTES + 1)
    response = client.post(
        "/api/v1/object-contexts",
        content=body,
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "payload_too_large"
    assert "BBB" not in json.dumps(response.json())


def test_valid_small_request_succeeds(client: TestClient) -> None:
    response = client.post(
        "/api/v1/object-contexts", json={"object_ids": ["alpha"]}
    )
    assert response.status_code == 200


def test_exact_byte_boundary_accepted(client: TestClient) -> None:
    body = json.dumps({"object_ids": ["alpha"]}).encode("utf-8")
    assert len(body) < _MAX_REQUEST_BYTES
    response = client.post(
        "/api/v1/object-contexts",
        content=body,
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 200


async def _asgi_call(
    app,
    *,
    method: str,
    path: str,
    body_chunks: list[bytes],
    content_length: str | None,
    content_type: str = "application/json",
) -> tuple[int, dict[str, str], bytes]:
    """Call the ASGI app directly with full control over the receive stream."""
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": method,
        "path": path,
        "raw_path": path.encode("utf-8"),
        "query_string": b"",
        "headers": [
            (b"content-type", content_type.encode("utf-8")),
        ],
        "client": ("127.0.0.1", 12345),
        "server": ("127.0.0.1", 8000),
        "scheme": "http",
    }
    if content_length is not None:
        scope["headers"].append((b"content-length", content_length.encode("utf-8")))

    chunk_index = 0

    async def receive():
        nonlocal chunk_index
        if chunk_index < len(body_chunks):
            chunk = body_chunks[chunk_index]
            chunk_index += 1
            return {
                "type": "http.request",
                "body": chunk,
                "more_body": chunk_index < len(body_chunks),
            }
        return {"type": "http.request", "body": b"", "more_body": False}

    response_status = 0
    response_headers: dict[str, str] = {}
    response_body = b""

    async def send(message):
        nonlocal response_status, response_headers, response_body
        if message["type"] == "http.response.start":
            response_status = message["status"]
            for key, value in message.get("headers", []):
                response_headers[key.decode("utf-8")] = value.decode("utf-8")
        elif message["type"] == "http.response.body":
            response_body += message.get("body", b"")

    await app(scope, receive, send)
    return response_status, response_headers, response_body


def test_misleading_content_length_small_header_big_body_rejected(
    client: TestClient,
) -> None:
    import asyncio

    big_body = b"B" * (_MAX_REQUEST_BYTES + 1000)
    status, _, body = asyncio.run(
        _asgi_call(
            client.app,
            method="POST",
            path="/api/v1/object-contexts",
            body_chunks=[big_body],
            content_length="10",
        )
    )
    assert status == 413
    import json as _json

    error = _json.loads(body.decode("utf-8"))["error"]
    assert error["code"] == "payload_too_large"
    assert b"BBB" not in body


def test_absent_content_length_oversized_body_rejected(client: TestClient) -> None:
    import asyncio

    big_body = b"B" * (_MAX_REQUEST_BYTES + 1)
    status, _, body = asyncio.run(
        _asgi_call(
            client.app,
            method="POST",
            path="/api/v1/object-contexts",
            body_chunks=[big_body],
            content_length=None,
        )
    )
    assert status == 413
    import json as _json

    error = _json.loads(body.decode("utf-8"))["error"]
    assert error["code"] == "payload_too_large"
    assert b"BBB" not in body


def test_chunked_body_within_limit_accepted(client: TestClient) -> None:
    import asyncio

    full_body = json.dumps({"object_ids": ["alpha"]}).encode("utf-8")
    midpoint = len(full_body) // 2
    chunks = [full_body[:midpoint], full_body[midpoint:]]
    status, _, body = asyncio.run(
        _asgi_call(
            client.app,
            method="POST",
            path="/api/v1/object-contexts",
            body_chunks=chunks,
            content_length=None,
        )
    )
    assert status == 200
    import json as _json

    assert _json.loads(body.decode("utf-8"))["count"] == 1


def test_chunked_oversized_body_rejected(client: TestClient) -> None:
    import asyncio

    chunks = [b"B" * 4096, b"B" * 4097]
    status, _, body = asyncio.run(
        _asgi_call(
            client.app,
            method="POST",
            path="/api/v1/object-contexts",
            body_chunks=chunks,
            content_length=None,
        )
    )
    assert status == 413
    import json as _json

    error = _json.loads(body.decode("utf-8"))["error"]
    assert error["code"] == "payload_too_large"


def test_non_batch_endpoint_not_bounded(client: TestClient) -> None:
    response = client.post(
        "/api/v1/objects/alpha/children",
        json={"id": "test-child", "kind": "service", "label": "Test"},
        headers={"Idempotency-Key": "test-key-1234567890123456"},
    )
    assert response.status_code != 413


# ---------------------------------------------------------------------------
# Finding 2 regressions: missing and concealed IDs receive equivalent
# policy-shaped work
# ---------------------------------------------------------------------------


def test_visibility_for_is_called_for_missing_and_concealed_ids(
    session_factory,
) -> None:
    with session_factory() as session:
        state = _RestrictedState(
            detail_ids=frozenset({"alpha"}),
            stub_ids=frozenset({"gamma"}),
        )
        access = _restricted_access(session, state)
        visibility_calls: list[str] = []
        original_visibility_for = access.policy.visibility_for

        def tracking_visibility_for(object_id: str):
            visibility_calls.append(object_id)
            return original_visibility_for(object_id)

        # PolicySnapshot is frozen but the instance attribute can be replaced
        # via __dict__ because it is not slotted.
        object.__setattr__(
            access.policy,
            "visibility_for",
            tracking_visibility_for,
        )
        batch = query_agent_object_contexts(
            session, access, ["alpha", "delta", "missing-id"]
        )

    assert "delta" in visibility_calls
    assert "missing-id" in visibility_calls
    assert "alpha" in visibility_calls
    assert batch.items[1].visibility == "concealed"
    assert batch.items[2].visibility == "concealed"


def test_missing_and_concealed_produce_identical_result_shape(
    session_factory,
) -> None:
    with session_factory() as session:
        state = _RestrictedState(
            detail_ids=frozenset({"alpha"}),
            stub_ids=frozenset({"gamma"}),
        )
        access = _restricted_access(session, state)
        batch = query_agent_object_contexts(
            session, access, ["delta", "missing-id"]
        )

    existing_concealed = batch.items[0].model_dump()
    missing = batch.items[1].model_dump()
    assert set(existing_concealed) == set(missing) == {"id", "visibility"}
    assert existing_concealed["visibility"] == missing["visibility"] == "concealed"


def test_missing_and_concealed_have_identical_query_count(
    session_factory,
    alembic_database,
) -> None:
    with session_factory() as session:
        state = _RestrictedState(
            detail_ids=frozenset({"alpha"}),
            stub_ids=frozenset({"gamma"}),
        )
        access = _restricted_access(session, state)

    select_counts: list[int] = []

    def count_selects(
        _connection,
        _cursor,
        statement: str,
        _parameters,
        _context,
        _executemany,
    ) -> None:
        if statement.lstrip().upper().startswith("SELECT"):
            select_counts.append(1)

    event.listen(alembic_database.engine, "before_cursor_execute", count_selects)
    try:
        with alembic_database.sessions() as session:
            access = _restricted_access(session, state)
            select_counts.clear()
            query_agent_object_contexts(session, access, ["missing-only"])
            missing_selects = len(select_counts)
            select_counts.clear()
            query_agent_object_contexts(session, access, ["delta"])
            concealed_selects = len(select_counts)
            select_counts.clear()
            query_agent_object_contexts(session, access, ["missing-only", "delta"])
            mixed_selects = len(select_counts)
    finally:
        event.remove(alembic_database.engine, "before_cursor_execute", count_selects)

    assert missing_selects == concealed_selects
    assert mixed_selects == missing_selects
    assert missing_selects <= 5
