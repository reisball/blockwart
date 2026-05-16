import json

from blockwart.mcp.server import TOOLS, call_tool, handle_request


def test_mcp_tools_are_read_only() -> None:
    names = {tool["name"] for tool in TOOLS}

    assert names == {
        "blockwart.search",
        "blockwart.get_object_context",
        "blockwart.get_context",
    }
    assert not any("write" in name or "delete" in name or "update" in name for name in names)


def test_mcp_tools_list_request() -> None:
    response = handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})

    assert response is not None
    assert response["result"]["tools"] == TOOLS


def test_mcp_search_calls_read_only_agent_search_endpoint() -> None:
    calls = []

    def fake_fetch(path, params):
        calls.append((path, params))
        return {"count": 1, "results": [{"ref": "system:brieftraeger"}]}

    response = call_tool(
        "blockwart.search",
        {"q": "brieftraeger", "kind": "system", "limit": 3},
        fetcher=fake_fetch,
    )

    assert calls == [("/api/agent/search", {"q": "brieftraeger", "kind": "system", "limit": 3})]
    payload = json.loads(response["content"][0]["text"])
    assert payload["results"][0]["ref"] == "system:brieftraeger"
    assert response["isError"] is False


def test_mcp_get_object_context_calls_read_only_agent_object_endpoint() -> None:
    calls = []

    def fake_fetch(path, params):
        calls.append((path, params))
        return {"count": 1, "objects": [{"ref": "system:n8n"}]}

    response = call_tool(
        "blockwart.get_object_context",
        {"object_id": "n8n"},
        fetcher=fake_fetch,
    )

    assert calls == [("/api/agent/objects/n8n", {})]
    payload = json.loads(response["content"][0]["text"])
    assert payload["objects"][0]["ref"] == "system:n8n"


def test_mcp_context_calls_read_only_agent_context_endpoint() -> None:
    calls = []

    def fake_fetch(path, params):
        calls.append((path, params))
        return {"count": 2, "objects": []}

    response = call_tool(
        "blockwart.get_context",
        {"q": "paperless", "kind": "service", "limit": 2},
        fetcher=fake_fetch,
    )

    assert calls == [("/api/agent/context", {"q": "paperless", "kind": "service", "limit": 2})]
    assert json.loads(response["content"][0]["text"])["count"] == 2


def test_mcp_rejects_unknown_tools_without_fetching() -> None:
    def fake_fetch(path, params):
        raise AssertionError("fetcher should not be called")

    try:
        call_tool("blockwart.delete", {}, fetcher=fake_fetch)
    except ValueError as exc:
        assert "Unknown tool" in str(exc)
    else:
        raise AssertionError("unknown tool should fail")
