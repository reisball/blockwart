"""Settings HTML cache contracts using independently issued browser sessions."""

import asyncio

import pytest
from starlette.requests import Request
from starlette.responses import Response
from test_catalog_root_creation import root_client, root_state  # noqa: F401

from blockwart.main import _is_principal_scoped_path, principal_scoped_cache_control
from blockwart.ui.security import AUTH_SESSION_COOKIE_NAME


def _assert_private(response):
    assert response.headers["cache-control"] == "private, no-store"
    assert response.headers["pragma"] == "no-cache"
    assert {"Authorization", "Cookie"} <= {
        value.strip() for value in response.headers["vary"].split(",")
    }


def test_settings_html_is_personalized_and_private(root_client, root_state):  # noqa: F811
    """Protect role-dependent HTML without changing real browser authorization.

    Args:
        root_client: In-process client connected to disposable migrated SQLite.
        root_state: Real non-admin user and platform-admin browser sessions.
    """
    bodies = {}
    for principal in ("owner", "admin"):
        root_client.cookies.set(AUTH_SESSION_COOKIE_NAME, root_state[principal + "_session"].value)
        response = root_client.get("/settings", follow_redirects=False)
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/html")
        bodies[principal] = response.text
        assert ('id="settings-principals-title"' in response.text) == (principal == "admin")
        assert ('href="/admin/principals"' in response.text) == (principal == "admin")
        _assert_private(response)
    assert bodies["owner"] != bodies["admin"]


@pytest.mark.parametrize("principal", [None, "owner", "admin"])
def test_settings_redirect_error_and_existing_subpage_contracts(
    root_client,  # noqa: F811
    root_state,  # noqa: F811
    principal,
):
    """Preserve auth, slash redirects, method errors and existing prefix policy.

    Args:
        root_client: In-process application client.
        root_state: Real browser-session fixture.
        principal: Anonymous, non-admin user or platform administrator.
    """
    if principal:
        root_client.cookies.set(AUTH_SESSION_COOKIE_NAME, root_state[principal + "_session"].value)
    for path in ("/settings", "/settings?lang=en", "/settings/schema?kind=invalid"):
        response = root_client.get(path, follow_redirects=False)
        assert response.status_code == (200 if principal else 303)
        if not principal:
            assert response.headers["location"] == "/auth"
        _assert_private(response)
    slash = root_client.get("/settings/", follow_redirects=False)
    assert slash.status_code == 307
    assert slash.headers["location"] == "http://testserver/settings"
    _assert_private(slash)
    missing = root_client.get("/settings/missing", follow_redirects=False)
    assert missing.status_code == 404
    _assert_private(missing)
    method = root_client.post("/settings", follow_redirects=False)
    assert method.status_code == 405
    assert method.headers["allow"] == "GET"
    _assert_private(method)
    for path in ("/settings-public", "/settingsary"):
        lookalike = root_client.get(path, follow_redirects=False)
        assert lookalike.status_code == 404
        for header in ("cache-control", "pragma", "vary"):
            assert header not in lookalike.headers
    asset = root_client.get("/static/app.css", follow_redirects=False)
    assert asset.status_code == 200
    assert "etag" in asset.headers
    assert "no-store" not in asset.headers.get("cache-control", "")


def test_settings_middleware_preserves_vary_and_response_contract():
    """Merge existing Vary tokens without changing response status, body or headers."""

    async def exercise(path, status):
        request = Request(
            {
                "type": "http",
                "method": "GET",
                "path": path,
                "headers": [],
                "query_string": b"",
                "scheme": "http",
                "server": ("testserver", 80),
            }
        )
        response = Response(
            "unchanged",
            status_code=status,
            headers={"Vary": "Accept-Language, Origin, Cookie", "X-Contract": "kept"},
        )

        async def call_next(_request):
            return response

        result = await principal_scoped_cache_control(request, call_next)
        assert result is response
        assert result.status_code == status
        assert result.body == b"unchanged"
        assert result.headers["x-contract"] == "kept"
        if path == "/settings":
            _assert_private(result)
            assert result.headers["vary"] == "Accept-Language, Authorization, Cookie, Origin"
        else:
            assert result.headers["vary"] == "Accept-Language, Origin, Cookie"
            assert "cache-control" not in result.headers
            assert "pragma" not in result.headers

    for path in ("/settings", "/settings-public", "/static/app.css"):
        for status in (200, 303, 400, 404, 422, 500):
            asyncio.run(exercise(path, status))
    for path in ("/settings", "/settings/", "/settings/schema", "/settings/missing"):
        assert _is_principal_scoped_path(path)
    for path in ("/settings-public", "/settingsary", "/static/app.css"):
        assert not _is_principal_scoped_path(path)
