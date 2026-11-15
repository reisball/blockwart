"""Targeted personalized HTML cache policy, with real authenticated sessions."""

import pytest
from test_catalog_root_creation import root_client, root_state  # noqa: F401
from test_project_workspace import _create_project

from blockwart.main import _is_principal_scoped_path
from blockwart.ui.security import AUTH_SESSION_COOKIE_NAME

CASES = [
    ("/activity", 200),
    ("/activity?event_type=object_revision", 200),
    ("/activity?since=2026-01-01T00:00:00Z", 200),
    ("/activity?event_type=invalid", 400),
    ("/activity?since=invalid", 400),
    ("/activity?cursor=invalid", 400),
    ("/attention", 200),
    ("/attention?severity=warning&signal_state=current", 200),
    ("/attention?category=invalid", 400),
    ("/attention?severity=invalid", 400),
    ("/attention?signal_state=invalid", 400),
    ("/attention?kind=invalid", 400),
    ("/attention?reason_code=invalid", 400),
    ("/attention?cursor=invalid", 400),
    ("/attention/filters/normalize?category=", 303),
    ("/projects", 200),
    ("/projects?project_category=implementation&project_status=planned", 200),
    ("/projects?project_status=invalid", 422),
    ("/projects?project_category=invalid", 422),
    ("/projects?cursor=invalid", 400),
    ("/projects/filters/normalize?project_status=", 303),
    ("/projects/cache-project", None),
    ("/projects/cache-project?edit=true", None),
    ("/projects/nonexistent", 404),
]


def _assert_private(response):
    assert response.headers["cache-control"] == "private, no-store"
    assert response.headers["pragma"] == "no-cache"
    assert {"Authorization", "Cookie"} <= {
        value.strip() for value in response.headers["vary"].split(",")
    }


@pytest.mark.parametrize("principal", ["owner", "admin"])
def test_personalized_routes_are_private(root_client, root_state, principal):  # noqa: F811
    """Check successful, invalid, redirect and concealed responses per principal.

    Args:
        root_client: Real in-process application client using owned SQLite.
        root_state: Two independently issued browser sessions and API owner.
        principal: Catalog owner or ungranted platform administrator.
    """
    _create_project(root_client, root_state["owner_token"], "cache-project")
    root_client.cookies.set(AUTH_SESSION_COOKIE_NAME, root_state[principal + "_session"].value)
    for path, status in CASES:
        response = root_client.get(path, follow_redirects=False)
        if status is None:
            status = 200 if principal == "owner" else 404
        assert response.status_code == status, (path, response.text)
        _assert_private(response)
        if path == "/projects":
            assert ("Cache Project" in response.text) == (principal == "owner")
        if path == "/activity":
            assert ("cache-project" in response.text) == (principal == "owner")
    # Existing integration policy remains unchanged even for a rejected admin page.
    _assert_private(root_client.get("/settings/integrations", follow_redirects=False))
    asset = root_client.get("/static/app.css")
    assert asset.status_code == 200
    assert "no-store" not in asset.headers.get("cache-control", "")
    assert "etag" in asset.headers


def test_unauthenticated_redirects_keep_auth_and_private_policy(root_client):  # noqa: F811
    """Preserve login redirects while making the targeted response uncacheable.

    Args:
        root_client: Application client without a browser cookie.
    """
    for path in ("/activity", "/attention", "/projects", "/projects/missing"):
        response = root_client.get(path, follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"] == "/auth"
        _assert_private(response)


def test_cache_path_matching_is_segment_bounded():
    """Do not broaden the policy to unrelated prefix lookalikes or static assets."""
    for path in ("/activity", "/attention", "/attention/filters/normalize", "/projects/a"):
        assert _is_principal_scoped_path(path)
    for path in ("/activity-public", "/attentionary", "/projects-public", "/static/app.css"):
        assert not _is_principal_scoped_path(path)
