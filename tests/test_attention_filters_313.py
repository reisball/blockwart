"""Browser filters share the authorized attention query and cursor binding (#313)."""

import re
from html import unescape
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient

from blockwart.api.deps import get_session
from blockwart.db.session import transaction
from blockwart.main import create_app
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services.catalog import upsert_object


@pytest.fixture
def attention_browser(alembic_session_factory, install_unrestricted_read_access):
    with alembic_session_factory() as session, transaction(session):
        for index in range(102):
            upsert_object(session, CatalogObjectIn.model_validate({
                "id": f"host-{index:03d}", "kind": "host", "label": f"Host {index:03d}",
                "lifecycle": "active", "health": "down", "data": {"schema_version": 1},
            }))
        upsert_object(session, CatalogObjectIn.model_validate({
            "id": "service-down", "kind": "service", "label": "Service Down",
            "lifecycle": "active", "health": "down", "data": {
                "schema_version": 1,
                "placement": {"state": "unassigned", "reason": "Synthetic fixture."},
            },
        }))
    app = create_app()
    install_unrestricted_read_access(app)

    def session_dependency():
        with alembic_session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = session_dependency
    with TestClient(app) as client:
        yield client


def _next_url(text):
    return unescape(re.search(r'href="([^"]+)">More items</a>', text)[1])


@pytest.mark.parametrize("filters,total", [
    ({"kind": "host", "category": "lifecycle"}, 102),
    ({"reason_code": "lifecycle_health_down"}, 103),
    ({"kind": "service", "reason_code": "lifecycle_health_down",
      "severity": "critical", "signal_state": "current", "category": "lifecycle"}, 1),
])
def test_browser_filter_rows_and_summary_match_shared_api(attention_browser, filters, total):
    api = attention_browser.get("/api/v1/attention", params={**filters, "include_total": True})
    assert api.status_code == 200
    assert api.json()["total"] == total
    page = attention_browser.get("/attention", params={**filters, "lang": "en"})
    assert page.status_code == 200
    assert page.text.count('class="attention-row ') == min(total, 100)
    for item in api.json()["items"]:
        assert item["target"]["label"] in page.text
    if filters.get("kind") == "service":
        assert "Host 000" not in page.text
        assert "Critical: 1" in page.text


def test_normalization_pagination_validation_and_reset(attention_browser):
    filters = {"kind": "host", "reason_code": "lifecycle_health_down", "category": "lifecycle"}
    normalized = attention_browser.get("/attention/filters/normalize", params={
        **filters, "severity": "", "signal_state": "", "cursor": "obsolete",
    }, follow_redirects=False)
    assert normalized.status_code == 303
    assert parse_qs(urlsplit(normalized.headers["location"]).query) == {
        key: [value] for key, value in filters.items()
    }
    first = attention_browser.get(normalized.headers["location"] + "&lang=en")
    assert 'value="host" selected' in first.text
    assert 'value="lifecycle_health_down" selected' in first.text
    assert 'href="/attention">Clear filters</a>' in first.text
    next_url = _next_url(first.text)
    params = parse_qs(urlsplit(next_url).query)
    assert all(params[key] == [value] for key, value in filters.items())
    second = attention_browser.get(next_url)
    assert second.status_code == 200
    assert second.text.count('class="attention-row ') == 2
    assert "Host 000" not in second.text
    changed = attention_browser.get("/attention", params={
        **filters, "kind": "service", "cursor": params["cursor"][0],
    })
    assert changed.status_code == 400
    assert changed.json()["detail"] == "Invalid pagination cursor"
    for invalid in ({"kind": "invalid"}, {"reason_code": "invalid"}):
        response = attention_browser.get("/attention", params=invalid)
        assert response.status_code == 400
        assert response.json()["detail"] == "Invalid attention filter"
        normalized = attention_browser.get("/attention/filters/normalize", params=invalid)
        assert normalized.status_code == 400
    assert attention_browser.get("/attention/filters/normalize", params={
        "kind": "", "reason_code": "",
    }, follow_redirects=False).headers["location"] == "/attention"


def test_controls_use_both_existing_locales(attention_browser):
    for locale, labels in {
        "en": ("Object kind", "All object kinds", "All reasons"),
        "de": ("Objekttyp", "Alle Objekttypen", "Alle Hinweisgründe"),
    }.items():
        response = attention_browser.get("/attention", params={"lang": locale})
        assert response.status_code == 200
        assert all(label in response.text for label in labels)
        assert 'value="credential_reference"' in response.text
        assert "attention.all_" not in response.text
