"""Explicit browser value actions use current rights, CSRF and no-store."""
import json

import pytest
from test_reference_content_ui_315 import (  # noqa: F401
    REFERENCE_ID,
    reference_browser,
    root_client,
    root_state,
)

from blockwart.db.session import transaction
from blockwart.domain.auth import Role
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services.catalog import upsert_object
from blockwart.services.credential_safe import Bao

SYNTHETIC = "synthetic-ui-safe-value-335"


@pytest.mark.parametrize("role,read_status,write_status", [
    (Role.VIEWER, 403, 403),
    (Role.EDITOR, 403, 403),
    (Role.REFERENCE_CONTENT_READER, 200, 403),
    (Role.REFERENCE_CONTENT_EDITOR, 403, 200),
    (Role.OWNER, 200, 200),
])
def test_no_prefetch_explicit_reveal_and_blind_write(
    reference_browser, monkeypatch, role, read_status, write_status,  # noqa: F811
):
    client, browser, factory = reference_browser(role)
    with factory() as session, transaction(session):
        upsert_object(session, CatalogObjectIn(
            id=REFERENCE_ID, kind="credential_reference", label="Safe entry",
            data={"schema_version": 1, "provider": "safe", "reference": {},
                  "secret_value_stored": False},
        ))
    calls = []
    monkeypatch.setattr(Bao, "__init__", lambda *args: None)

    def backend(self, method, path, body=None):
        calls.append((method, path, body))
        if method == "POST":
            return {"data": {"version": 1}}
        return {"data": {"data": {"fields": {"password": SYNTHETIC}, "deleted": False},
                         "metadata": {"version": 1}}}

    monkeypatch.setattr(Bao, "request", backend)
    page = client.get(f"/objects/{REFERENCE_ID}?lang=en")
    assert page.status_code == 200 and SYNTHETIC not in page.text
    assert not calls
    url = f"/objects/{REFERENCE_ID}/safe"
    assert client.post(url, data={"action": "read", "csrf_token": "invalid"}).status_code == 403
    assert not calls
    reveal = client.post(url, data={"action": "read", "csrf_token": browser.csrf_token})
    assert reveal.status_code == read_status
    assert (SYNTHETIC in reveal.text) is (read_status == 200)
    assert "no-store" in reveal.headers["Cache-Control"]
    write = client.post(url, data={"action": "write", "cas": "0",
                                  "fields_json": json.dumps({"password": SYNTHETIC}),
                                  "csrf_token": browser.csrf_token})
    assert write.status_code == write_status and SYNTHETIC not in write.text
