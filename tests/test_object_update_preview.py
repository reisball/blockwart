"""ETag-bound read-only update preview (issue #189).

The preview shares one planning core with the real full-object update, so
these tests prove three separate things: that the shared plan really is the
same decision, that the published preview contract is bounded, deterministic,
and redacted, and that a preview mutates nothing at all on SQLite and
PostgreSQL.
"""

from __future__ import annotations

import json
from collections.abc import Generator
from io import BytesIO
from pathlib import Path
from urllib.error import HTTPError

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import inspect, select, text
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.db.session import transaction
from blockwart.domain.auth import GrantScope, Role
from blockwart.domain.security import REDACTED_SECRET_VALUE
from blockwart.domain.update_preview import (
    PREVIEW_CONTRACT_VERSION,
    PREVIEW_DIFF_MAX_ENTRIES,
    PREVIEW_DIFF_VALUE_MAX_LENGTH,
    PREVIEW_DIGEST_DOMAIN,
    REDACTED_PREVIEW_VALUE,
    preview_diff,
    preview_digest,
)
from blockwart.main import create_app
from blockwart.mcp.server import (
    TOOL_DEFINITIONS,
    UpstreamError,
    _translate_http_error,
    call_tool,
)
from blockwart.models import (
    CatalogObject,
    ObjectGrant,
    Principal,
    Relationship,
    SecurityEvent,
)
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services.access import create_object_grant
from blockwart.services.catalog import upsert_object
from blockwart.services.commands import (
    CommandNotFound,
    WriteContext,
    preview_catalog_object_update,
    update_catalog_object,
)
from blockwart.services.identity import (
    create_service_account,
    issue_service_token,
    principal_context,
)
from blockwart.services.policy import policy_for_principal

PREVIEW_PATH = "/api/v1/objects/{object_id}/update-preview"
SECRET_MARKER = "Bearer abcdefghijklmnopqrstuvwxyz0123456789"

# One representative object per supported kind. `data` is the canonical minimal
# valid document of that kind, so every preview below runs the real registry.
KIND_DATA: dict[str, dict] = {
    "host": {"schema_version": 1},
    "system": {"schema_version": 1},
    "network": {"schema_version": 1, "network": {"category": "access_point"}},
    "device": {"schema_version": 1, "device": {"category": "adapter"}},
    "service": {"schema_version": 1},
    "credential_reference": {"schema_version": 1},
    "runbook": {
        "schema_version": 1,
        "runbook_status": "draft",
        "approval_required": False,
    },
    "decision": {"schema_version": 1, "decision_status": "proposed"},
    "project": {
        "schema_version": 1,
        "category": "implementation",
        "project_status": "planned",
    },
}
ASSET_KINDS = ("host", "system", "network", "device", "service")


def _object(
    object_id: str,
    *,
    kind: str = "service",
    label: str | None = None,
    summary: str | None = None,
    data: dict | None = None,
) -> CatalogObjectIn:
    payload: dict = {
        "id": object_id,
        "kind": kind,
        "label": label or object_id,
        "summary": summary,
        "data": data if data is not None else dict(KIND_DATA[kind]),
    }
    if kind in ASSET_KINDS:
        payload["lifecycle"] = "active"
        payload["health"] = "healthy"
    return CatalogObjectIn(**payload)


def _kind_object_id(kind: str) -> str:
    return f"preview-{kind.replace('_', '-')}"


def _raw(
    object_id: str,
    *,
    kind: str = "service",
    label: str | None = None,
    summary: str | None = None,
    data: dict | None = None,
) -> dict:
    """Build a request body the client model does not pre-validate.

    Rejection-parity cases must reach the server exactly as an agent would
    send them, so they cannot be routed through `CatalogObjectIn` first.
    """
    payload: dict = {
        "id": object_id,
        "kind": kind,
        "label": label or object_id,
        "status": "active",
        "summary": summary,
        "data": data if data is not None else dict(KIND_DATA[kind]),
    }
    if kind in ASSET_KINDS:
        payload["lifecycle"] = "active"
        payload["health"] = "healthy"
    return payload


@pytest.fixture
def preview_state(alembic_session_factory):
    """One writable object per kind plus concealed and discover-only neighbours."""
    with alembic_session_factory() as session:
        with transaction(session):
            principal = create_service_account(
                session,
                login="preview.writer",
                display_name="Preview Writer",
            )
            for kind in KIND_DATA:
                row = upsert_object(
                    session,
                    _object(_kind_object_id(kind), kind=kind, summary="before"),
                )
                create_object_grant(
                    session,
                    principal_id=principal.id,
                    object_id=row.id,
                    role=Role.EDITOR,
                    scope=GrantScope.SELF,
                )
            discover_only = upsert_object(
                session,
                _object("preview-discover-only", summary="hidden summary"),
            )
            create_object_grant(
                session,
                principal_id=principal.id,
                object_id=discover_only.id,
                role=Role.DISCOVERER,
                scope=GrantScope.SELF,
            )
            reader_only = upsert_object(
                session,
                _object("preview-read-only", summary="read only"),
            )
            create_object_grant(
                session,
                principal_id=principal.id,
                object_id=reader_only.id,
                role=Role.VIEWER,
                scope=GrantScope.SELF,
            )
            # Never granted to the acting principal at all.
            upsert_object(session, _object("preview-concealed", summary="concealed"))
            upsert_object(
                session,
                _object("preview-concealed-two", summary="concealed too"),
            )
            token = issue_service_token(
                session,
                principal_id=principal.id,
                name="preview",
            )
    return {
        "session_factory": alembic_session_factory,
        "principal_id": principal.id,
        "token": token.value,
    }


@pytest.fixture
def preview_client(preview_state) -> Generator[TestClient, None, None]:
    session_factory = preview_state["session_factory"]
    app = create_app()

    def override_get_session() -> Generator[Session, None, None]:
        with session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    with TestClient(app) as client:
        yield client


def _auth(state) -> dict[str, str]:
    return {"Authorization": f"Bearer {state['token']}"}


def _etag(client: TestClient, state, object_id: str) -> str:
    response = client.get(f"/api/v1/objects/{object_id}", headers=_auth(state))
    assert response.status_code == 200, response.text
    return response.headers["etag"]


def _preview(client, state, object_id, payload, *, if_match, headers=None):
    request_headers = {**_auth(state), **(headers or {})}
    if if_match is not None:
        request_headers["If-Match"] = if_match
    return client.post(
        PREVIEW_PATH.format(object_id=object_id),
        headers=request_headers,
        json=payload,
    )


def _paths(body: dict) -> list[str]:
    return [entry["path"] for entry in body["diff"]]


# ---------------------------------------------------------------------------
# Row-exact read-only evidence
# ---------------------------------------------------------------------------

def _database_fingerprint(session: Session) -> dict[str, list[tuple[object, ...]]]:
    """Every persisted row, including auth timestamps and auxiliary state."""
    bind = session.get_bind()
    return {
        table: sorted(
            (tuple(row) for row in session.execute(text(f'SELECT * FROM "{table}"'))),
            key=repr,
        )
        for table in sorted(inspect(bind).get_table_names())
    }


def _sqlite_sequences(session: Session) -> list[tuple[str, int]]:
    exists = session.execute(
        text("SELECT name FROM sqlite_master WHERE type='table' AND name='sqlite_sequence'")
    ).first()
    if exists is None:
        return []
    return [
        (str(name), int(seq))
        for name, seq in session.execute(
            text("SELECT name, seq FROM sqlite_sequence ORDER BY name")
        )
    ]


# ---------------------------------------------------------------------------
# Positive contract: changed and canonical no-op previews for every kind
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", sorted(KIND_DATA))
def test_changed_and_canonical_noop_preview_for_every_supported_kind(
    preview_client: TestClient,
    preview_state,
    kind: str,
) -> None:
    object_id = _kind_object_id(kind)
    etag = _etag(preview_client, preview_state, object_id)
    unchanged = _object(object_id, kind=kind, summary="before").model_dump(mode="json")

    noop = _preview(preview_client, preview_state, object_id, unchanged, if_match=etag)

    assert noop.status_code == 200, noop.text
    noop_body = noop.json()
    assert noop_body["changed"] is False
    assert noop_body["diff"] == []
    assert noop_body["base_etag"] == etag
    assert noop_body["expected_result_etag"] == etag
    assert noop_body["base_revision"] == noop_body["expected_result_revision"]
    assert noop_body["object_kind"] == kind
    assert noop_body["preview_contract_version"] == PREVIEW_CONTRACT_VERSION

    changed_payload = {**unchanged, "summary": "after", "label": "Renamed"}
    changed = _preview(
        preview_client,
        preview_state,
        object_id,
        changed_payload,
        if_match=etag,
    )

    assert changed.status_code == 200, changed.text
    changed_body = changed.json()
    assert changed_body["changed"] is True
    assert _paths(changed_body) == ["/label", "/summary"]
    assert changed_body["expected_result_revision"] == changed_body["base_revision"] + 1
    assert changed_body["expected_result_etag"] != changed_body["base_etag"]
    assert changed_body["preview_digest"] != noop_body["preview_digest"]

    # Reordered input is not business state: the canonical no-op survives it.
    reordered = dict(reversed(list(unchanged.items())))
    repeated_noop = _preview(
        preview_client,
        preview_state,
        object_id,
        reordered,
        if_match=etag,
    )
    assert repeated_noop.status_code == 200
    assert repeated_noop.json() == noop_body


def test_preview_normalization_and_immediate_real_update_agree(
    preview_client: TestClient,
    preview_state,
) -> None:
    """The shared plan makes the preview a faithful forecast of the write."""
    object_id = _kind_object_id("service")
    etag = _etag(preview_client, preview_state, object_id)
    proposed = _object(
        object_id,
        summary="after",
        data={
            "schema_version": 1,
            "components": {
                "items": [
                    {
                        "id": "database",
                        "name": "Database",
                        "role": "database",
                        "description": "Stores records.",
                    },
                    {
                        "id": "api",
                        "name": "API",
                        "role": "api",
                        "description": "HTTP boundary.",
                    },
                ],
                "dependencies": [],
            },
        },
    ).model_dump(mode="json")

    preview = _preview(preview_client, preview_state, object_id, proposed, if_match=etag)
    assert preview.status_code == 200, preview.text
    body = preview.json()

    applied = preview_client.put(
        f"/api/v1/objects/{object_id}",
        headers={**_auth(preview_state), "If-Match": etag},
        json=proposed,
    )

    assert applied.status_code == 200, applied.text
    assert applied.json()["changed"] is body["changed"]
    assert applied.headers["etag"] == body["expected_result_etag"]
    assert applied.json()["catalog_object"]["revision"] == body["expected_result_revision"]
    # Normalization parity: the preview reports the normalized component order.
    component_change = next(
        entry for entry in body["diff"] if entry["path"] == "/data/components/items"
    )
    assert component_change["after"]["text"] is not None
    assert applied.json()["catalog_object"]["data"]["components"]["items"][0]["id"] == "api"

    # Previewing the applied state is now the canonical no-op.
    settled = _preview(
        preview_client,
        preview_state,
        object_id,
        proposed,
        if_match=applied.headers["etag"],
    )
    assert settled.status_code == 200
    assert settled.json()["changed"] is False
    assert settled.json()["diff"] == []


def test_preview_reports_a_provenance_only_change_instead_of_an_empty_diff(
    preview_client: TestClient,
    preview_state,
) -> None:
    object_id = _kind_object_id("host")
    etag = _etag(preview_client, preview_state, object_id)
    proposed = _object(object_id, kind="host", summary="before").model_dump(mode="json")
    proposed["provenance"] = {
        "source_type": "import",
        "source_ref": "seed://example",
        "manual_override": False,
    }

    body = _preview(
        preview_client,
        preview_state,
        object_id,
        proposed,
        if_match=etag,
    ).json()

    assert body["changed"] is True
    assert "/provenance/source_type" in _paths(body)
    assert body["diff"] == sorted(body["diff"], key=lambda entry: entry["path"])


# ---------------------------------------------------------------------------
# Preconditions, concurrency, and authorization boundaries
# ---------------------------------------------------------------------------


def test_missing_stale_and_malformed_etags_match_the_update_envelopes(
    preview_client: TestClient,
    preview_state,
) -> None:
    object_id = _kind_object_id("service")
    etag = _etag(preview_client, preview_state, object_id)
    payload = _object(object_id, summary="after").model_dump(mode="json")

    missing = _preview(preview_client, preview_state, object_id, payload, if_match=None)
    malformed = _preview(
        preview_client,
        preview_state,
        object_id,
        payload,
        if_match="not-an-etag",
    )
    weak = _preview(
        preview_client,
        preview_state,
        object_id,
        payload,
        if_match='W/"rev-1"',
    )
    stale = _preview(
        preview_client,
        preview_state,
        object_id,
        payload,
        if_match='"rev-99"',
    )

    assert missing.status_code == 428
    assert malformed.status_code == 412
    assert weak.status_code == 412
    assert stale.status_code == 412

    for preview_response, method_response in (
        (missing, preview_client.put(
            f"/api/v1/objects/{object_id}",
            headers=_auth(preview_state),
            json=payload,
        )),
        (malformed, preview_client.put(
            f"/api/v1/objects/{object_id}",
            headers={**_auth(preview_state), "If-Match": "not-an-etag"},
            json=payload,
        )),
        (stale, preview_client.put(
            f"/api/v1/objects/{object_id}",
            headers={**_auth(preview_state), "If-Match": '"rev-99"'},
            json=payload,
        )),
    ):
        assert preview_response.status_code == method_response.status_code
        assert preview_response.json()["error"]["code"] == (
            method_response.json()["error"]["code"]
        )

    assert etag  # the readable current ETag still previews successfully
    assert _preview(
        preview_client,
        preview_state,
        object_id,
        payload,
        if_match=etag,
    ).status_code == 200


def test_a_write_between_preview_and_apply_fails_the_ordinary_precondition(
    preview_client: TestClient,
    preview_state,
) -> None:
    object_id = _kind_object_id("service")
    etag = _etag(preview_client, preview_state, object_id)
    payload = _object(object_id, summary="planned").model_dump(mode="json")

    preview = _preview(preview_client, preview_state, object_id, payload, if_match=etag)
    assert preview.status_code == 200
    assert preview.json()["expected_result_etag"] == '"rev-3"'

    concurrent = preview_client.put(
        f"/api/v1/objects/{object_id}",
        headers={**_auth(preview_state), "If-Match": etag},
        json=_object(object_id, summary="someone else").model_dump(mode="json"),
    )
    assert concurrent.status_code == 200

    late_apply = preview_client.put(
        f"/api/v1/objects/{object_id}",
        headers={**_auth(preview_state), "If-Match": etag},
        json=payload,
    )
    late_preview = _preview(
        preview_client,
        preview_state,
        object_id,
        payload,
        if_match=etag,
    )

    assert late_apply.status_code == 412
    assert late_preview.status_code == 412


def test_missing_concealed_discover_only_and_read_only_give_no_preview_oracle(
    preview_client: TestClient,
    preview_state,
) -> None:
    session_factory = preview_state["session_factory"]
    payload_for = lambda object_id: _object(  # noqa: E731
        object_id,
        summary="probe",
    ).model_dump(mode="json")

    absent = _preview(
        preview_client,
        preview_state,
        "preview-does-not-exist",
        payload_for("preview-does-not-exist"),
        if_match='"rev-1"',
    )
    concealed = _preview(
        preview_client,
        preview_state,
        "preview-concealed",
        payload_for("preview-concealed"),
        if_match='"rev-1"',
    )
    discover_only = _preview(
        preview_client,
        preview_state,
        "preview-discover-only",
        payload_for("preview-discover-only"),
        if_match='"rev-1"',
    )
    read_only = _preview(
        preview_client,
        preview_state,
        "preview-read-only",
        payload_for("preview-read-only"),
        if_match='"rev-1"',
    )

    # Absent and concealed are byte-identical apart from the correlation ID.
    assert absent.status_code == concealed.status_code == 404
    assert absent.json()["error"]["code"] == concealed.json()["error"]["code"]
    assert absent.json()["error"]["message"] == concealed.json()["error"]["message"]
    # Neither reveals the real revision through the stale ETag it was handed.
    assert "rev-" not in absent.text
    assert "rev-" not in concealed.text

    # Discoverable but not writable: the same denial the real update raises,
    # decided before any payload, revision, or diff is computed.
    assert discover_only.status_code == 403
    assert read_only.status_code == 403
    assert "hidden summary" not in discover_only.text
    assert "read only" not in read_only.text
    assert "rev-" not in discover_only.text

    with session_factory() as session:
        denials = session.scalars(
            select(SecurityEvent)
            .where(SecurityEvent.event_type == "object_command_authorization")
            .order_by(SecurityEvent.id)
        ).all()
    # Unlike the real write command, the read-only preview creates no security
    # row for these permission denials.
    assert denials == []


def test_cross_object_authorization_and_identity_are_enforced(
    preview_client: TestClient,
    preview_state,
) -> None:
    writable = _kind_object_id("service")
    etag = _etag(preview_client, preview_state, writable)

    # A payload naming another object cannot be smuggled through the path.
    mismatched = _preview(
        preview_client,
        preview_state,
        writable,
        _object("preview-concealed", summary="smuggled").model_dump(mode="json"),
        if_match=etag,
    )
    # ...and the reverse: a writable payload aimed at a concealed path.
    concealed_path = _preview(
        preview_client,
        preview_state,
        "preview-concealed",
        _object(writable, summary="smuggled").model_dump(mode="json"),
        if_match=etag,
    )

    assert mismatched.status_code == 409
    assert "preview-concealed" not in mismatched.json()["error"]["message"]
    assert concealed_path.status_code == 404


def test_preview_and_update_reauthorize_from_current_state_not_a_stale_policy(
    preview_state,
) -> None:
    session_factory = preview_state["session_factory"]
    object_id = _kind_object_id("service")
    with session_factory() as session:
        principal_row = session.get(
            Principal,
            preview_state["principal_id"],
        )
        target = session.get(CatalogObject, object_id)
        assert principal_row is not None
        assert target is not None
        stale_context = WriteContext(
            principal=principal_context(principal_row),
            policy=policy_for_principal(session, principal_row.id),
            channel="api",
            request_id="preview-stale-policy",
        )
        expected_revision = target.revision
        grant = session.scalar(
            select(ObjectGrant).where(
                ObjectGrant.principal_id == principal_row.id,
                ObjectGrant.object_id == object_id,
            )
        )
        assert grant is not None
        session.delete(grant)
        session.commit()

    payload = _object(object_id, summary="must not apply")
    with session_factory() as session:
        with pytest.raises(CommandNotFound):
            preview_catalog_object_update(
                session,
                stale_context,
                object_id=object_id,
                payload=payload,
                expected_revision=expected_revision,
                refresh_policy=True,
            )
        with pytest.raises(CommandNotFound):
            update_catalog_object(
                session,
                stale_context,
                object_id=object_id,
                payload=payload,
                expected_revision=expected_revision,
                refresh_policy=True,
            )


def test_preview_requires_authentication_like_every_other_object_command(
    preview_client: TestClient,
    preview_state,
) -> None:
    object_id = _kind_object_id("service")
    response = preview_client.post(
        PREVIEW_PATH.format(object_id=object_id),
        headers={"If-Match": '"rev-2"'},
        json=_object(object_id).model_dump(mode="json"),
    )
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# Rejection parity with the real update
# ---------------------------------------------------------------------------


REJECTION_CASES: list[tuple[str, str, dict, int]] = [
    (
        "schema_version_value",
        "service",
        {"schema_version": "one"},
        422,
    ),
    (
        "domain_enum_value",
        "network",
        {"schema_version": 1, "network": {"category": "not-a-category"}},
        422,
    ),
    (
        "secret_shaped_key",
        "service",
        {"schema_version": 1, "password": "anything"},
        422,
    ),
    (
        "secret_shaped_value",
        "service",
        {"schema_version": 1, "note": SECRET_MARKER},
        422,
    ),
    (
        "acl_shaped_key",
        "service",
        {"schema_version": 1, "permissions": ["read"]},
        422,
    ),
    (
        "typed_reference_target",
        "service",
        {"schema_version": 1, "credential_refs": ["credential_reference:not-here"]},
        404,
    ),
    (
        "component_reference",
        "service",
        {
            "schema_version": 1,
            "components": {
                "items": [
                    {
                        "id": "api",
                        "name": "API",
                        "role": "api",
                        "description": "Boundary.",
                    }
                ],
                "dependencies": [
                    {"component_id": "api", "depends_on": "service:preview-concealed"}
                ],
            },
        },
        422,
    ),
    (
        "monitoring_document",
        "service",
        {"schema_version": 1, "monitoring": {"enabled": "yes-please"}},
        422,
    ),
    (
        "placement_document",
        "host",
        {
            "schema_version": 1,
            "placement": {"state": "unassigned", "reason": "not valid on a host"},
        },
        422,
    ),
    (
        "runbook_status_value",
        "runbook",
        {
            "schema_version": 1,
            "runbook_status": "not-a-status",
            "approval_required": False,
        },
        422,
    ),
    (
        "decision_status",
        "decision",
        {"schema_version": 1, "decision_status": "not-a-status"},
        422,
    ),
    (
        "project_category",
        "project",
        {"schema_version": 1, "category": "nope", "project_status": "planned"},
        422,
    ),
]


@pytest.mark.parametrize(
    ("case", "kind", "data", "status"),
    REJECTION_CASES,
    ids=[case[0] for case in REJECTION_CASES],
)
def test_invalid_proposals_fail_exactly_like_the_real_update(
    preview_client: TestClient,
    preview_state,
    case: str,
    kind: str,
    data: dict,
    status: int,
) -> None:
    object_id = _kind_object_id(kind)
    etag = _etag(preview_client, preview_state, object_id)
    payload = _raw(object_id, kind=kind, data=data)

    preview = _preview(preview_client, preview_state, object_id, payload, if_match=etag)
    applied = preview_client.put(
        f"/api/v1/objects/{object_id}",
        headers={**_auth(preview_state), "If-Match": etag},
        json=payload,
    )

    assert preview.status_code == applied.status_code == status, preview.text
    preview_error = preview.json()["error"]
    applied_error = applied.json()["error"]
    assert preview_error["code"] == applied_error["code"]
    assert preview_error["message"] == applied_error["message"]
    assert preview_error.get("details") == applied_error.get("details")
    assert SECRET_MARKER not in preview.text
    assert "preview-concealed" not in preview.text


def test_asset_state_on_a_knowledge_kind_is_rejected_identically(
    preview_client: TestClient,
    preview_state,
) -> None:
    object_id = _kind_object_id("decision")
    etag = _etag(preview_client, preview_state, object_id)
    payload = {
        **_raw(object_id, kind="decision"),
        "lifecycle": "active",
        "health": "healthy",
    }

    preview = _preview(preview_client, preview_state, object_id, payload, if_match=etag)
    applied = preview_client.put(
        f"/api/v1/objects/{object_id}",
        headers={**_auth(preview_state), "If-Match": etag},
        json=payload,
    )

    assert preview.status_code == applied.status_code == 422
    assert preview.json()["error"]["details"] == applied.json()["error"]["details"]


@pytest.mark.parametrize(
    "payload_patch",
    [
        {"kind": "unsupported-kind"},
        {"provenance": {"source_type": "unsupported-source"}},
    ],
)
def test_kind_and_provenance_boundary_rejections_match_the_real_update(
    preview_client: TestClient,
    preview_state,
    payload_patch: dict,
) -> None:
    object_id = _kind_object_id("service")
    etag = _etag(preview_client, preview_state, object_id)
    payload = {**_raw(object_id), **payload_patch}

    preview = _preview(preview_client, preview_state, object_id, payload, if_match=etag)
    applied = preview_client.put(
        f"/api/v1/objects/{object_id}",
        headers={**_auth(preview_state), "If-Match": etag},
        json=payload,
    )

    assert preview.status_code == applied.status_code == 422
    assert preview.json()["error"]["details"] == applied.json()["error"]["details"]


def test_a_relationship_integrity_rejection_matches_the_real_update(
    preview_client: TestClient,
    preview_state,
) -> None:
    """A rejection only the surrounding edge set can decide stays a 409."""
    session_factory = preview_state["session_factory"]
    object_id = _kind_object_id("device")
    with session_factory() as session:
        with transaction(session):
            session.add(
                Relationship(
                    from_ref=f"host:{_kind_object_id('host')}",
                    relation_type="hosts",
                    to_ref=f"device:{object_id}",
                    metadata_json="{}",
                )
            )
    etag = _etag(preview_client, preview_state, object_id)
    payload = _object(object_id, kind="service", data={"schema_version": 1}).model_dump(
        mode="json"
    )

    preview = _preview(preview_client, preview_state, object_id, payload, if_match=etag)
    applied = preview_client.put(
        f"/api/v1/objects/{object_id}",
        headers={**_auth(preview_state), "If-Match": etag},
        json=payload,
    )

    assert preview.status_code == applied.status_code == 409
    assert preview.json()["error"]["code"] == applied.json()["error"]["code"]
    assert "details" not in preview.json()["error"]


def test_a_knowledge_reference_to_a_concealed_target_stays_indistinguishable(
    preview_client: TestClient,
    preview_state,
) -> None:
    object_id = _kind_object_id("runbook")
    etag = _etag(preview_client, preview_state, object_id)
    payload = _object(
        object_id,
        kind="runbook",
        data={
            "schema_version": 1,
            "runbook_status": "draft",
            "approval_required": False,
            "applies_to": ["service:preview-concealed"],
        },
    ).model_dump(mode="json")

    preview = _preview(preview_client, preview_state, object_id, payload, if_match=etag)
    applied = preview_client.put(
        f"/api/v1/objects/{object_id}",
        headers={**_auth(preview_state), "If-Match": etag},
        json=payload,
    )

    assert preview.status_code == applied.status_code == 404
    assert preview.json()["error"]["message"] == applied.json()["error"]["message"]
    assert "preview-concealed" not in preview.text


def test_service_update_preserves_an_unchanged_stored_concealed_reference(
    preview_state,
) -> None:
    """The shared planner exempts only the byte-identical stored value."""
    session_factory = preview_state["session_factory"]
    object_id = _kind_object_id("service")
    stored_data = {
        "schema_version": 1,
        "credential": "service:preview-concealed",
    }
    with session_factory() as session:
        with transaction(session):
            row = session.get(CatalogObject, object_id)
            assert row is not None
            row.data_json = json.dumps(stored_data, sort_keys=True)

    payload = _object(
        object_id,
        summary="service-layer change",
        data=stored_data,
    )
    with session_factory() as session:
        target = session.get(CatalogObject, object_id)
        assert target is not None
        seeded_revision = target.revision
        principal = session.get(Principal, preview_state["principal_id"])
        assert principal is not None
        context = WriteContext(
            principal=principal_context(principal),
            policy=policy_for_principal(session, principal.id),
            channel="api",
        )
        preview = preview_catalog_object_update(
            session,
            context,
            object_id=object_id,
            payload=payload,
            expected_revision=seeded_revision,
        )
        assert preview.changed is True
        assert [entry.path for entry in preview.diff] == ["/summary"]

    with session_factory() as session:
        with transaction(session):
            principal = session.get(Principal, preview_state["principal_id"])
            assert principal is not None
            context = WriteContext(
                principal=principal_context(principal),
                policy=policy_for_principal(session, principal.id),
                channel="api",
            )
            applied = update_catalog_object(
                session,
                context,
                object_id=object_id,
                payload=payload,
                expected_revision=seeded_revision,
            )
            assert applied.changed is True
            assert applied.catalog_object.revision == seeded_revision + 1
            assert applied.catalog_object.data == stored_data


def test_rest_update_preserves_only_an_unchanged_stored_concealed_reference(
    preview_client: TestClient,
    preview_state,
) -> None:
    session_factory = preview_state["session_factory"]
    object_id = _kind_object_id("service")
    stored_data = {
        "schema_version": 1,
        "credential": "service:preview-concealed",
    }
    with session_factory() as session:
        with transaction(session):
            row = session.get(CatalogObject, object_id)
            assert row is not None
            row.data_json = json.dumps(stored_data, sort_keys=True)

    etag = _etag(preview_client, preview_state, object_id)
    payload = _object(
        object_id,
        summary="REST change",
        data=stored_data,
    ).model_dump(mode="json")
    preview = _preview(
        preview_client,
        preview_state,
        object_id,
        payload,
        if_match=etag,
    )
    applied = preview_client.put(
        f"/api/v1/objects/{object_id}",
        headers={**_auth(preview_state), "If-Match": etag},
        json=payload,
    )

    assert preview.status_code == applied.status_code == 200
    assert preview.json()["expected_result_etag"] == applied.headers["etag"]
    current_etag = applied.headers["etag"]

    def changed_reference(reference: str) -> dict:
        return _object(
            object_id,
            summary="REST change",
            data={"schema_version": 1, "credential": reference},
        ).model_dump(mode="json")

    failures = []
    for reference in ("service:preview-concealed-two", "service:not-present"):
        proposed = changed_reference(reference)
        failures.extend(
            (
                _preview(
                    preview_client,
                    preview_state,
                    object_id,
                    proposed,
                    if_match=current_etag,
                ),
                preview_client.put(
                    f"/api/v1/objects/{object_id}",
                    headers={
                        **_auth(preview_state),
                        "If-Match": current_etag,
                    },
                    json=proposed,
                ),
            )
        )

    assert [response.status_code for response in failures] == [404, 404, 404, 404]
    safe_errors = [
        {
            key: value
            for key, value in response.json()["error"].items()
            if key != "correlation_id"
        }
        for response in failures
    ]
    assert all(error == safe_errors[0] for error in safe_errors[1:])
    serialized = json.dumps(safe_errors)
    assert "preview-concealed-two" not in serialized
    assert "not-present" not in serialized


# ---------------------------------------------------------------------------
# Diff and digest contract
# ---------------------------------------------------------------------------


def test_diff_is_closed_ordered_and_free_of_sensitive_values(
    preview_client: TestClient,
    preview_state,
) -> None:
    session_factory = preview_state["session_factory"]
    object_id = _kind_object_id("service")
    long_value = "y" * (PREVIEW_DIFF_VALUE_MAX_LENGTH + 40)
    with session_factory() as session:
        with transaction(session):
            row = session.get(CatalogObject, object_id)
            assert row is not None
            # A legacy record that already stores secret-shaped state.
            row.data_json = json.dumps(
                {
                    "schema_version": 1,
                    "token": SECRET_MARKER,
                    "note": SECRET_MARKER,
                    "long_field": long_value,
                    "count": 7,
                    "flag": True,
                    "list_field": ["a", "b"],
                }
            )
    etag = _etag(preview_client, preview_state, object_id)
    payload = _object(object_id, summary="cleaned").model_dump(mode="json")

    response = _preview(preview_client, preview_state, object_id, payload, if_match=etag)

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["changed"] is True
    assert body["diff_truncated"] is False
    assert _paths(body) == sorted(_paths(body))

    entries = {entry["path"]: entry for entry in body["diff"]}
    assert set(entries["/data/token"]["before"]) == {"state", "type", "text"}
    assert entries["/data/token"]["before"] == {
        "state": "redacted",
        "type": "string",
        "text": None,
    }
    assert entries["/data/token"]["operation"] == "removed"
    assert entries["/data/token"]["after"] == {
        "state": "absent",
        "type": "absent",
        "text": None,
    }
    assert entries["/data/note"]["before"]["state"] == "redacted"
    assert entries["/data/long_field"]["before"]["state"] == "truncated"
    assert len(entries["/data/long_field"]["before"]["text"]) == PREVIEW_DIFF_VALUE_MAX_LENGTH
    assert entries["/data/count"]["before"] == {
        "state": "value",
        "type": "integer",
        "text": "7",
    }
    assert entries["/data/flag"]["before"]["type"] == "boolean"
    assert entries["/data/list_field"]["before"] == {
        "state": "value",
        "type": "array",
        "text": '["a","b"]',
    }
    assert entries["/summary"]["operation"] == "changed"
    assert SECRET_MARKER not in response.text
    assert REDACTED_SECRET_VALUE not in response.text
    assert long_value not in response.text
    for entry in body["diff"]:
        assert set(entry) == {"path", "path_state", "operation", "before", "after"}
        assert entry["path_state"] == "exact"
        assert entry["operation"] in {"added", "removed", "changed"}


def test_diff_is_bounded_and_reports_its_own_truncation(
    preview_client: TestClient,
    preview_state,
) -> None:
    session_factory = preview_state["session_factory"]
    object_id = _kind_object_id("service")
    overflow = PREVIEW_DIFF_MAX_ENTRIES + 25
    with session_factory() as session:
        with transaction(session):
            row = session.get(CatalogObject, object_id)
            assert row is not None
            row.data_json = json.dumps(
                {
                    "schema_version": 1,
                    **{f"bulk_{index:04d}": index for index in range(overflow)},
                }
            )
    etag = _etag(preview_client, preview_state, object_id)
    payload = _object(object_id, summary="cleaned").model_dump(mode="json")

    body = _preview(
        preview_client,
        preview_state,
        object_id,
        payload,
        if_match=etag,
    ).json()

    assert body["changed"] is True
    assert body["diff_truncated"] is True
    assert len(body["diff"]) == PREVIEW_DIFF_MAX_ENTRIES
    assert _paths(body) == sorted(_paths(body))
    assert _paths(body)[0] == "/data/bulk_0000"
    assert _paths(body)[-1] == f"/data/bulk_{PREVIEW_DIFF_MAX_ENTRIES - 1:04d}"


def test_the_digest_is_stable_versioned_and_domain_separated(
    preview_client: TestClient,
    preview_state,
) -> None:
    object_id = _kind_object_id("service")
    etag = _etag(preview_client, preview_state, object_id)
    payload = _object(object_id, summary="after").model_dump(mode="json")

    first = _preview(preview_client, preview_state, object_id, payload, if_match=etag).json()
    repeated = _preview(
        preview_client,
        preview_state,
        object_id,
        payload,
        if_match=etag,
    ).json()

    assert first == repeated
    assert first["preview_digest"].startswith("sha256:")

    body = {
        "base_etag": first["base_etag"],
        "base_revision": first["base_revision"],
        "changed": first["changed"],
        "preview_contract_version": PREVIEW_CONTRACT_VERSION,
        "diff": first["diff"],
        "diff_digest": first["diff_digest"],
        "diff_truncated": first["diff_truncated"],
        "expected_result_etag": first["expected_result_etag"],
        "expected_result_revision": first["expected_result_revision"],
        "object_id": first["object_id"],
        "object_kind": first["object_kind"],
    }
    assert set(body) == set(first) - {"preview_digest"}
    assert preview_digest(body) == first["preview_digest"]
    assert SECRET_MARKER not in first["preview_digest"]

    # Domain and version separation: the same body under another domain or
    # contract version cannot collide with this digest.
    import hashlib

    from blockwart.domain.update_preview import _canonical_json

    def digest_under(domain: str, version: str) -> str:
        material = (
            domain.encode("ascii")
            + b"\x00"
            + version.encode("ascii")
            + b"\x00"
            + _canonical_json(body).encode("ascii")
        )
        return "sha256:" + hashlib.sha256(material).hexdigest()

    assert digest_under(PREVIEW_DIGEST_DOMAIN, PREVIEW_CONTRACT_VERSION) == (
        first["preview_digest"]
    )
    assert digest_under("blockwart/other-domain", PREVIEW_CONTRACT_VERSION) != (
        first["preview_digest"]
    )
    assert digest_under(PREVIEW_DIGEST_DOMAIN, "2") != first["preview_digest"]
    # The plain body without domain separation is also not the digest.
    assert (
        "sha256:" + hashlib.sha256(_canonical_json(body).encode("ascii")).hexdigest()
        != first["preview_digest"]
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("summary", "another summary"),
        ("label", "another label"),
    ],
)
def test_every_safe_semantic_preview_change_changes_the_digest(
    preview_client: TestClient,
    preview_state,
    field: str,
    value: str,
) -> None:
    object_id = _kind_object_id("service")
    etag = _etag(preview_client, preview_state, object_id)
    base_payload = _object(object_id, summary="after").model_dump(mode="json")
    changed_payload = {**base_payload, field: value}

    base = _preview(
        preview_client,
        preview_state,
        object_id,
        base_payload,
        if_match=etag,
    ).json()
    changed = _preview(
        preview_client,
        preview_state,
        object_id,
        changed_payload,
        if_match=etag,
    ).json()

    assert base["preview_digest"] != changed["preview_digest"]


def test_the_digest_never_distinguishes_two_redacted_values(
    preview_client: TestClient,
    preview_state,
) -> None:
    """The digest covers the safe contract only, so it is not a secret oracle."""
    session_factory = preview_state["session_factory"]
    object_id = _kind_object_id("service")
    digests = []
    for stored_secret in (
        "ghp_aaaaaaaaaaaaaaaaaaaaaaaaa",
        "ghp_bbbbbbbbbbbbbbbbbbbbbbbbb",
    ):
        with session_factory() as session:
            with transaction(session):
                row = session.get(CatalogObject, object_id)
                assert row is not None
                row.data_json = json.dumps(
                    {"schema_version": 1, "secret": stored_secret}
                )
        etag = _etag(preview_client, preview_state, object_id)
        body = _preview(
            preview_client,
            preview_state,
            object_id,
            _object(object_id, summary="cleaned").model_dump(mode="json"),
            if_match=etag,
        ).json()
        digests.append(body["preview_digest"])
        assert stored_secret not in json.dumps(body)

    assert digests[0] == digests[1]


def test_digest_covers_safe_value_suffixes_and_changes_omitted_from_the_diff(
    preview_client: TestClient,
    preview_state,
) -> None:
    object_id = _kind_object_id("service")
    etag = _etag(preview_client, preview_state, object_id)
    common_prefix = "v" * PREVIEW_DIFF_VALUE_MAX_LENGTH
    first_long = _object(
        object_id,
        data={"schema_version": 1, "long": common_prefix + "-one"},
    ).model_dump(mode="json")
    second_long = _object(
        object_id,
        data={"schema_version": 1, "long": common_prefix + "-two"},
    ).model_dump(mode="json")

    first = _preview(
        preview_client,
        preview_state,
        object_id,
        first_long,
        if_match=etag,
    ).json()
    second = _preview(
        preview_client,
        preview_state,
        object_id,
        second_long,
        if_match=etag,
    ).json()

    assert first["diff"] == second["diff"]
    assert first["diff_digest"] != second["diff_digest"]
    assert first["preview_digest"] != second["preview_digest"]

    overflow = PREVIEW_DIFF_MAX_ENTRIES + 2
    with preview_state["session_factory"]() as session:
        with transaction(session):
            row = session.get(CatalogObject, object_id)
            assert row is not None
            row.data_json = json.dumps(
                {
                    "schema_version": 1,
                    **{f"bulk_{index:04d}": index for index in range(overflow)},
                }
            )
    etag = _etag(preview_client, preview_state, object_id)
    remove_all = _object(object_id).model_dump(mode="json")
    change_last = _object(
        object_id,
        data={"schema_version": 1, f"bulk_{overflow - 1:04d}": -1},
    ).model_dump(mode="json")
    removed = _preview(
        preview_client,
        preview_state,
        object_id,
        remove_all,
        if_match=etag,
    ).json()
    changed = _preview(
        preview_client,
        preview_state,
        object_id,
        change_last,
        if_match=etag,
    ).json()

    assert removed["diff_truncated"] is changed["diff_truncated"] is True
    assert removed["diff"] == changed["diff"]
    assert removed["diff_digest"] != changed["diff_digest"]
    assert removed["preview_digest"] != changed["preview_digest"]


def test_diff_paths_are_unambiguous_canonical_json_pointers(
    preview_client: TestClient,
    preview_state,
) -> None:
    object_id = _kind_object_id("service")
    etag = _etag(preview_client, preview_state, object_id)
    flat = _preview(
        preview_client,
        preview_state,
        object_id,
        _object(
            object_id,
            data={"schema_version": 1, "a.b/c~d": "value"},
        ).model_dump(mode="json"),
        if_match=etag,
    ).json()
    nested = _preview(
        preview_client,
        preview_state,
        object_id,
        _object(
            object_id,
            data={"schema_version": 1, "a.b": {"c~d": "value"}},
        ).model_dump(mode="json"),
        if_match=etag,
    ).json()

    assert "/data/a.b~1c~0d" in _paths(flat)
    assert "/data/a.b/c~0d" in _paths(nested)
    assert flat["diff_digest"] != nested["diff_digest"]
    assert flat["preview_digest"] != nested["preview_digest"]

    long_key = "long/" + "k" * 600
    bounded = _preview(
        preview_client,
        preview_state,
        object_id,
        _object(
            object_id,
            data={"schema_version": 1, long_key: "value"},
        ).model_dump(mode="json"),
        if_match=etag,
    ).json()
    long_change = next(
        entry for entry in bounded["diff"] if entry["path_state"] == "hashed"
    )
    assert long_change["path"].startswith("/@sha256:")
    assert len(long_change["path"]) < 80
    assert long_key not in json.dumps(bounded)


def test_concealed_missing_and_kind_mismatched_references_are_indistinguishable(
    preview_client: TestClient,
    preview_state,
) -> None:
    object_id = _kind_object_id("service")
    etag = _etag(preview_client, preview_state, object_id)

    def proposed(reference: str) -> dict:
        return _object(
            object_id,
            data={"schema_version": 1, "opaque_reference": reference},
        ).model_dump(mode="json")

    responses = [
        _preview(
            preview_client,
            preview_state,
            object_id,
            proposed(reference),
            if_match=etag,
        )
        for reference in (
            "service:preview-concealed",
            "credential_reference:preview-concealed",
            "service:not-present",
        )
    ]

    assert [response.status_code for response in responses] == [404, 404, 404]
    safe_errors = [
        {
            key: value
            for key, value in response.json()["error"].items()
            if key != "correlation_id"
        }
        for response in responses
    ]
    assert safe_errors[0] == safe_errors[1] == safe_errors[2]
    assert "preview-concealed" not in json.dumps(safe_errors)
    assert "not-present" not in json.dumps(safe_errors)


def test_distinct_caller_supplied_concealed_proposals_bind_distinct_digests(
    preview_client: TestClient,
    preview_state,
) -> None:
    """Compare canonical values first, then redact only the public rendering."""
    session_factory = preview_state["session_factory"]
    object_id = _kind_object_id("service")
    concealed_values = (
        "service:preview-concealed",
        "service:preview-concealed-two",
        "service:preview-concealed-three",
    )
    with session_factory() as session:
        with transaction(session):
            upsert_object(
                session,
                _object("preview-concealed-three", summary="concealed three"),
            )
            row = session.get(CatalogObject, object_id)
            assert row is not None
            row.summary = concealed_values[0]

    etag = _etag(preview_client, preview_state, object_id)
    unchanged = _preview(
        preview_client,
        preview_state,
        object_id,
        _object(object_id, summary=concealed_values[0]).model_dump(mode="json"),
        if_match=etag,
    ).json()
    proposals = [
        _preview(
            preview_client,
            preview_state,
            object_id,
            _object(object_id, summary=value).model_dump(mode="json"),
            if_match=etag,
        ).json()
        for value in concealed_values[1:]
    ]

    assert unchanged["changed"] is False
    assert unchanged["diff"] == []
    assert unchanged["expected_result_etag"] == etag
    assert all(proposal["changed"] is True for proposal in proposals)
    for proposal in proposals:
        assert proposal["diff_truncated"] is False
        assert len(proposal["diff"]) == 1
        entry = proposal["diff"][0]
        assert entry["path"] == "/summary"
        assert entry["before"] == entry["after"] == {
            "state": "redacted",
            "type": "string",
            "text": None,
        }
    assert proposals[0]["diff_digest"] != proposals[1]["diff_digest"]
    assert proposals[0]["preview_digest"] != proposals[1]["preview_digest"]
    serialized = json.dumps([unchanged, *proposals])
    assert all(value not in serialized for value in concealed_values)


def test_diff_digest_preserves_safe_siblings_and_rejects_forgeable_markers() -> None:
    first_diff, _, first_digest = preview_diff(
        {"values": []},
        {"values": ["public-one", REDACTED_PREVIEW_VALUE]},
    )
    second_diff, _, second_digest = preview_diff(
        {"values": []},
        {"values": ["public-two", REDACTED_PREVIEW_VALUE]},
    )
    literal_diff, _, literal_digest = preview_diff(
        {"values": []},
        {"values": ["public-one", REDACTED_SECRET_VALUE]},
    )

    assert first_diff[0].after.as_json() == second_diff[0].after.as_json() == {
        "state": "redacted",
        "type": "array",
        "text": None,
    }
    assert first_digest != second_digest
    assert literal_digest != first_digest
    assert literal_diff[0].after.as_json()["state"] == "value"


# ---------------------------------------------------------------------------
# Read-only proof
# ---------------------------------------------------------------------------


def test_previews_leave_the_catalog_byte_and_row_exact_on_sqlite(
    preview_client: TestClient,
    preview_state,
) -> None:
    session_factory = preview_state["session_factory"]
    object_id = _kind_object_id("service")
    etag = _etag(preview_client, preview_state, object_id)

    with session_factory() as session:
        before = _database_fingerprint(session)
        before_sequences = _sqlite_sequences(session)
        database_path = Path(str(session.get_bind().url.database))
    before_database_bytes = database_path.read_bytes()

    responses = [
        _preview(
            preview_client,
            preview_state,
            object_id,
            _object(object_id, summary="after").model_dump(mode="json"),
            if_match=etag,
        ),
        _preview(
            preview_client,
            preview_state,
            object_id,
            _object(object_id, summary="before").model_dump(mode="json"),
            if_match=etag,
        ),
        _preview(
            preview_client,
            preview_state,
            object_id,
            _object(object_id, summary="after").model_dump(mode="json"),
            if_match='"rev-99"',
        ),
        _preview(
            preview_client,
            preview_state,
            object_id,
            _raw(object_id, data={"schema_version": 1, "password": "x"}),
            if_match=etag,
        ),
        _preview(
            preview_client,
            preview_state,
            "preview-concealed",
            _object("preview-concealed").model_dump(mode="json"),
            if_match=etag,
        ),
        _preview(
            preview_client,
            preview_state,
            "preview-discover-only",
            _object("preview-discover-only").model_dump(mode="json"),
            if_match=etag,
        ),
        _preview(
            preview_client,
            preview_state,
            "preview-read-only",
            _object("preview-read-only").model_dump(mode="json"),
            if_match=etag,
        ),
    ]

    assert [response.status_code for response in responses] == [
        200,
        200,
        412,
        422,
        404,
        403,
        403,
    ]
    with session_factory() as session:
        after = _database_fingerprint(session)
        after_sequences = _sqlite_sequences(session)

    assert after == before
    assert after_sequences == before_sequences
    assert database_path.read_bytes() == before_database_bytes


def test_a_read_only_command_that_staged_a_mutation_fails_closed(
    alembic_session_factory,
) -> None:
    from blockwart.db.session import DatabaseTransactionError, read_only_transaction

    with alembic_session_factory() as session:
        with pytest.raises(DatabaseTransactionError):
            with read_only_transaction(session):
                session.add(
                    CatalogObject(
                        id="never-committed",
                        kind="host",
                        label="Never committed",
                        status="active",
                        data_json="{}",
                        provenance_json="{}",
                    )
                )
    with alembic_session_factory() as session:
        assert session.get(CatalogObject, "never-committed") is None


# ---------------------------------------------------------------------------
# REST/MCP parity
# ---------------------------------------------------------------------------


def test_mcp_preview_tool_publishes_the_reviewed_contract() -> None:
    tool = TOOL_DEFINITIONS["blockwart.preview_object_update"]
    update_tool = TOOL_DEFINITIONS["blockwart.update_object"]

    assert tool["annotations"] == {
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    }
    # The proposed input is exactly the safe full-object update input.
    assert tool["inputSchema"] == update_tool["inputSchema"]


def test_mcp_and_rest_previews_are_byte_identical(
    preview_client: TestClient,
    preview_state,
) -> None:
    object_id = _kind_object_id("service")
    etag = _etag(preview_client, preview_state, object_id)
    proposed = _object(object_id, summary="after").model_dump(mode="json")

    rest = _preview(preview_client, preview_state, object_id, proposed, if_match=etag)

    def requester(method, path, body, headers):
        response = preview_client.request(
            method,
            path,
            json=body,
            headers={**headers, **_auth(preview_state)},
        )
        response.raise_for_status()
        return response.json()

    mcp = call_tool(
        "blockwart.preview_object_update",
        {"object_id": object_id, "if_match": etag, "object": proposed},
        requester=requester,
    )

    assert rest.status_code == 200
    assert json.loads(mcp["content"][0]["text"]) == rest.json()


def test_mcp_preview_forwards_the_exact_upstream_request() -> None:
    calls = []
    proposed = {
        "id": "preview-service",
        "kind": "service",
        "label": "Preview service",
        "data": {"schema_version": 1},
    }

    def requester(method, path, body, headers):
        calls.append((method, path, body, headers))
        return {"changed": False}

    call_tool(
        "blockwart.preview_object_update",
        {"object_id": "preview-service", "if_match": '"rev-2"', "object": proposed},
        requester=requester,
    )

    method, path, body, headers = calls[0]
    assert method == "POST"
    assert path == "/api/v1/objects/preview-service/update-preview"
    assert body == proposed
    assert headers["If-Match"] == '"rev-2"'
    assert headers["X-Blockwart-Channel"] == "mcp"


def test_mcp_preview_publishes_safe_field_accurate_argument_failures() -> None:
    from blockwart.mcp.server import ToolInputError

    with pytest.raises(ToolInputError) as exc_info:
        call_tool(
            "blockwart.preview_object_update",
            {"object_id": "preview-service", "object": {"id": "x", "kind": "service"}},
        )

    details = exc_info.value.details
    assert {detail["location"] for detail in details} >= {"if_match", "object.label"}
    assert all(set(detail) == {"code", "location", "message", "path", "rule"} for detail in details)


def test_mcp_preview_forwards_only_sanitized_upstream_validation_details() -> None:
    upstream = HTTPError(
        "http://127.0.0.1/api/v1/objects/preview-service/update-preview",
        422,
        "Unprocessable Entity",
        {},
        BytesIO(
            json.dumps(
                {
                    "error": {
                        "code": "validation_error",
                        "message": "Request validation failed.",
                        "correlation_id": "preview-proof-1",
                        "details": [
                            {
                                "code": "forbidden_key",
                                "location": "body.data.password",
                                "message": "upstream-only-text",
                                "path": "data.password",
                                "rule": "reject_credential_value_keys",
                                "input": SECRET_MARKER,
                            },
                            {"code": "never_published", "location": "body"},
                        ],
                    }
                }
            ).encode()
        ),
    )

    translated = _translate_http_error(upstream)

    assert isinstance(translated, UpstreamError)
    assert translated.code == "validation_error"
    assert [detail["path"] for detail in translated.details] == ["data.password"]
    assert SECRET_MARKER not in json.dumps(translated.details)
    assert "upstream-only-text" not in json.dumps(translated.details)
