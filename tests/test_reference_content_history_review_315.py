"""Unclassified history and blind replacement intents cannot expose locators."""
from __future__ import annotations

import json

import pytest
from test_reference_content_boundary import (
    LOCATOR,
    NEW_LOCATOR,
    REF_ID,
    access_for,
    payload_from,
    write_for,
)
from test_reference_content_boundary import (
    boundary_state as boundary_state,
)

from blockwart.db.session import transaction
from blockwart.models import AuditEvent, CatalogObject
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services.activity import query_activity_page
from blockwart.services.commands import update_catalog_object
from blockwart.services.queries import query_catalog_detail


@pytest.mark.parametrize("converted", [False, True])
@pytest.mark.parametrize("shape", ["snapshot", "object_change", "data_change", "scalar", "pointer"])
def test_unclassified_historical_payloads_keep_field_boundary(
    alembic_session_factory, boundary_state, converted, shape,
):
    snapshot = {"id": REF_ID, "data": {"reference": {"path": LOCATOR}}}
    extra = {
        "snapshot": {"before": snapshot},
        "object_change": {"changes": [{"field": "object", "old": snapshot, "new": {},
                                         "value_change": True}]},
        "data_change": {"changes": [{"field": "data", "old": snapshot["data"], "new": {},
                                       "value_change": True}]},
        "scalar": {"before": {"id": REF_ID, "data": LOCATOR}},
        "pointer": {"changes": [{"field": "/data/reference/path", "old": LOCATOR,
                                   "new": NEW_LOCATOR, "value_change": True}]},
    }[shape]
    with alembic_session_factory() as session, transaction(session):
        session.add(AuditEvent(object_id=REF_ID, action="update", actor="legacy", summary="update",
                               details_json=json.dumps({"event": "update", "version": 1, **extra})))
        session.flush()
        if converted:
            row = session.get(CatalogObject, REF_ID)
            update_catalog_object(
                session, write_for(session, boundary_state, "owner"), object_id=REF_ID,
                payload=CatalogObjectIn(id=REF_ID, kind="service", label="Converted",
                                        data={"schema_version": 1}), expected_revision=row.revision,
            )
        viewer = access_for(session, boundary_state, "viewer")
        history = query_catalog_detail(session, REF_ID, viewer).audit_events
        activity = query_activity_page(session, viewer, object_id=REF_ID)
        assert LOCATOR not in json.dumps(history)
        assert LOCATOR not in str(activity)
        owner_history = query_catalog_detail(
            session, REF_ID, access_for(session, boundary_state, "owner"),
        ).audit_events
        assert LOCATOR in json.dumps(owner_history)


def test_blind_update_history_and_activity_conceal_equality_and_shape(
    alembic_session_factory, boundary_state,
):
    with alembic_session_factory() as session, transaction(session):
        row = session.get(CatalogObject, REF_ID)
        reference = json.loads(row.data_json)["reference"]
        observed = []
        proposals = (reference, {"name": NEW_LOCATOR}, {"path": NEW_LOCATOR, "key": "other"}, {})
        for proposal in proposals:
            update_catalog_object(
                session, write_for(session, boundary_state, "writer"), object_id=REF_ID,
                payload=payload_from(session, reference=proposal), expected_revision=row.revision,
            )
            viewer = access_for(session, boundary_state, "writer")
            history = query_catalog_detail(session, REF_ID, viewer).audit_events
            latest = next(item for item in history if item["action"] == "update")
            activity = query_activity_page(session, viewer, object_id=REF_ID,
                                           event_type="object_revision", limit=1)
            observed.append((latest["summary"], latest["details"]["changes"],
                             activity.items[0].summary))
        assert all(item == observed[0] for item in observed)
        assert observed[0][1] == [{"field": "reference", "value_change": False}]
        # Full-control readers still receive the truthful canonical evidence.
        owner_history = query_catalog_detail(
            session, REF_ID, access_for(session, boundary_state, "owner"),
        ).audit_events
        assert LOCATOR in json.dumps(owner_history)
        assert NEW_LOCATOR in json.dumps(owner_history)
