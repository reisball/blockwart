"""Proof for the authorized catalog-wide attention view (#176).

Every fixture is synthetic and documentation-safe. No private inventory count,
endpoint, path, credential, token, or instance mapping is part of this file.
"""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event, func, select
from sqlalchemy.orm import Session

import blockwart.api.routes.v1 as v1_routes
import blockwart.services.attention as attention_service
import blockwart.services.monitoring_registry as monitoring_registry
import blockwart.ui.routes as ui_routes
from blockwart.api.deps import get_session
from blockwart.db.session import transaction
from blockwart.domain.attention import (
    ATTENTION_CATEGORY_VALUES,
    ATTENTION_REASON_VALUES,
    ATTENTION_SEVERITY_VALUES,
    ATTENTION_SIGNAL_STATE_VALUES,
    CATALOG_COVERAGE_REF,
    REASON_SPEC_BY_CODE,
    AttentionCoverageInput,
    AttentionObjectInput,
    attention_contract_projection,
    build_attention_derivation,
)
from blockwart.domain.auth import Permission, PrincipalContext, PrincipalType
from blockwart.domain.monitoring import MonitoringObservation
from blockwart.domain.provenance import CatalogProvenance
from blockwart.domain.source_coverage import (
    SourceEntry,
    SourceMapping,
    SourceSnapshot,
    content_fingerprint,
    source_fingerprint,
)
from blockwart.main import create_app
from blockwart.mcp.server import TOOLS, call_tool
from blockwart.models import (
    AuditEvent,
    CatalogObject,
    ObjectComment,
    ObjectGrant,
    Relationship,
    ServiceCheckLease,
    ServiceObservation,
)
from blockwart.models.source_coverage import SourceEntry as SourceEntryRow
from blockwart.models.source_coverage import (
    SourceEntryMapping as SourceEntryMappingRow,
)
from blockwart.models.source_coverage import SourceSnapshot as SourceSnapshotRow
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services.attention import (
    ATTENTION_ITEM_SIGNAL_STATES,
    AttentionQueryError,
    query_attention_page,
)
from blockwart.services.catalog import upsert_object
from blockwart.services.monitoring import (
    MonitoringSettings,
    record_service_observation,
)
from blockwart.services.pagination import InvalidCursor
from blockwart.services.policy import PolicySnapshot
from blockwart.services.read_access import ReadAccess
from blockwart.services.source_coverage import (
    load_current_snapshot,
    record_source_snapshot,
)

NOW = datetime(2026, 8, 20, 12, 0, tzinfo=UTC)
PAST = "2026-01-01T00:00:00Z"
FUTURE = "2027-01-01T00:00:00Z"


def _access(
    principal_id: str = "reader",
    readable: set[str] | None = None,
    *,
    discoverable: set[str] | None = None,
) -> ReadAccess:
    permissions: dict[str, frozenset[Permission]] = {
        object_id: frozenset({Permission.DISCOVER, Permission.READ})
        for object_id in (readable or set())
    }
    for object_id in discoverable or set():
        permissions.setdefault(object_id, frozenset({Permission.DISCOVER}))
    return ReadAccess(
        principal=PrincipalContext(
            id=principal_id,
            principal_type=PrincipalType.HUMAN,
            login=principal_id,
            display_name=principal_id,
        ),
        policy=PolicySnapshot(
            principal_id=principal_id,
            _permissions=permissions,
            _grants={},
        ),
    )


def _asset(
    object_id: str,
    kind: str = "host",
    *,
    lifecycle: str = "active",
    health: str = "healthy",
    data: dict | None = None,
    provenance: CatalogProvenance | None = None,
    explicitly_unassigned: bool = True,
) -> CatalogObjectIn:
    document = {"schema_version": 1, **(data or {})}
    if kind in {"system", "service"} and explicitly_unassigned:
        document.setdefault(
            "placement",
            {"state": "unassigned", "reason": "Synthetic standalone fixture."},
        )
    payload = {
        "id": object_id,
        "kind": kind,
        "label": object_id.replace("-", " ").title(),
        "lifecycle": lifecycle,
        "health": health,
        "data": document,
    }
    if provenance is not None:
        payload["provenance"] = provenance
    return CatalogObjectIn.model_validate(payload)


def _knowledge(object_id: str, kind: str, *, data: dict) -> CatalogObjectIn:
    return CatalogObjectIn.model_validate(
        {
            "id": object_id,
            "kind": kind,
            "label": object_id.replace("-", " ").title(),
            "data": {"schema_version": 1, **data},
        }
    )


def _active_runbook(object_id: str, **overrides) -> CatalogObjectIn:
    data = {
        "runbook_status": "active",
        "purpose": "Inspect a synthetic service without changing it.",
        "risk_level": "read-only",
        "approval_required": False,
        "prerequisites": [{"id": "access", "description": "Read access exists."}],
        "steps": [
            {
                "id": "inspect",
                "description": "Inspect synthetic state.",
                "expected_effect": "No state changes.",
            }
        ],
        "verification": [
            {
                "id": "verify",
                "description": "Review the synthetic result.",
                "success_expectation": "The result is understood.",
            }
        ],
        "last_verified_at": "2025-12-01T00:00:00Z",
        "review_after": FUTURE,
        **overrides,
    }
    return _knowledge(object_id, "runbook", data=data)


def _endpoint(endpoint_id: str = "web") -> dict:
    return {
        "id": endpoint_id,
        "type": "Web",
        "url": f"https://{endpoint_id}.example.invalid:8443/app",
        "protocol": "https",
        "port": 8443,
        "exposure": "internal",
    }


def _page(session: Session, access: ReadAccess, **kwargs):
    kwargs.setdefault("include_total", True)
    kwargs.setdefault("now", NOW)
    return query_attention_page(session, access, **kwargs)


def _reasons(page) -> list[tuple[str, str]]:
    return [(item.target.ref, item.reason_code) for item in page.items]


def _fingerprint(value: str) -> str:
    return content_fingerprint([value])


def _snapshot(*entries: SourceEntry, collected_at: str = "2026-08-19T09:00:00Z"):
    aggregate = source_fingerprint(
        entry.entry_fingerprint for entry in entries if entry.presence == "present"
    )
    normalized = tuple(replace(entry, source_fingerprint=aggregate) for entry in entries)
    return SourceSnapshot(
        collector="markdown_tools",
        collected_at=collected_at,
        entries=normalized,
    ).with_digest()


def _entry(
    entry_id: str,
    *,
    fingerprint: str | None = None,
    mappings: tuple[SourceMapping, ...] = (),
) -> SourceEntry:
    return SourceEntry(
        source_uri="workspace://INVENTORY.md",
        entry_id=entry_id,
        classification="operational",
        intent="expect_object",
        decision_reason="operational_inventory",
        entry_fingerprint=fingerprint or _fingerprint(entry_id),
        source_fingerprint="0" * 64,
        observed_at="2026-08-19T09:00:00Z",
        presence="present",
        mappings=mappings,
    )


def _mapping(object_id: str, fingerprint: str, *, role: str = "primary") -> SourceMapping:
    return SourceMapping(
        object_id=object_id,
        role=role,  # type: ignore[arg-type]
        imported_entry_fingerprint=fingerprint,
        imported_at="2026-08-19T09:00:00Z",
        verified_at="2026-08-19T09:00:00Z",
    )


def _current_entries(*object_ids: str) -> tuple[SourceEntry, ...]:
    return tuple(
        _entry(
            object_id,
            fingerprint=(fingerprint := _fingerprint(object_id)),
            mappings=(_mapping(object_id, fingerprint),),
        )
        for object_id in object_ids
    )


def _observe(
    session: Session,
    object_id: str,
    *,
    state: str,
    checked_at: datetime,
    error_code: str | None = None,
) -> None:
    row = session.get(CatalogObject, object_id)
    assert row is not None
    result = record_service_observation(
        session,
        object_id=object_id,
        object_instance_id=row.instance_id,
        observation=MonitoringObservation(
            provider="builtin_http",
            state=state,  # type: ignore[arg-type]
            checked_at=checked_at,
            error_code=error_code,  # type: ignore[arg-type]
        ),
        now=checked_at,
        settings=MonitoringSettings(jitter_seconds=0),
    )
    assert result is not None


def test_reason_registry_is_closed_consistent_and_totally_ordered() -> None:
    assert len(set(ATTENTION_REASON_VALUES)) == len(ATTENTION_REASON_VALUES)
    assert set(REASON_SPEC_BY_CODE) == set(ATTENTION_REASON_VALUES)
    assert set(ATTENTION_SIGNAL_STATE_VALUES) == {
        "current",
        "stale",
        "unknown",
        "not_applicable",
    }
    assert ATTENTION_ITEM_SIGNAL_STATES == {"current", "stale", "unknown"}
    for spec in REASON_SPEC_BY_CODE.values():
        assert spec.category in ATTENTION_CATEGORY_VALUES
        assert spec.severity in ATTENTION_SEVERITY_VALUES
        assert spec.signal_state in ATTENTION_ITEM_SIGNAL_STATES
        assert 0 < len(spec.description) <= 512
    assert {spec.category for spec in REASON_SPEC_BY_CODE.values()} == set(
        ATTENTION_CATEGORY_VALUES
    )
    contract = attention_contract_projection()
    assert contract["categories"] == list(ATTENTION_CATEGORY_VALUES)
    assert contract["severities"] == list(ATTENTION_SEVERITY_VALUES)
    assert contract["read_only"] is True
    assert contract["performs_probe_or_source_read"] is False


def test_raw_signal_deduplication_is_independent_of_input_order() -> None:
    candidate = AttentionObjectInput(
        object_id="dedup-target",
        kind="host",
        label="Synthetic dedup target",
        lifecycle="active",
        health="healthy",
        record_state="valid",
        placement_state=None,
        provenance_source_type="manual",
        provenance_observed_at=None,
        provenance_verified_at="2026-08-19T00:00:00Z",
        provenance_stale_after=None,
        data={"schema_version": 1},
    )
    raw = (
        AttentionCoverageInput(
            object_id="dedup-target",
            state="duplicate_mapping",
            observed_at="2026-08-19T00:00:00Z",
        ),
        AttentionCoverageInput(
            object_id="dedup-target",
            state="source_changed_since_import",
            observed_at="2026-08-19T00:00:00Z",
        ),
    )

    forward = build_attention_derivation(
        objects=(candidate,),
        coverage=raw,
        coverage_collected=True,
        now=NOW,
    )
    reverse = build_attention_derivation(
        objects=(candidate,),
        coverage=tuple(reversed(raw)),
        coverage_collected=True,
        now=NOW,
    )

    assert forward.items == reverse.items
    coverage_items = [item for item in forward.items if item.category == "source_coverage"]
    assert len(coverage_items) == 1
    assert coverage_items[0].reason_code == "coverage_import_drift"


def test_lifecycle_unknown_is_contextual_and_manual_states_remain_distinct(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session, transaction(session):
        for object_id, lifecycle, health in (
            ("down", "active", "down"),
            ("degraded", "active", "degraded"),
            ("unknown", "active", "unknown"),
            ("maintenance", "active", "maintenance"),
            ("planned", "planned", "down"),
            ("retired", "retired", "down"),
        ):
            upsert_object(
                session,
                _asset(object_id, lifecycle=lifecycle, health=health),
            )

    access = _access(readable={"down", "degraded", "unknown", "maintenance", "planned", "retired"})
    with alembic_session_factory() as session:
        page = _page(session, access, category="lifecycle")
        warning = _page(session, access, category="lifecycle", severity="warning")
        unknown = _page(
            session,
            access,
            reason_code="lifecycle_health_unknown",
            signal_state="unknown",
        )

    assert _reasons(page) == [
        ("host:down", "lifecycle_health_down"),
        ("host:degraded", "lifecycle_health_degraded"),
        ("host:unknown", "lifecycle_health_unknown"),
        ("host:maintenance", "lifecycle_maintenance"),
    ]
    assert page.summary.total == page.total == 4
    assert _reasons(warning) == [
        ("host:degraded", "lifecycle_health_degraded")
    ]
    assert warning.summary.total == warning.total == 1
    assert warning.summary.by_category["lifecycle"] == 1
    assert sum(warning.summary.by_category.values()) == 1
    assert _reasons(unknown) == [
        ("host:unknown", "lifecycle_health_unknown")
    ]
    assert unknown.summary.total == unknown.total == 1
    assert unknown.summary.by_reason["lifecycle_health_unknown"] == 1
    assert not {"host:planned", "host:retired"} & {
        item.target.ref for item in page.items
    }


def test_monitoring_disabled_pending_stale_maintenance_down_and_check_error(
    alembic_session_factory,
) -> None:
    enabled = {"enabled": True, "interval_seconds": 3600}
    with alembic_session_factory() as session, transaction(session):
        upsert_object(
            session,
            _asset(
                "disabled",
                "service",
                data={"monitoring": {"enabled": False}},
            ),
        )
        for object_id, health, endpoints in (
            ("pending", "healthy", [_endpoint("pending")]),
            ("stale", "healthy", [_endpoint("stale")]),
            ("observed-down", "healthy", [_endpoint("down")]),
            ("check-error", "healthy", [_endpoint("error")]),
            ("maintenance", "maintenance", [_endpoint("maintenance")]),
            ("degraded", "degraded", [_endpoint("degraded")]),
            ("bad-endpoint", "healthy", []),
            (
                "ambiguous-endpoint",
                "healthy",
                [_endpoint("ambiguous-a"), _endpoint("ambiguous-b")],
            ),
        ):
            upsert_object(
                session,
                _asset(
                    object_id,
                    "service",
                    health=health,
                    data={"monitoring": enabled, "endpoints": endpoints},
                ),
            )
        _observe(
            session,
            "stale",
            state="down",
            checked_at=NOW - timedelta(days=1),
            error_code="timeout",
        )
        _observe(
            session,
            "observed-down",
            state="down",
            checked_at=NOW,
            error_code="timeout",
        )
        _observe(
            session,
            "check-error",
            state="check_error",
            checked_at=NOW,
            error_code="policy_denied",
        )
        _observe(
            session,
            "maintenance",
            state="down",
            checked_at=NOW,
            error_code="timeout",
        )
        _observe(session, "degraded", state="healthy", checked_at=NOW)

    ids = {
        "disabled",
        "pending",
        "stale",
        "observed-down",
        "check-error",
        "maintenance",
        "degraded",
        "bad-endpoint",
        "ambiguous-endpoint",
    }
    with alembic_session_factory() as session:
        monitoring = _page(session, _access(readable=ids), category="monitoring")
        endpoint = _page(session, _access(readable=ids), category="endpoint")
        lifecycle = _page(session, _access(readable=ids), category="lifecycle")

    assert _reasons(monitoring) == [
        ("service:observed-down", "monitoring_observed_down"),
        ("service:check-error", "monitoring_check_error"),
        ("service:stale", "monitoring_observation_stale"),
        ("service:ambiguous-endpoint", "monitoring_never_observed"),
        ("service:bad-endpoint", "monitoring_never_observed"),
        ("service:pending", "monitoring_never_observed"),
    ]
    assert ("service:maintenance", "monitoring_observed_down") not in _reasons(monitoring)
    assert all(item.target.object_id != "disabled" for item in monitoring.items)
    assert _reasons(endpoint) == [
        ("service:ambiguous-endpoint", "endpoint_target_unresolved"),
        ("service:bad-endpoint", "endpoint_target_unresolved")
    ]
    assert {
        item.target.object_id: item.detail_code for item in endpoint.items
    } == {
        "ambiguous-endpoint": "ambiguous_endpoints",
        "bad-endpoint": "no_http_endpoint",
    }
    assert _reasons(lifecycle) == [
        ("service:degraded", "lifecycle_health_degraded"),
        ("service:maintenance", "lifecycle_maintenance"),
    ]
    stale = next(item for item in monitoring.items if item.target.object_id == "stale")
    assert (stale.signal_state, stale.detail_code) == ("stale", "down")


def test_corrupt_record_and_malformed_monitoring_keep_separate_safe_diagnostics(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session, transaction(session):
        upsert_object(
            session,
            _asset(
                "malformed",
                "service",
                data={"monitoring": {"enabled": True}, "endpoints": [_endpoint()]},
            ),
        )
        row = session.get(CatalogObject, "malformed")
        assert row is not None
        document = json.loads(row.data_json)
        document["monitoring"] = {
            "enabled": True,
            "interval_seconds": "rejected-value-must-not-escape",
        }
        row.data_json = json.dumps(document, sort_keys=True)

    with alembic_session_factory() as session:
        page = _page(session, _access(readable={"malformed"}))

    assert _reasons(page)[:2] == [
        ("service:malformed", "record_corrupt"),
        ("service:malformed", "monitoring_config_invalid"),
    ]
    serialized = repr(page)
    assert "rejected-value-must-not-escape" not in serialized
    assert all(len(item.description) <= 512 for item in page.items)


def test_provenance_runbook_and_knowledge_states_are_independent_and_deduplicated(
    alembic_session_factory,
) -> None:
    stale_provenance = CatalogProvenance(
        source_type="import",
        source_ref="inventory:synthetic",
        observed_at="2025-01-01T00:00:00Z",
        verified_at="2025-01-02T00:00:00Z",
        stale_after=PAST,
    )
    with alembic_session_factory() as session, transaction(session):
        upsert_object(session, _asset("stale-provenance", provenance=stale_provenance))
        upsert_object(session, _asset("unknown-provenance", provenance=CatalogProvenance()))
        upsert_object(
            session,
            _asset(
                "observed-unverified",
                provenance=CatalogProvenance(
                    source_type="import",
                    source_ref="inventory:synthetic-observed",
                    observed_at="2026-08-19T00:00:00Z",
                ),
            ),
        )
        upsert_object(session, _active_runbook("overdue-runbook", review_after=PAST))
        upsert_object(
            session,
            _knowledge(
                "legacy-runbook",
                "runbook",
                data={"runbook_status": "draft", "approval_required": False},
            ),
        )
        upsert_object(
            session,
            _knowledge(
                "deprecated-runbook",
                "runbook",
                data={"runbook_status": "draft", "approval_required": False},
            ),
        )
        upsert_object(
            session,
            _knowledge("accepted-overdue", "decision", data={"decision_status": "proposed"}),
        )
        upsert_object(
            session,
            _knowledge("accepted-unscheduled", "decision", data={"decision_status": "proposed"}),
        )
        upsert_object(
            session,
            _knowledge("finished-decision", "decision", data={"decision_status": "proposed"}),
        )
        mutations = {
            "legacy-runbook": {
                "schema_version": 1,
                "runbook_status": "active",
                "review_after": PAST,
            },
            "deprecated-runbook": {
                "schema_version": 1,
                "runbook_status": "deprecated",
            },
            "accepted-overdue": {
                "schema_version": 1,
                "decision_status": "accepted",
                "review_after": PAST,
            },
            "accepted-unscheduled": {
                "schema_version": 1,
                "decision_status": "accepted",
            },
            "finished-decision": {
                "schema_version": 1,
                "decision_status": "rejected",
                "review_after": PAST,
            },
        }
        for object_id, document in mutations.items():
            row = session.get(CatalogObject, object_id)
            assert row is not None
            row.data_json = json.dumps(document, sort_keys=True)

    ids = {
        "stale-provenance",
        "unknown-provenance",
        "observed-unverified",
        "overdue-runbook",
        "legacy-runbook",
        "deprecated-runbook",
        "accepted-overdue",
        "accepted-unscheduled",
        "finished-decision",
    }
    access = _access(readable=ids)
    with alembic_session_factory() as session:
        provenance = _page(session, access, category="provenance")
        runbook = _page(session, access, category="runbook")
        knowledge = _page(session, access, category="knowledge")

    assert _reasons(provenance) == [
        ("host:stale-provenance", "provenance_stale"),
        ("decision:accepted-overdue", "provenance_unverified"),
        ("decision:accepted-unscheduled", "provenance_unverified"),
        ("host:observed-unverified", "provenance_unverified"),
        ("host:unknown-provenance", "provenance_unverified"),
        ("runbook:deprecated-runbook", "provenance_unverified"),
        ("runbook:legacy-runbook", "provenance_unverified"),
        ("runbook:overdue-runbook", "provenance_unverified"),
    ]
    assert _reasons(runbook) == [
        ("runbook:legacy-runbook", "runbook_review_overdue"),
        ("runbook:overdue-runbook", "runbook_review_overdue"),
        ("runbook:deprecated-runbook", "runbook_deprecated_unresolved"),
    ]
    assert not any(
        item.target.object_id == "legacy-runbook"
        and item.reason_code == "runbook_unverified"
        for item in runbook.items
    )
    assert _reasons(knowledge) == [
        ("decision:accepted-overdue", "knowledge_review_overdue"),
        ("decision:accepted-unscheduled", "knowledge_review_unscheduled"),
    ]


def test_critical_service_runbook_readiness_is_explicit_authorized_and_correctable(
    alembic_session_factory,
) -> None:
    services = {
        "missing",
        "covered-data",
        "covered-edge",
        "draft-only",
        "hidden-only",
        "standard",
        "planned",
        "retired",
    }
    with alembic_session_factory() as session, transaction(session):
        for object_id in services:
            lifecycle = (
                "planned"
                if object_id == "planned"
                else "retired"
                if object_id == "retired"
                else "active"
            )
            criticality = "standard" if object_id == "standard" else "critical"
            upsert_object(
                session,
                _asset(
                    object_id,
                    "service",
                    lifecycle=lifecycle,
                    data={"criticality": criticality},
                ),
            )
        upsert_object(
            session,
            _active_runbook("data-book", applies_to=["service:covered-data"]),
        )
        upsert_object(session, _active_runbook("edge-book"))
        upsert_object(
            session,
            _knowledge(
                "draft-book",
                "runbook",
                data={
                    "runbook_status": "draft",
                    "approval_required": False,
                    "applies_to": ["service:draft-only"],
                },
            ),
        )
        upsert_object(
            session,
            _active_runbook("hidden-book", applies_to=["service:hidden-only"]),
        )
        session.add(
            Relationship(
                from_ref="runbook:edge-book",
                relation_type="documents",
                to_ref="service:covered-edge",
            )
        )

    readable = services | {"data-book", "edge-book", "draft-book"}
    with alembic_session_factory() as session:
        page = _page(session, _access(readable=readable), category="runbook")
    assert {
        item.target.object_id
        for item in page.items
        if item.reason_code == "critical_service_runbook_missing"
    } == {"missing", "draft-only", "hidden-only"}
    assert not {
        "covered-data",
        "covered-edge",
        "standard",
        "planned",
        "retired",
    } & {
        item.target.object_id
        for item in page.items
        if item.reason_code == "critical_service_runbook_missing"
    }

    with alembic_session_factory() as session, transaction(session):
        upsert_object(
            session,
            _active_runbook("correction-book", applies_to=["service:missing"]),
        )
    readable.add("correction-book")
    with alembic_session_factory() as session:
        corrected = _page(session, _access(readable=readable), category="runbook")
    assert not any(
        item.target.object_id == "missing"
        and item.reason_code == "critical_service_runbook_missing"
        for item in corrected.items
    )


def test_relationship_diagnostics_are_redacted_target_bound_deduplicated_and_correctable(
    alembic_session_factory,
) -> None:
    ids = {
        "dangling-book",
        "mismatch-book",
        "actual-host",
        "primary-device",
        "primary-a",
        "primary-b",
        "placement-service",
        "placement-host",
        "domain-host",
        "domain-service",
    }
    with alembic_session_factory() as session, transaction(session):
        upsert_object(session, _active_runbook("dangling-book"))
        upsert_object(session, _active_runbook("mismatch-book"))
        upsert_object(session, _asset("actual-host"))
        upsert_object(
            session,
            _asset(
                "primary-device",
                "device",
                data={"device": {"category": "sensor"}},
            ),
        )
        upsert_object(session, _asset("primary-a", "system"))
        upsert_object(session, _asset("primary-b", "system"))
        upsert_object(session, _asset("placement-service", "service"))
        upsert_object(session, _asset("placement-host"))
        upsert_object(session, _asset("domain-host"))
        upsert_object(session, _asset("domain-service", "service"))
        for object_id, applies_to in (
            ("dangling-book", ["service:missing-service"]),
            (
                "mismatch-book",
                ["service:actual-host", "service:actual-host"],
            ),
        ):
            row = session.get(CatalogObject, object_id)
            assert row is not None
            data = json.loads(row.data_json)
            data["applies_to"] = applies_to
            row.data_json = json.dumps(data, sort_keys=True)
        session.add_all(
            [
                Relationship(
                    from_ref="device:primary-device",
                    relation_type="attached_to",
                    to_ref=f"system:{target}",
                    metadata_json='{"primary":true}',
                )
                for target in ("primary-a", "primary-b")
            ]
        )
        session.add(
            Relationship(
                from_ref="service:placement-service",
                relation_type="hosts",
                to_ref="host:placement-host",
            )
        )
        session.add(
            Relationship(
                from_ref="host:domain-host",
                relation_type="supports",
                to_ref="service:domain-service",
            )
        )

    access = _access(readable=ids | {"missing-service"})
    with alembic_session_factory() as session:
        relationship_page = _page(
            session,
            access,
            category="relationship_integrity",
        )
        placement_page = _page(session, access, category="placement")
    assert _reasons(relationship_page) == [
        ("runbook:dangling-book", "relationship_target_unresolved"),
        ("device:primary-device", "relationship_primary_ambiguous"),
        ("runbook:mismatch-book", "knowledge_relationship_invalid"),
        ("host:domain-host", "relationship_domain_invalid"),
    ]
    assert _reasons(placement_page) == [
        ("service:placement-service", "placement_relationship_invalid")
    ]
    assert sum(
        item.target.object_id == "mismatch-book"
        for item in relationship_page.items
    ) == 1
    serialized = repr((relationship_page, placement_page))
    assert "missing-service" not in serialized
    assert "service:actual-host" not in serialized

    with alembic_session_factory() as session, transaction(session):
        for object_id in ("dangling-book", "mismatch-book"):
            row = session.get(CatalogObject, object_id)
            assert row is not None
            data = json.loads(row.data_json)
            data.pop("applies_to", None)
            row.data_json = json.dumps(data, sort_keys=True)
        for row in session.scalars(select(Relationship)).all():
            session.delete(row)
    with alembic_session_factory() as session:
        corrected_relationships = _page(
            session,
            access,
            category="relationship_integrity",
        )
        corrected_placement = _page(session, access, category="placement")
    assert corrected_relationships.items == []
    assert corrected_placement.items == []


def test_coverage_not_collected_drift_ambiguity_and_resolution_after_correction(
    alembic_session_factory,
) -> None:
    ids = {"drift", "amb-a", "amb-b", "duplicate", "clean"}
    with alembic_session_factory() as session, transaction(session):
        for object_id in ids:
            upsert_object(session, _asset(object_id))

    access = _access(readable=ids)
    with alembic_session_factory() as session:
        missing = _page(session, access, category="source_coverage")
    assert _reasons(missing) == [
        (CATALOG_COVERAGE_REF, "coverage_not_collected")
    ]
    assert missing.summary.coverage_snapshot_state == "not_collected"
    assert missing.summary.signals["source_coverage"].state == "unknown"
    assert missing.items[0].target.detail_path == "/attention?category=source_coverage"

    drift_fp = _fingerprint("drift-current")
    amb_fp = _fingerprint("ambiguous")
    dup_one_fp = _fingerprint("duplicate-one")
    dup_two_fp = _fingerprint("duplicate-two")
    clean_fp = _fingerprint("clean")
    with alembic_session_factory() as session, transaction(session):
        record_source_snapshot(
            session,
            _snapshot(
                _entry(
                    "drift",
                    fingerprint=drift_fp,
                    mappings=(_mapping("drift", _fingerprint("drift-old")),),
                ),
                _entry(
                    "ambiguous",
                    fingerprint=amb_fp,
                    mappings=(
                        _mapping("amb-a", amb_fp),
                        _mapping("amb-b", amb_fp),
                    ),
                ),
                _entry(
                    "duplicate-one",
                    fingerprint=dup_one_fp,
                    mappings=(_mapping("duplicate", dup_one_fp),),
                ),
                _entry(
                    "duplicate-two",
                    fingerprint=dup_two_fp,
                    mappings=(_mapping("duplicate", dup_two_fp),),
                ),
                _entry(
                    "clean",
                    fingerprint=clean_fp,
                    mappings=(_mapping("clean", clean_fp),),
                ),
                _entry("source-only-gap"),
            ),
        )

    with alembic_session_factory() as session:
        drift = _page(session, access, category="source_coverage")
    assert _reasons(drift) == [
        ("host:drift", "coverage_import_drift"),
        ("host:amb-a", "coverage_mapping_ambiguous"),
        ("host:amb-b", "coverage_mapping_ambiguous"),
        ("host:duplicate", "coverage_mapping_ambiguous"),
    ]
    assert drift.summary.coverage_snapshot_state == "collected"
    assert "source-only-gap" not in json.dumps(_reasons(drift))

    with alembic_session_factory() as session, transaction(session):
        record_source_snapshot(
            session,
            _snapshot(
                *_current_entries(*sorted(ids)),
                _entry("source-only-gap"),
                collected_at="2026-08-20T13:00:00Z",
            ),
        )
    with alembic_session_factory() as session:
        corrected = _page(session, access, category="source_coverage")
    assert corrected.items == []
    assert corrected.summary.total == corrected.total == 0
    assert corrected.summary.coverage_snapshot_state == "collected"
    assert corrected.summary.signals["source_coverage"].state == "current"


def test_summary_pagination_order_and_cursor_invalidation_are_bound_to_authorized_view(
    alembic_session_factory,
) -> None:
    ids = {"alpha", "bravo", "charlie"}
    with alembic_session_factory() as session, transaction(session):
        for object_id in ids:
            upsert_object(session, _asset(object_id, health="down"))
        record_source_snapshot(session, _snapshot(*_current_entries(*sorted(ids))))

    access = _access(readable=ids)
    with alembic_session_factory() as session:
        first = _page(session, access, category="lifecycle", limit=1)
        second = _page(
            session,
            access,
            category="lifecycle",
            limit=1,
            cursor=first.next_cursor,
        )
        reverse = _page(
            session,
            access,
            category="lifecycle",
            limit=3,
            direction="desc",
        )
        assert first.summary.total == first.total == second.total == 3
        assert [first.items[0].target.ref, second.items[0].target.ref] == [
            "host:alpha",
            "host:bravo",
        ]
        assert [item.target.ref for item in reverse.items] == [
            "host:charlie",
            "host:bravo",
            "host:alpha",
        ]
        empty_kind = _page(session, access, kind="service")
        assert empty_kind.summary.total == empty_kind.total == 0
        assert empty_kind.summary.signals["lifecycle"].evaluated == 0
        assert empty_kind.summary.coverage_snapshot_state == "not_collected"
        for changed in (
            {"limit": 2},
            {"severity": "critical"},
            {"direction": "desc"},
        ):
            with pytest.raises(InvalidCursor):
                _page(
                    session,
                    access,
                    category="lifecycle",
                    cursor=first.next_cursor,
                    **changed,
                )
        with pytest.raises(InvalidCursor):
            _page(
                session,
                _access("other", readable=ids),
                category="lifecycle",
                limit=1,
                cursor=first.next_cursor,
            )

    with alembic_session_factory() as session, transaction(session):
        upsert_object(session, _asset("concealed-new", health="down"))
    with alembic_session_factory() as session:
        unchanged = _page(
            session,
            access,
            category="lifecycle",
            limit=1,
            cursor=first.next_cursor,
        )
    assert unchanged.items[0].target.ref == "host:bravo"

    with alembic_session_factory() as session, transaction(session):
        upsert_object(session, _asset("alpha", health="healthy"))
    with alembic_session_factory() as session, pytest.raises(InvalidCursor):
        _page(
            session,
            access,
            category="lifecycle",
            limit=1,
            cursor=first.next_cursor,
        )


def test_concealed_objects_mappings_and_discover_stubs_are_observationally_absent(
    alembic_database,
    alembic_session_factory,
) -> None:
    visible_fp = _fingerprint("visible")
    hidden_fp = _fingerprint("hidden-new")
    stub_fp = _fingerprint("stub-new")
    with alembic_session_factory() as session, transaction(session):
        upsert_object(
            session,
            _asset("visible", health="down", provenance=CatalogProvenance()),
        )
        upsert_object(session, _asset("hidden", health="down"))
        upsert_object(session, _asset("stub", health="down"))
        session.add(
            Relationship(
                from_ref="host:visible",
                relation_type="related_to",
                to_ref="host:hidden",
            )
        )
        record_source_snapshot(
            session,
            _snapshot(
                _entry(
                    "visible",
                    fingerprint=visible_fp,
                    mappings=(_mapping("visible", visible_fp),),
                ),
                _entry(
                    "hidden",
                    fingerprint=hidden_fp,
                    mappings=(_mapping("hidden", _fingerprint("hidden-old")),),
                ),
                _entry(
                    "stub",
                    fingerprint=stub_fp,
                    mappings=(_mapping("stub", _fingerprint("stub-old")),),
                ),
            ),
        )

    access = _access(readable={"visible"}, discoverable={"stub"})

    def read_and_count():
        statements: list[str] = []

        def count_selects(_conn, _cursor, statement, _parameters, _context, _executemany):
            if statement.lstrip().upper().startswith("SELECT"):
                statements.append(statement)

        event.listen(alembic_database.engine, "before_cursor_execute", count_selects)
        try:
            with alembic_session_factory() as session:
                page = _page(session, access, limit=1)
        finally:
            event.remove(alembic_database.engine, "before_cursor_execute", count_selects)
        return page, len(statements)

    before, before_queries = read_and_count()
    assert before.summary.total == before.total == 2
    assert before.next_cursor is not None
    assert {item.target.object_id for item in before.items if item.target.object_id} == {
        "visible"
    }

    with alembic_session_factory() as session, transaction(session):
        snapshot = load_current_snapshot(session)
        assert snapshot is not None
        hidden_only_change = tuple(
            replace(
                entry,
                mappings=(
                    *entry.mappings,
                    _mapping("hidden", entry.entry_fingerprint, role="derived"),
                ),
            )
            if entry.entry_id == "visible"
            else entry
            for entry in snapshot.entries
        )
        record_source_snapshot(
            session,
            _snapshot(
                *hidden_only_change,
                collected_at="2026-08-20T13:00:00Z",
            ),
        )

    refreshed, refreshed_queries = read_and_count()
    assert refreshed.summary == before.summary
    assert refreshed.items == before.items
    assert refreshed.next_cursor == before.next_cursor
    assert refreshed.total == before.total
    assert refreshed_queries == before_queries

    with alembic_session_factory() as session, transaction(session):
        for object_id in ("hidden", "stub"):
            row = session.get(CatalogObject, object_id)
            assert row is not None
            session.delete(row)

    after, after_queries = read_and_count()
    assert after.summary == refreshed.summary
    assert after.items == refreshed.items
    assert after.next_cursor == refreshed.next_cursor
    assert after.total == refreshed.total
    assert after_queries == refreshed_queries


def test_query_count_is_constant_below_the_existing_coverage_batch_bound(
    alembic_database,
    alembic_session_factory,
) -> None:
    object_ids = [f"budget-{index:02d}" for index in range(30)]
    with alembic_session_factory() as session, transaction(session):
        for object_id in object_ids:
            upsert_object(session, _asset(object_id, health="unknown"))
        record_source_snapshot(session, _snapshot(*_current_entries(*object_ids)))

    def select_count(readable: set[str]) -> int:
        count = 0

        def listener(_conn, _cursor, statement, _parameters, _context, _executemany):
            nonlocal count
            if statement.lstrip().upper().startswith("SELECT"):
                count += 1

        event.listen(alembic_database.engine, "before_cursor_execute", listener)
        try:
            with alembic_session_factory() as session:
                _page(session, _access(readable=readable))
        finally:
            event.remove(alembic_database.engine, "before_cursor_execute", listener)
        return count

    single_count = select_count({object_ids[0]})
    assert single_count == select_count(set(object_ids))
    assert single_count <= 12


def test_attention_read_performs_no_write_file_read_or_acquisition(
    alembic_session_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with alembic_session_factory() as session, transaction(session):
        upsert_object(
            session,
            _asset(
                "read-only",
                "service",
                health="down",
                data={"monitoring": {"enabled": True}, "endpoints": [_endpoint()]},
            ),
        )
        record_source_snapshot(
            session,
            _snapshot(*_current_entries("read-only")),
        )

    models = (
        CatalogObject,
        AuditEvent,
        ObjectComment,
        ObjectGrant,
        Relationship,
        SourceSnapshotRow,
        SourceEntryRow,
        SourceEntryMappingRow,
        ServiceObservation,
        ServiceCheckLease,
    )

    def counts(session: Session) -> tuple[int, ...]:
        return tuple(
            int(session.scalar(select(func.count()).select_from(model)) or 0)
            for model in models
        )

    monkeypatch.setattr(
        Path,
        "read_text",
        lambda *_args, **_kwargs: pytest.fail("attention read opened a source file"),
    )
    monkeypatch.setattr(
        monitoring_registry,
        "get_provider",
        lambda *_args, **_kwargs: pytest.fail("attention read invoked acquisition"),
    )
    with alembic_session_factory() as session:
        before = counts(session)
        page = _page(session, _access(readable={"read-only"}))
        after = counts(session)
        assert not session.new and not session.dirty and not session.deleted

    assert before == after
    assert page.summary.total == page.total


def test_rest_ui_and_mcp_share_the_application_resolver_and_closed_contract(
    alembic_session_factory,
    install_unrestricted_read_access,
) -> None:
    with alembic_session_factory() as session, transaction(session):
        upsert_object(session, _asset("surface-down", health="down"))
        record_source_snapshot(
            session,
            _snapshot(*_current_entries("surface-down")),
        )

    app = create_app()
    install_unrestricted_read_access(app)

    def session_dependency():
        with alembic_session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = session_dependency
    with TestClient(app) as client:
        rest_response = client.get(
            "/api/v1/attention",
            params={"include_total": "true", "category": "lifecycle"},
        )

        requested_paths: list[str] = []

        def fetch(path: str, params: dict) -> dict:
            requested_paths.append(path)
            response = client.get(
                path,
                params={key: value for key, value in params.items() if value is not None},
            )
            response.raise_for_status()
            return response.json()

        mcp_result = call_tool(
            "blockwart.get_attention",
            {"include_total": True, "category": "lifecycle"},
            fetcher=fetch,
        )
        english = client.get("/attention?category=lifecycle&lang=en")
        german = client.get("/attention?category=lifecycle&lang=de")
        index = client.get("/?lang=en")

    assert rest_response.status_code == 200
    rest = rest_response.json()
    mcp = json.loads(mcp_result["content"][0]["text"])
    assert requested_paths == ["/api/v1/attention"]
    assert {key: value for key, value in mcp.items() if key != "generated_at"} == {
        key: value for key, value in rest.items() if key != "generated_at"
    }
    assert rest["items"][0]["reason_code"] == "lifecycle_health_down"
    assert set(rest["summary"]["signals"]) == set(ATTENTION_CATEGORY_VALUES)
    assert set(rest["summary"]["by_severity"]) == set(ATTENTION_SEVERITY_VALUES)
    assert set(rest["summary"]["by_reason"]) == set(ATTENTION_REASON_VALUES)
    assert english.status_code == german.status_code == 200
    assert "Recorded health down" in english.text
    assert "Erfasster Zustand ausgefallen" in german.text
    assert 'href="/attention"' in index.text
    assert v1_routes.query_attention_page is attention_service.query_attention_page
    assert ui_routes.query_attention_page is attention_service.query_attention_page

    tool = next(item for item in TOOLS if item["name"] == "blockwart.get_attention")
    properties = tool["inputSchema"]["properties"]
    assert properties["category"]["enum"] == list(ATTENTION_CATEGORY_VALUES)
    assert properties["severity"]["enum"] == list(ATTENTION_SEVERITY_VALUES)
    assert properties["reason_code"]["enum"] == list(ATTENTION_REASON_VALUES)
    assert tool["annotations"]["readOnlyHint"] is True


def test_empty_filtered_result_and_invalid_application_inputs_are_controlled(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session, transaction(session):
        upsert_object(session, _asset("healthy"))
        record_source_snapshot(session, _snapshot(*_current_entries("healthy")))
    with alembic_session_factory() as session:
        page = _page(session, _access(readable={"healthy"}), severity="critical")
        assert page.items == []
        assert page.summary.total == page.total == 0
        assert all(value == 0 for value in page.summary.by_severity.values())
        with pytest.raises(AttentionQueryError):
            _page(session, _access(readable={"healthy"}), category="private-rule")
        with pytest.raises(AttentionQueryError):
            _page(session, _access(readable={"healthy"}), signal_state="not_applicable")
        with pytest.raises(AttentionQueryError):
            _page(session, _access(readable={"healthy"}), limit=101)
