"""Protected pre-start adoption of legacy ownerless objects (#242).

Every database is a temporary test database. The representative legacy catalog
is written at the historical Alembic baseline without any Owner grant, upgraded
to the packaged head, and then completed with the principals, placements,
relationships, and unrelated grants that a pre-#232 installation could hold.
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import threading
import time
import uuid
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path

import pytest
from alembic import command
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.orm import Session

from blockwart.cli import database as database_cli
from blockwart.config import Settings
from blockwart.db.base import Base
from blockwart.db.migrations import BASELINE_REVISION, build_alembic_config, upgrade_database
from blockwart.db.readiness import DatabaseReadinessError, check_database_readiness
from blockwart.db.session import build_engine, transaction
from blockwart.domain.auth import CatalogRole, GrantScope, Role
from blockwart.models import AuditEvent, CatalogObject, ObjectGrant, Principal, SecurityEvent
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services import legacy_owner_adoption as adoption_module
from blockwart.services.access import create_object_grant
from blockwart.services.audit import load_audit_details
from blockwart.services.catalog import create_relationship, upsert_object
from blockwart.services.commands import CommandPreconditionFailed, WriteContext
from blockwart.services.grant_management import adopt_ownerless_object
from blockwart.services.identity import create_service_account, principal_context
from blockwart.services.legacy_owner_adoption import (
    apply_legacy_owner_adoption,
    validate_adoption_request,
)
from blockwart.services.ownership import INITIAL_OWNER_ALREADY_PRESENT, InitialOwnerError
from blockwart.services.read_access import read_access_for_principal

OWNER_LOGIN = "legacy.catalog.owner"
REASON = "Adopt legacy objects before the first owner-enforcing start"
REQUEST_ID = "legacy-upgrade-0001"
EXPECTED_OWNERLESS = ("legacy-host", "legacy-runbook", "legacy-service", "retired-host")
EXPECTED_BY_KIND = {"host": 2, "runbook": 1, "service": 1}
LEGACY_RAW_OBJECTS = (
    ("legacy-host", "host", "Legacy Host", '{"schema_version":1,"future":{"preserve":true}}'),
    (
        "legacy-runbook",
        "runbook",
        "Legacy Runbook",
        '{"schema_version":1,"steps":["Preserve exactly."]}',
    ),
)
EVIDENCE_TABLES = {"catalog_objects", "object_grants", "audit_events", "security_events"}


def _asset(object_id: str, kind: str = "host") -> CatalogObjectIn:
    return CatalogObjectIn(
        id=object_id,
        kind=kind,
        label=object_id,
        data={"schema_version": 1},
    )


def _build_legacy_database(database_url: str) -> dict[str, str]:
    """Write a pre-#232 catalog: no object in the legacy set has an active Owner."""
    command.upgrade(build_alembic_config(database_url), BASELINE_REVISION)
    raw_engine = create_engine(database_url)
    try:
        with raw_engine.begin() as connection:
            for object_id, kind, label, data_json in LEGACY_RAW_OBJECTS:
                connection.execute(
                    text(
                        "INSERT INTO catalog_objects "
                        "(id, kind, label, status, summary, data_json) "
                        "VALUES (:id, :kind, :label, 'active', :summary, :data_json)"
                    ),
                    {
                        "id": object_id,
                        "kind": kind,
                        "label": label,
                        "summary": "Written before the ownership invariant.",
                        "data_json": data_json,
                    },
                )
    finally:
        raw_engine.dispose()
    upgrade_database(database_url)

    engine = build_engine(database_url)
    try:
        with Session(engine) as session, transaction(session):
            ids = {
                name: create_service_account(
                    session,
                    login=login,
                    display_name=login,
                    catalog_role=catalog_role,
                ).id
                for name, login, catalog_role in (
                    ("catalog_owner", OWNER_LOGIN, CatalogRole.CATALOG_OWNER),
                    ("operator", "legacy.operator", None),
                    ("viewer", "legacy.viewer", None),
                    ("team_owner", "legacy.team.owner", None),
                    ("retired", "legacy.retired", None),
                )
            }
            # The ownerless legacy placement.
            upsert_object(session, _asset("legacy-service", "service"))
            create_relationship(
                session,
                from_ref="host:legacy-host",
                relation_type="hosts",
                to_ref="service:legacy-service",
            )
            # Unrelated non-Owner grants that must survive untouched.
            create_object_grant(
                session,
                principal_id=ids["viewer"],
                object_id="legacy-host",
                role=Role.VIEWER,
                scope=GrantScope.SELF,
            )
            create_object_grant(
                session,
                principal_id=ids["operator"],
                object_id="legacy-runbook",
                role=Role.ACCESS_MANAGER,
                scope=GrantScope.SELF,
            )
            # A healthy subtree: direct Owner on the host, inherited on the service.
            upsert_object(session, _asset("owned-host"))
            upsert_object(session, _asset("owned-service", "service"))
            create_relationship(
                session,
                from_ref="host:owned-host",
                relation_type="hosts",
                to_ref="service:owned-service",
            )
            create_object_grant(
                session,
                principal_id=ids["team_owner"],
                object_id="owned-host",
                role=Role.OWNER,
                scope=GrantScope.SUBTREE,
            )
            # A non-placement edge from the ownerless set into the owned one.
            create_relationship(
                session,
                from_ref="service:legacy-service",
                relation_type="uses",
                to_ref="host:owned-host",
            )
            # An object whose only Owner was later deactivated.
            upsert_object(session, _asset("retired-host"))
            create_object_grant(
                session,
                principal_id=ids["retired"],
                object_id="retired-host",
                role=Role.OWNER,
                scope=GrantScope.SELF,
            )
            retired = session.get(Principal, ids["retired"])
            assert retired is not None
            retired.active = False
    finally:
        engine.dispose()
    return ids


@pytest.fixture(scope="module")
def legacy_template(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, dict[str, str]]:
    path = tmp_path_factory.mktemp("legacy-template") / "legacy.sqlite3"
    ids = _build_legacy_database(f"sqlite:///{path}")
    return path, ids


@pytest.fixture
def legacy(legacy_template, tmp_path: Path) -> tuple[str, dict[str, str]]:
    template, ids = legacy_template
    target = tmp_path / "legacy.sqlite3"
    for suffix in ("", "-wal", "-shm"):
        source = template.with_name(template.name + suffix)
        if source.exists():
            shutil.copyfile(source, target.with_name(target.name + suffix))
    return f"sqlite:///{target}", ids


def _state(database_url: str) -> dict[str, list[tuple]]:
    """Every mapped table, row by row in primary-key order."""
    engine = create_engine(database_url)
    try:
        with engine.connect() as connection:
            return {
                table.name: [
                    tuple(row)
                    for row in connection.execute(
                        select(table).order_by(*table.primary_key.columns)
                    )
                ]
                for table in Base.metadata.sorted_tables
            }
    finally:
        engine.dispose()


def _readiness_code(database_url: str) -> str:
    try:
        check_database_readiness(Settings(database_url=database_url))
    except DatabaseReadinessError as exc:
        return exc.code
    return "ok"


def _adopt_args(
    *,
    apply: bool = False,
    login: str | None = OWNER_LOGIN,
    reason: str | None = REASON,
    digest: str | None = None,
    request_id: str | None = None,
) -> list[str]:
    args = ["--apply"] if apply else []
    args.append("adopt-owners")
    for flag, value in (
        ("--owner-login", login),
        ("--reason", reason),
        ("--expect-plan-digest", digest),
        ("--request-id", request_id),
    ):
        if value is not None:
            args.extend((flag, value))
    return args


def _cli(capsys, database_url: str, args: list[str]) -> tuple[int, str, str]:
    code = database_cli.main(["--database-url", database_url, *args])
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def _summary(output: str) -> dict[str, str]:
    line = output.strip().splitlines()[-1]
    head, *fields = line.split(" ")
    assert head == "database_adopt_owners_ok", output
    return dict(field.split("=", 1) for field in fields)


def _json_lines(output: str, prefix: str) -> list[dict]:
    return [
        json.loads(line[len(prefix) :])
        for line in output.splitlines()
        if line.startswith(prefix)
    ]


def _preview_digest(capsys, database_url: str, login: str = OWNER_LOGIN) -> str:
    code, out, err = _cli(capsys, database_url, _adopt_args(login=login))
    assert code == 0, err
    return _summary(out)["plan_digest"]


def _apply(capsys, database_url: str, digest: str, **kwargs) -> tuple[int, str, str]:
    return _cli(capsys, database_url, _adopt_args(apply=True, digest=digest, **kwargs))


def _write_context(session: Session, principal_id: str) -> WriteContext:
    principal = session.get(Principal, principal_id)
    assert principal is not None
    return WriteContext.from_read_access(
        read_access_for_principal(session, principal_context(principal)),
        channel="ui",
    )


def _objects_without_concurrency_tokens(database_url: str) -> dict[str, dict]:
    engine = create_engine(database_url)
    try:
        with engine.connect() as connection:
            return {
                row["id"]: {
                    key: value
                    for key, value in row.items()
                    if key not in {"revision", "updated_at"}
                }
                for row in connection.execute(select(CatalogObject.__table__)).mappings()
            }
    finally:
        engine.dispose()


# --- acceptance --------------------------------------------------------------


def test_legacy_catalog_stays_non_ready_until_explicit_adoption(legacy, capsys) -> None:
    url, ids = legacy
    assert _readiness_code(url) == "owner_coverage_incomplete"

    before = _state(url)
    code, preview, err = _cli(capsys, url, _adopt_args())
    assert (code, err) == (0, "")
    candidates = _json_lines(preview, "owner_adoption_candidate ")
    assert [item["object_id"] for item in candidates] == list(EXPECTED_OWNERLESS)
    assert candidates[0] == {
        "ref": "host:legacy-host",
        "object_id": "legacy-host",
        "kind": "host",
        "revision": 3,
    }
    summary = _summary(preview)
    assert summary["mode"] == "dry-run"
    assert summary["target_principal_id"] == ids["catalog_owner"]
    assert (summary["ownerless"], summary["adopted"], summary["remaining"]) == ("4", "0", "4")
    assert json.loads(summary["by_kind"]) == EXPECTED_BY_KIND
    assert summary["plan_digest"].startswith("sha256:")
    assert summary["request_id"] == "none"
    # The preview is mutation-free and deterministic.
    assert _state(url) == before
    assert _readiness_code(url) == "owner_coverage_incomplete"
    assert _cli(capsys, url, _adopt_args())[1] == preview

    code, applied, err = _apply(capsys, url, summary["plan_digest"], request_id=REQUEST_ID)
    assert (code, err) == (0, "")
    adopted = _json_lines(applied, "owner_adopted ")
    assert [item["object_id"] for item in adopted] == list(EXPECTED_OWNERLESS)
    assert all(item["new_revision"] == item["old_revision"] + 1 for item in adopted)
    result = _summary(applied)
    assert result["mode"] == "apply"
    assert (result["ownerless"], result["adopted"], result["remaining"]) == ("4", "4", "0")
    assert result["plan_digest"] == summary["plan_digest"]
    assert result["request_id"] == REQUEST_ID
    assert json.loads(result["by_kind"]) == EXPECTED_BY_KIND

    assert _readiness_code(url) == "ok"
    code, out, _err = _cli(capsys, url, ["owners"])
    assert code == 0 and "database_owners_ok" in out
    code, out, err = _cli(capsys, url, ["integrity"])
    assert code == 0 and "diagnostics=0" in out
    assert "owner_integrity_warning" not in err
    database_path = url.removeprefix("sqlite:///")
    with sqlite3.connect(database_path) as connection:
        assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_adoption_preserves_objects_relationships_and_unrelated_grants(legacy, capsys) -> None:
    url, ids = legacy
    before = _state(url)
    objects_before = _objects_without_concurrency_tokens(url)
    digest = _preview_digest(capsys, url)

    assert _apply(capsys, url, digest)[0] == 0
    after = _state(url)

    assert _objects_without_concurrency_tokens(url) == objects_before
    for name in set(before) - EVIDENCE_TABLES:
        assert after[name] == before[name], name
    object_columns = CatalogObject.__table__.columns.keys()
    id_index, revision_index = object_columns.index("id"), object_columns.index("revision")
    old_revisions = {row[id_index]: row[revision_index] for row in before["catalog_objects"]}
    assert {row[id_index]: row[revision_index] for row in after["catalog_objects"]} == {
        object_id: revision + (1 if object_id in EXPECTED_OWNERLESS else 0)
        for object_id, revision in old_revisions.items()
    }

    grants_before = set(before["object_grants"])
    assert grants_before <= set(after["object_grants"])
    columns = ObjectGrant.__table__.columns.keys()
    new_grants = [
        dict(zip(columns, row, strict=True))
        for row in after["object_grants"]
        if row not in grants_before
    ]
    assert sorted(grant["object_id"] for grant in new_grants) == list(EXPECTED_OWNERLESS)
    assert {
        (grant["principal_id"], grant["role"], grant["scope"], grant["created_by_principal_id"])
        for grant in new_grants
    } == {(ids["catalog_owner"], "owner", "self", None)}


def test_adoption_writes_durable_audit_evidence(legacy, capsys) -> None:
    url, ids = legacy
    digest = _preview_digest(capsys, url)
    code, applied, _err = _apply(capsys, url, digest, request_id=REQUEST_ID)
    assert code == 0
    grant_ids = {
        item["object_id"]: item["grant_id"]
        for item in _json_lines(applied, "owner_adopted ")
    }

    with Session(create_engine(url)) as session:
        object_events = session.scalars(
            select(AuditEvent)
            .where(AuditEvent.action == "owner_adopt")
            .order_by(AuditEvent.object_id)
        ).all()
        assert [event.object_id for event in object_events] == list(EXPECTED_OWNERLESS)
        for event in object_events:
            details = load_audit_details(event)
            assert event.actor == "protected_cli"
            assert details["event"] == "owner_adopt"
            assert details["operation"] == "legacy_owner_adoption"
            assert details["actor"] == "protected_cli"
            assert details["channel"] == "cli"
            assert details["request_id"] == REQUEST_ID
            assert details["reason"] == REASON
            assert details["target_principal_id"] == ids["catalog_owner"]
            assert details["target_login"] == OWNER_LOGIN
            assert details["target_catalog_role"] == "catalog_owner"
            assert details["plan_digest"] == digest
            assert details["previous_owner_count"] == 0
            assert details["new_revision"] == details["old_revision"] + 1
            assert details["before"] is None
            assert details["after"] == {
                "grant_id": grant_ids[event.object_id],
                "principal_id": ids["catalog_owner"],
                "object_id": event.object_id,
                "role": "owner",
                "scope": "self",
            }
        retired = next(event for event in object_events if event.object_id == "retired-host")
        assert load_audit_details(retired)["inactive_direct_owner_grants"] == 1

        batch = session.scalars(
            select(AuditEvent).where(AuditEvent.action == "legacy_owner_adoption")
        ).all()
        assert len(batch) == 1 and batch[0].object_id is None
        batch_details = load_audit_details(batch[0])
        assert batch_details["object_ids"] == list(EXPECTED_OWNERLESS)
        assert batch_details["grant_ids"] == [grant_ids[item] for item in EXPECTED_OWNERLESS]
        assert batch_details["counts_by_kind"] == EXPECTED_BY_KIND
        assert batch_details["adopted"] == 4
        assert (batch_details["reason"], batch_details["request_id"]) == (REASON, REQUEST_ID)

        security = session.scalars(
            select(SecurityEvent).where(SecurityEvent.event_type == "legacy_owner_adoption")
        ).all()
        assert len(security) == 1
        assert (security[0].channel, security[0].outcome) == ("cli", "success")
        assert (security[0].principal_id, security[0].request_id) == (
            ids["catalog_owner"],
            REQUEST_ID,
        )
        assert json.loads(security[0].details_json)["adopted"] == 4


def test_rerun_is_an_idempotent_no_op_with_stable_output(legacy, capsys) -> None:
    url, _ids = legacy
    digest = _preview_digest(capsys, url)
    assert _apply(capsys, url, digest, request_id=REQUEST_ID)[0] == 0
    after_first = _state(url)

    code, second, err = _apply(capsys, url, digest, request_id=REQUEST_ID)
    assert (code, err) == (0, "")
    assert _json_lines(second, "owner_adopted ") == []
    summary = _summary(second)
    assert (summary["ownerless"], summary["adopted"], summary["remaining"]) == ("0", "0", "0")
    assert json.loads(summary["by_kind"]) == {}
    assert _state(url) == after_first
    assert _apply(capsys, url, digest, request_id=REQUEST_ID)[1] == second
    # Without an explicit request ID a no-op writes and invents nothing.
    assert _summary(_apply(capsys, url, digest)[1])["request_id"] == "none"
    assert _summary(_cli(capsys, url, _adopt_args())[1])["ownerless"] == "0"
    assert _state(url) == after_first


REJECTIONS = [
    ("missing-login", {"login": None}, "owner_principal_required"),
    ("blank-login", {"login": "   "}, "owner_principal_required"),
    ("malformed-login", {"login": "Not A Login!"}, "owner_principal_malformed"),
    ("unknown-login", {"login": "missing.principal"}, "owner_principal_inactive"),
    ("inactive-login", {"login": "legacy.retired"}, "owner_principal_inactive"),
    ("missing-reason", {"reason": None}, "adoption_reason_required"),
    ("blank-reason", {"reason": "   "}, "adoption_reason_required"),
    ("multiline-reason", {"reason": "first line\nsecond line"}, "adoption_reason_invalid"),
    ("long-reason", {"reason": "x" * 501}, "adoption_reason_invalid"),
    (
        "secret-reason",
        {"reason": "Bearer abcdefghijklmnopqrstuvwxyz0123456789"},
        "adoption_reason_invalid",
    ),
    ("bad-request-id", {"request_id": "not a request id"}, "adoption_request_id_invalid"),
]


@pytest.mark.parametrize("apply", [False, True], ids=["preview", "apply"])
@pytest.mark.parametrize(
    ("overrides", "code"),
    [(overrides, code) for _name, overrides, code in REJECTIONS],
    ids=[name for name, _overrides, _code in REJECTIONS],
)
def test_invalid_requests_are_rejected_without_mutation(
    legacy,
    capsys,
    overrides: dict,
    code: str,
    apply: bool,
) -> None:
    url, _ids = legacy
    digest = _preview_digest(capsys, url) if apply else None
    before = _state(url)

    exit_code, out, err = _cli(
        capsys,
        url,
        _adopt_args(**{"apply": apply, "digest": digest, **overrides}),
    )

    assert (exit_code, out, err.strip()) == (1, "", f"database_adopt_owners_error={code}")
    assert _state(url) == before
    assert _readiness_code(url) == "owner_coverage_incomplete"


@pytest.mark.parametrize(
    ("name", "login"),
    [("operator", "legacy.operator"), ("team_owner", "legacy.team.owner")],
    ids=["no-catalog-role", "owner-grants-only"],
)
def test_any_explicit_active_principal_without_catalog_role_can_be_the_target(
    legacy,
    capsys,
    name: str,
    login: str,
) -> None:
    url, ids = legacy
    before = _state(url)
    # A plan reviewed for one target never applies to another.
    code, _out, err = _apply(capsys, url, _preview_digest(capsys, url), login=login)
    assert (code, err.strip()) == (1, "database_adopt_owners_error=adoption_plan_drift")
    assert _state(url) == before

    digest = _preview_digest(capsys, url, login=login)
    assert _state(url) == before
    code, applied, err = _apply(capsys, url, digest, login=login, request_id=REQUEST_ID)
    assert (code, err) == (0, "")
    summary = _summary(applied)
    assert summary["target_principal_id"] == ids[name]
    assert (summary["adopted"], summary["remaining"]) == ("4", "0")
    assert _readiness_code(url) == "ok"

    engine = create_engine(url)
    try:
        with Session(engine) as session:
            target = session.get(Principal, ids[name])
            assert target is not None and target.active and target.catalog_role is None
            new_owners = session.execute(
                select(ObjectGrant.object_id, ObjectGrant.principal_id, ObjectGrant.scope)
                .where(
                    ObjectGrant.role == Role.OWNER,
                    ObjectGrant.object_id.in_(EXPECTED_OWNERLESS),
                    ObjectGrant.principal_id != ids["retired"],
                )
                .order_by(ObjectGrant.object_id)
            ).all()
            assert [tuple(row) for row in new_owners] == [
                (object_id, ids[name], "self") for object_id in EXPECTED_OWNERLESS
            ]
            for event in session.scalars(
                select(AuditEvent).where(AuditEvent.action == "owner_adopt")
            ):
                details = load_audit_details(event)
                assert details["target_principal_id"] == ids[name]
                assert details["target_login"] == login
                assert details["target_catalog_role"] is None
                assert details["actor"] == "protected_cli"
    finally:
        engine.dispose()

    after = _state(url)
    code, rerun, _err = _apply(capsys, url, digest, login=login, request_id=REQUEST_ID)
    assert code == 0 and _summary(rerun)["adopted"] == "0"
    assert _state(url) == after


def test_apply_requires_the_reviewed_plan_digest(legacy, capsys) -> None:
    url, _ids = legacy
    before = _state(url)
    for digest in (None, "   "):
        code, _out, err = _cli(capsys, url, _adopt_args(apply=True, digest=digest))
        assert (code, err.strip()) == (
            1,
            "database_adopt_owners_error=adoption_plan_digest_required",
        )
    code, _out, err = _apply(capsys, url, "sha256:" + "0" * 64)
    assert (code, err.strip()) == (1, "database_adopt_owners_error=adoption_plan_drift")
    assert _state(url) == before


def test_adopt_owners_requires_the_packaged_schema_head(tmp_path: Path, capsys) -> None:
    url = f"sqlite:///{tmp_path / 'baseline.sqlite3'}"
    command.upgrade(build_alembic_config(url), BASELINE_REVISION)
    for args in (_adopt_args(), _adopt_args(apply=True, digest="sha256:" + "0" * 64)):
        code, out, err = _cli(capsys, url, args)
        assert (code, out, err.strip()) == (1, "", "database_adopt_owners_error=failed")
    with sqlite3.connect(tmp_path / "baseline.sqlite3") as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == (
            BASELINE_REVISION,
        )


# --- drift, atomicity, and concurrency ---------------------------------------


def _drift_adopt_one(session: Session, ids: dict[str, str]) -> None:
    adopt_ownerless_object(
        session,
        _write_context(session, ids["catalog_owner"]),
        object_id="legacy-runbook",
        principal_id=ids["operator"],
        expected_revision=session.get(CatalogObject, "legacy-runbook").revision,
    )


def _drift_unrelated_grant(session: Session, ids: dict[str, str]) -> None:
    create_object_grant(
        session,
        principal_id=ids["viewer"],
        object_id="legacy-service",
        role=Role.VIEWER,
        scope=GrantScope.SELF,
    )


def _drift_new_ownerless_object(session: Session, _ids: dict[str, str]) -> None:
    upsert_object(session, _asset("late-legacy-host"))


def _drift_owner_deactivated(session: Session, ids: dict[str, str]) -> None:
    session.get(Principal, ids["team_owner"]).active = False


def _second_catalog_owner(session: Session) -> None:
    # The database refuses to lose its last active catalog owner.
    create_service_account(
        session,
        login="legacy.second.owner",
        display_name="Second Catalog Owner",
        catalog_role=CatalogRole.CATALOG_OWNER,
    )


def _drift_target_deactivated(session: Session, ids: dict[str, str]) -> None:
    _second_catalog_owner(session)
    session.get(Principal, ids["catalog_owner"]).active = False


@pytest.mark.parametrize(
    ("drift", "code"),
    [
        (_drift_adopt_one, "adoption_plan_drift"),
        (_drift_unrelated_grant, "adoption_plan_drift"),
        (_drift_new_ownerless_object, "adoption_plan_drift"),
        (_drift_owner_deactivated, "adoption_plan_drift"),
        (_drift_target_deactivated, "owner_principal_inactive"),
    ],
    ids=[
        "concurrent-online-adoption",
        "catalog-revision",
        "new-ownerless-object",
        "owner-deactivated",
        "target-deactivated",
    ],
)
def test_apply_fails_closed_on_drift_after_the_preview(legacy, capsys, drift, code) -> None:
    url, ids = legacy
    digest = _preview_digest(capsys, url)
    engine = build_engine(url)
    try:
        with Session(engine) as session, transaction(session):
            drift(session, ids)
    finally:
        engine.dispose()
    before = _state(url)

    exit_code, out, err = _apply(capsys, url, digest)

    assert (exit_code, out, err.strip()) == (1, "", f"database_adopt_owners_error={code}")
    assert _state(url) == before
    if code == "adoption_plan_drift":
        # A fresh preview of the drifted catalog is applied cleanly.
        assert _apply(capsys, url, _preview_digest(capsys, url))[0] == 0
        assert _readiness_code(url) == "ok"


@pytest.mark.parametrize("failure", ["late_audit", "mid_batch_grant"])
def test_a_failure_anywhere_in_apply_leaves_no_partial_mutation(
    legacy,
    capsys,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    url, _ids = legacy
    digest = _preview_digest(capsys, url)
    before = _state(url)
    if failure == "late_audit":

        def fail_security_event(*_args, **_kwargs) -> None:
            raise RuntimeError("injected late failure")

        monkeypatch.setattr(adoption_module, "record_security_event", fail_security_event)
        expected = "failed"
    else:
        original = adoption_module.assign_initial_owner
        calls: list[str] = []

        def fail_third_grant(session: Session, **kwargs):
            calls.append(kwargs["object_id"])
            if len(calls) == 3:
                raise InitialOwnerError(INITIAL_OWNER_ALREADY_PRESENT, "injected")
            return original(session, **kwargs)

        monkeypatch.setattr(adoption_module, "assign_initial_owner", fail_third_grant)
        expected = "adoption_plan_drift"

    exit_code, out, err = _apply(capsys, url, digest)

    assert (exit_code, out, err.strip()) == (1, "", f"database_adopt_owners_error={expected}")
    assert _state(url) == before


def _coordinated_concurrent_applies(
    database_url: str,
    digest: str,
    monkeypatch: pytest.MonkeyPatch,
    competitor,
):
    """Hold the coverage locks in one apply while ``competitor`` starts."""
    first_locked = threading.Event()
    competitor_started = threading.Event()
    original_lock = adoption_module.lock_owner_coverage_state
    lock_calls: list[int] = []
    guard = threading.Lock()

    def coordinated_lock(session: Session, *, extra_principal_ids=()) -> None:
        original_lock(session, extra_principal_ids=extra_principal_ids)
        with guard:
            lock_calls.append(1)
            first = len(lock_calls) == 1
        if first:
            first_locked.set()
            assert competitor_started.wait(timeout=10)
            # Give the competitor time to block on the held writer or row locks.
            time.sleep(0.5)

    monkeypatch.setattr(adoption_module, "lock_owner_coverage_state", coordinated_lock)
    request = validate_adoption_request(
        owner_login=OWNER_LOGIN,
        reason=REASON,
        expected_plan_digest=digest,
        apply=True,
    )

    def apply_once() -> int:
        engine = build_engine(database_url)
        try:
            with Session(engine) as session, transaction(session):
                return len(apply_legacy_owner_adoption(session, request).adopted)
        finally:
            engine.dispose()

    def run_competitor():
        assert first_locked.wait(timeout=10)
        competitor_started.set()
        return competitor(apply_once)

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(apply_once)
        second = pool.submit(run_competitor)
        return first.result(timeout=30), second.result(timeout=30)


def _owner_grant_counts(database_url: str) -> dict[str, int]:
    engine = create_engine(database_url)
    try:
        with Session(engine) as session:
            return dict(
                session.execute(
                    select(ObjectGrant.object_id, func.count(ObjectGrant.id))
                    .where(ObjectGrant.role == Role.OWNER)
                    .group_by(ObjectGrant.object_id)
                ).all()
            )
    finally:
        engine.dispose()


def test_sqlite_concurrent_applies_serialize_to_one_repair(
    legacy,
    capsys,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    url, _ids = legacy
    digest = _preview_digest(capsys, url)

    first, second = _coordinated_concurrent_applies(
        url,
        digest,
        monkeypatch,
        lambda apply_once: apply_once(),
    )

    assert (first, second) == (4, 0)
    counts = _owner_grant_counts(url)
    # retired-host keeps its inactive historical Owner grant next to the new one.
    assert {object_id: counts[object_id] for object_id in EXPECTED_OWNERLESS} == {
        "legacy-host": 1,
        "legacy-runbook": 1,
        "legacy-service": 1,
        "retired-host": 2,
    }
    assert _readiness_code(url) == "ok"


# --- PostgreSQL ----------------------------------------------------------------

PG_TEST_URL = os.environ.get(
    "BLOCKWART_TEST_PG_URL",
    "postgresql+psycopg2://postgres:test@127.0.0.1:5432/blockwart_test",
)


def _pg_url(database: str) -> str:
    return PG_TEST_URL.rsplit("/", 1)[0] + f"/{database}"


def _pg_available() -> bool:
    try:
        engine = create_engine(_pg_url("postgres"))
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        engine.dispose()
    except Exception:  # noqa: BLE001 - any connection failure means "skip"
        return False
    return True


requires_postgresql = pytest.mark.skipif(
    not _pg_available(),
    reason="PostgreSQL test database unreachable",
)


@contextmanager
def _pg_database(prefix: str) -> Iterator[str]:
    name = f"{prefix}_{uuid.uuid4().hex[:12]}"
    admin = create_engine(_pg_url("postgres"), isolation_level="AUTOCOMMIT")
    with admin.connect() as connection:
        connection.execute(text(f'CREATE DATABASE "{name}"'))
    try:
        yield _pg_url(name)
    finally:
        with admin.connect() as connection:
            connection.execute(
                text(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                    "WHERE datname = :name AND pid <> pg_backend_pid()"
                ),
                {"name": name},
            )
            connection.execute(text(f'DROP DATABASE IF EXISTS "{name}"'))
        admin.dispose()


@requires_postgresql
def test_postgresql_legacy_upgrade_preview_drift_apply_and_rerun(capsys) -> None:
    with _pg_database("bw_legacy_adopt") as url:
        ids = _build_legacy_database(url)
        assert _readiness_code(url) == "owner_coverage_incomplete"

        before = _state(url)
        digest = _preview_digest(capsys, url)
        assert _state(url) == before

        engine = build_engine(url)
        try:
            with Session(engine) as session, transaction(session):
                _drift_new_ownerless_object(session, ids)
        finally:
            engine.dispose()
        drifted = _state(url)
        code, _out, err = _apply(capsys, url, digest)
        assert (code, err.strip()) == (1, "database_adopt_owners_error=adoption_plan_drift")
        assert _state(url) == drifted

        for login in ("missing.principal", "legacy.retired"):
            code, _out, err = _cli(capsys, url, _adopt_args(login=login))
            assert (code, err.strip()) == (
                1,
                "database_adopt_owners_error=owner_principal_inactive",
            )
        assert _state(url) == drifted

        # A normal active principal without any catalog role is a valid target.
        target = "legacy.operator"
        digest = _preview_digest(capsys, url, login=target)
        code, applied, _err = _apply(capsys, url, digest, login=target, request_id=REQUEST_ID)
        assert code == 0
        assert _summary(applied)["adopted"] == "5"
        assert _summary(applied)["target_principal_id"] == ids["operator"]
        assert _readiness_code(url) == "ok"

        after = _state(url)
        code, rerun, _err = _apply(capsys, url, digest, login=target, request_id=REQUEST_ID)
        assert code == 0 and _summary(rerun)["adopted"] == "0"
        assert _state(url) == after
        assert _cli(capsys, url, ["owners"])[0] == 0


@requires_postgresql
def test_postgresql_concurrent_applies_serialize_without_deadlock(
    capsys,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _pg_database("bw_legacy_race") as url:
        _build_legacy_database(url)
        digest = _preview_digest(capsys, url)

        first, second = _coordinated_concurrent_applies(
            url,
            digest,
            monkeypatch,
            lambda apply_once: apply_once(),
        )

        assert (first, second) == (4, 0)
        counts = _owner_grant_counts(url)
        assert counts["legacy-host"] == counts["legacy-runbook"] == 1
        assert counts["legacy-service"] == 1
        assert _readiness_code(url) == "ok"


@requires_postgresql
def test_postgresql_online_adoption_racing_apply_fails_closed(
    capsys,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _pg_database("bw_legacy_online") as url:
        ids = _build_legacy_database(url)
        digest = _preview_digest(capsys, url)
        engine = build_engine(url)
        try:
            with Session(engine) as session:
                previewed_revision = session.get(CatalogObject, "legacy-runbook").revision
        finally:
            engine.dispose()

        def online_adoption(_apply_once) -> str:
            engine = build_engine(url)
            try:
                with Session(engine) as session, transaction(session):
                    adopt_ownerless_object(
                        session,
                        _write_context(session, ids["catalog_owner"]),
                        object_id="legacy-runbook",
                        principal_id=ids["operator"],
                        expected_revision=previewed_revision,
                    )
            except CommandPreconditionFailed:
                return "precondition_failed"
            finally:
                engine.dispose()
            return "adopted"

        first, second = _coordinated_concurrent_applies(
            url,
            digest,
            monkeypatch,
            online_adoption,
        )

        assert (first, second) == (4, "precondition_failed")
        engine = build_engine(url)
        try:
            with Session(engine) as session:
                owners = session.scalars(
                    select(ObjectGrant.principal_id).where(
                        ObjectGrant.object_id == "legacy-runbook",
                        ObjectGrant.role == Role.OWNER,
                    )
                ).all()
                channels = [
                    load_audit_details(event)["channel"]
                    for event in session.scalars(
                        select(AuditEvent).where(
                            AuditEvent.object_id == "legacy-runbook",
                            AuditEvent.action == "owner_adopt",
                        )
                    )
                ]
        finally:
            engine.dispose()
        assert owners == [ids["catalog_owner"]]
        assert channels == ["cli"]
