from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from sqlalchemy.orm import Session

from blockwart.config import get_settings
from blockwart.db.migrations import (
    build_alembic_config,
    check_database_revision,
    upgrade_database,
)
from blockwart.db.session import build_engine, build_read_only_engine, transaction
from blockwart.services.catalog import relationship_diagnostics
from blockwart.services.decision_migration import (
    apply_decision_migration_plan,
    build_decision_migration_plan,
    load_decision_migration_mapping,
)
from blockwart.services.interface_migration import (
    apply_interface_migration_plan,
    build_interface_migration_plan,
)
from blockwart.services.monitoring import (
    build_monitoring_plan,
    monitoring_plan_entry_payload,
    monitoring_settings,
    run_due_service_checks,
)
from blockwart.services.network_classification import (
    NetworkClassificationError,
    build_network_classification_plan,
    classification_entry_payload,
    load_network_classification_evidence,
)
from blockwart.services.ownership import OwnerlessObjectReport, find_ownerless_objects
from blockwart.services.placement_migration import (
    apply_placement_migration_plan,
    build_placement_migration_plan,
)
from blockwart.services.project_migration import (
    apply_project_migration_plan,
    build_project_migration_plan,
    load_project_migration_mapping,
)
from blockwart.services.runbook_migration import (
    apply_runbook_migration_plan,
    build_runbook_migration_plan,
    load_runbook_migration_mapping,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="blockwart-db",
        description="Manage and verify the Blockwart database schema.",
    )
    parser.add_argument(
        "--database-url",
        help="SQLAlchemy database URL. Defaults to BLOCKWART_DATABASE_URL or local config.",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply a data-normalization plan. Default is a read-only dry run.",
    )
    parser.add_argument(
        "--mapping",
        help="Reviewed YAML mapping for the networks, decisions, projects, or runbooks action.",
    )
    parser.add_argument(
        "action",
        choices=(
            "upgrade",
            "check",
            "integrity",
            "owners",
            "interfaces",
            "placements",
            "monitoring",
            "networks",
            "decisions",
            "projects",
            "runbooks",
        ),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        if args.action == "upgrade":
            revision = upgrade_database(args.database_url)
        elif args.action == "integrity":
            revision = check_database_revision(args.database_url)
            diagnostics = _relationship_diagnostics(args.database_url)
            if diagnostics:
                for diagnostic in diagnostics:
                    print(
                        "relationship_integrity_error "
                        f"code={diagnostic.code} location={diagnostic.location}",
                        file=sys.stderr,
                    )
                return 1
            # Legacy ownerless objects are reported, not failed: an upgraded
            # catalog may contain them, and they are repaired only through the
            # audited adoption command, never by this check.
            for report in _ownerless_report(args.database_url):
                print(
                    "owner_integrity_warning code=access_owner_missing "
                    f"ref={report.ref} placement={report.placement} "
                    f"adoption_possible={int(report.adoption_possible)}",
                    file=sys.stderr,
                )
        elif args.action == "owners":
            if args.apply:
                print("owner_report_error=apply_not_available", file=sys.stderr)
                return 1
            revision = check_database_revision(args.database_url, read_only=True)
            reports = _ownerless_report(args.database_url)
            for report in reports:
                print(
                    "ownerless_object "
                    + json.dumps(
                        _ownerless_payload(report),
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                )
            adoptable = sum(1 for report in reports if report.adoption_possible)
            result = "database_owners_attention" if reports else "database_owners_ok"
            print(
                f"{result} revision={revision} mode=dry-run "
                f"ownerless={len(reports)} adoptable={adoptable}"
            )
            return 1 if reports else 0
        elif args.action == "interfaces":
            revision = check_database_revision(args.database_url)
            plan = _interface_plan(args.database_url, apply=args.apply)
            for diagnostic in plan.diagnostics:
                print(
                    "interface_diagnostic "
                    f"code={diagnostic.code} location={diagnostic.location}"
                )
            mode = "apply" if args.apply else "dry-run"
            print(
                "database_interfaces_ok "
                f"revision={revision} mode={mode} "
                f"scanned={plan.scanned_objects} changed={plan.changed_objects} "
                f"diagnostics={len(plan.diagnostics)}"
            )
            return 0
        elif args.action == "placements":
            revision = check_database_revision(args.database_url)
            plan = _placement_plan(args.database_url, apply=args.apply)
            for diagnostic in plan.diagnostics:
                print(
                    "placement_diagnostic "
                    f"code={diagnostic.code} location={diagnostic.location}",
                    file=sys.stderr,
                )
            for object_ref in plan.unassigned_refs:
                print(f"placement_unassigned ref={object_ref}")
            for change in plan.changes:
                print(
                    "placement_change "
                    f"ref={change.kind}:{change.object_id} action={change.action}"
                )
            mode = "apply" if args.apply else "dry-run"
            result = (
                "database_placements_error"
                if plan.diagnostics
                else "database_placements_ok"
            )
            print(
                f"{result} "
                f"revision={revision} mode={mode} "
                f"scanned={plan.scanned_assets} changed={plan.changed_objects} "
                f"assigned={len(plan.assigned_refs)} "
                f"unassigned={len(plan.unassigned_refs)} "
                f"diagnostics={len(plan.diagnostics)}"
            )
            return 1 if plan.diagnostics else 0
        elif args.action == "monitoring":
            revision = check_database_revision(
                args.database_url,
                read_only=not args.apply,
            )
            plan, run = _monitoring_plan(args.database_url, apply=args.apply)
            for entry in plan.entries:
                print(
                    "monitoring_service "
                    + json.dumps(
                        monitoring_plan_entry_payload(entry),
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                )
            mode = "apply" if args.apply else "dry-run"
            skipped = run.skipped_reason if run is not None else None
            if skipped is not None:
                print(f"monitoring_run_skipped reason={skipped}", file=sys.stderr)
            print(
                "database_monitoring_ok "
                f"revision={revision} mode={mode} "
                f"scanned={plan.scanned_services} enabled={plan.enabled_services} "
                f"diagnostics={plan.diagnostics} "
                f"poller={'enabled' if plan.poller_enabled else 'disabled'} "
                f"allowlist={'configured' if plan.allowlist_configured else 'empty'} "
                f"claimed={run.claimed if run is not None else 0} "
                f"completed={run.completed if run is not None else 0}"
            )
            return 0
        elif args.action == "networks":
            if args.apply:
                print(
                    "network_classification_error=apply_not_available",
                    file=sys.stderr,
                )
                return 1
            revision = check_database_revision(args.database_url, read_only=True)
            plan = _network_plan(args.database_url, mapping_path=args.mapping)
            for diagnostic in plan.diagnostics:
                print(
                    "network_classification_diagnostic "
                    + json.dumps(
                        {"code": diagnostic},
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                    file=sys.stderr,
                )
            for entry in plan.entries:
                print(
                    "network_classification "
                    + json.dumps(
                        classification_entry_payload(entry),
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                )
            failed = bool(plan.diagnostics or plan.blocked_networks)
            result = (
                "database_networks_error" if failed else "database_networks_ok"
            )
            print(
                f"{result} revision={revision} mode=dry-run "
                f"scanned={plan.scanned_networks} changed={plan.changed_networks} "
                f"blocked={plan.blocked_networks} diagnostics={len(plan.diagnostics)}"
            )
            return 1 if failed else 0
        elif args.action == "decisions":
            revision = check_database_revision(args.database_url, read_only=not args.apply)
            plan = _decision_plan(
                args.database_url,
                mapping_path=args.mapping,
                apply=args.apply,
            )
            for diagnostic in plan.diagnostics:
                print(
                    "decision_migration_diagnostic "
                    f"code={diagnostic.code} object_id={diagnostic.object_id}",
                    file=sys.stderr,
                )
            mode = "apply" if args.apply else "dry-run"
            failed = bool(plan.diagnostics)
            result = "database_decisions_error" if failed else "database_decisions_ok"
            print(
                f"{result} revision={revision} mode={mode} "
                f"scanned={plan.scanned_decisions} canonical={plan.canonical_decisions} "
                f"changed={len(plan.changes)} blocked={plan.blocked_decisions} "
                f"diagnostics={len(plan.diagnostics)}"
            )
            return 1 if failed else 0
        elif args.action == "projects":
            revision = check_database_revision(args.database_url, read_only=not args.apply)
            plan = _project_plan(
                args.database_url,
                mapping_path=args.mapping,
                apply=args.apply,
            )
            for diagnostic in plan.diagnostics:
                print(
                    "project_migration_diagnostic "
                    f"code={diagnostic.code} object_id={diagnostic.object_id}",
                    file=sys.stderr,
                )
            mode = "apply" if args.apply else "dry-run"
            failed = bool(plan.diagnostics)
            result = "database_projects_error" if failed else "database_projects_ok"
            print(
                f"{result} revision={revision} mode={mode} "
                f"scanned={plan.scanned_projects} canonical={plan.canonical_projects} "
                f"changed={len(plan.changes)} blocked={plan.blocked_projects} "
                f"diagnostics={len(plan.diagnostics)}"
            )
            return 1 if failed else 0
        elif args.action == "runbooks":
            revision = check_database_revision(args.database_url, read_only=not args.apply)
            plan = _runbook_plan(
                args.database_url,
                mapping_path=args.mapping,
                apply=args.apply,
            )
            for diagnostic in plan.diagnostics:
                print(
                    "runbook_migration_diagnostic "
                    f"code={diagnostic.code} object_id={diagnostic.object_id}",
                    file=sys.stderr,
                )
            mode = "apply" if args.apply else "dry-run"
            failed = bool(plan.diagnostics)
            result = "database_runbooks_error" if failed else "database_runbooks_ok"
            print(
                f"{result} revision={revision} mode={mode} "
                f"plan_digest={plan.plan_digest} "
                f"scanned={plan.scanned_runbooks} canonical={plan.canonical_runbooks} "
                f"changed={len(plan.changes)} blocked={plan.blocked_runbooks} "
                f"diagnostics={len(plan.diagnostics)}"
            )
            return 1 if failed else 0
        else:
            revision = check_database_revision(args.database_url)
    except Exception:  # noqa: BLE001 - CLI boundary must redact database details
        print(f"database_{args.action}_error=failed", file=sys.stderr)
        return 1

    suffix = " diagnostics=0" if args.action == "integrity" else ""
    print(f"database_{args.action}_ok revision={revision}{suffix}")
    return 0


def _relationship_diagnostics(database_url: str | None):
    config = build_alembic_config(database_url)
    engine = build_engine(str(config.attributes["database_url"]))
    try:
        with Session(engine) as session:
            return relationship_diagnostics(session)
    finally:
        engine.dispose()


def _ownerless_report(database_url: str | None) -> tuple[OwnerlessObjectReport, ...]:
    """Read-only legacy ownership report; it never guesses or assigns an owner."""
    config = build_alembic_config(database_url)
    engine = build_read_only_engine(str(config.attributes["database_url"]))
    try:
        with Session(engine) as session:
            return find_ownerless_objects(session)
    finally:
        engine.dispose()


def _ownerless_payload(report: OwnerlessObjectReport) -> dict[str, object]:
    return {
        "ref": report.ref,
        "object_id": report.object_id,
        "kind": report.kind,
        "label": report.label,
        "revision": report.revision,
        "etag": f'"rev-{report.revision}"',
        "placement": report.placement,
        "direct_active_owner_grants": report.direct_active_owner_grants,
        "inherited_active_owner_grants": report.inherited_active_owner_grants,
        "inactive_direct_owner_grants": report.inactive_direct_owner_grants,
        "provenance": {
            "source_type": report.provenance_source_type,
            "source_ref": report.provenance_source_ref,
        },
        "adoption_possible": report.adoption_possible,
        "adoption_blocker": report.adoption_blocker,
    }


def _interface_plan(database_url: str | None, *, apply: bool):
    config = build_alembic_config(database_url)
    engine = build_engine(str(config.attributes["database_url"]))
    try:
        with Session(engine) as session:
            plan = build_interface_migration_plan(session)
            if apply:
                with transaction(session):
                    apply_interface_migration_plan(session, plan)
            return plan
    finally:
        engine.dispose()


def _placement_plan(database_url: str | None, *, apply: bool):
    config = build_alembic_config(database_url)
    engine = build_engine(str(config.attributes["database_url"]))
    try:
        with Session(engine) as session:
            plan = build_placement_migration_plan(session)
            if apply and not plan.diagnostics:
                with transaction(session):
                    apply_placement_migration_plan(session, plan)
            return plan
    finally:
        engine.dispose()


def _monitoring_plan(database_url: str | None, *, apply: bool):
    """Build the write-free monitoring plan and optionally run one due pass."""

    config = build_alembic_config(database_url)
    resolved_url = str(config.attributes["database_url"])
    engine = (
        build_engine(resolved_url) if apply else build_read_only_engine(resolved_url)
    )
    try:
        settings = monitoring_settings(get_settings())
        with Session(engine) as session:
            run = (
                run_due_service_checks(session, settings=settings) if apply else None
            )
            plan = build_monitoring_plan(session, settings=settings)
            return plan, run
    finally:
        engine.dispose()


def _network_plan(database_url: str | None, *, mapping_path: str | None):
    config = build_alembic_config(database_url)
    engine = build_read_only_engine(str(config.attributes["database_url"]))
    try:
        evidence = (
            load_network_classification_evidence(mapping_path)
            if mapping_path is not None
            else {}
        )
        with Session(engine) as session:
            return build_network_classification_plan(session, evidence)
    except NetworkClassificationError:
        raise
    finally:
        engine.dispose()


def _decision_plan(
    database_url: str | None,
    *,
    mapping_path: str | None,
    apply: bool,
):
    config = build_alembic_config(database_url)
    engine_builder = build_engine if apply else build_read_only_engine
    engine = engine_builder(str(config.attributes["database_url"]))
    try:
        mapping = (
            load_decision_migration_mapping(mapping_path)
            if mapping_path is not None
            else {}
        )
        with Session(engine) as session:
            plan = build_decision_migration_plan(session, mapping)
            if apply and not plan.diagnostics:
                with transaction(session):
                    apply_decision_migration_plan(session, plan)
            return plan
    finally:
        engine.dispose()


def _project_plan(
    database_url: str | None,
    *,
    mapping_path: str | None,
    apply: bool,
):
    config = build_alembic_config(database_url)
    engine_builder = build_engine if apply else build_read_only_engine
    engine = engine_builder(str(config.attributes["database_url"]))
    try:
        mapping = (
            load_project_migration_mapping(mapping_path)
            if mapping_path is not None
            else {}
        )
        with Session(engine) as session:
            plan = build_project_migration_plan(session, mapping)
            if apply and not plan.diagnostics:
                with transaction(session):
                    apply_project_migration_plan(session, plan)
            return plan
    finally:
        engine.dispose()


def _runbook_plan(
    database_url: str | None,
    *,
    mapping_path: str | None,
    apply: bool,
):
    config = build_alembic_config(database_url)
    engine_builder = build_engine if apply else build_read_only_engine
    engine = engine_builder(str(config.attributes["database_url"]))
    try:
        mapping = (
            load_runbook_migration_mapping(mapping_path)
            if mapping_path is not None
            else {}
        )
        with Session(engine) as session:
            plan = build_runbook_migration_plan(session, mapping)
            if apply and not plan.diagnostics:
                with transaction(session):
                    apply_runbook_migration_plan(session, plan)
            return plan
    finally:
        engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
