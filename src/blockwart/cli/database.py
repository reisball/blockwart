from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from sqlalchemy.orm import Session

from blockwart.db.migrations import (
    build_alembic_config,
    check_database_revision,
    upgrade_database,
)
from blockwart.db.session import build_engine, build_read_only_engine, transaction
from blockwart.services.catalog import relationship_diagnostics
from blockwart.services.interface_migration import (
    apply_interface_migration_plan,
    build_interface_migration_plan,
)
from blockwart.services.network_classification import (
    NetworkClassificationError,
    build_network_classification_plan,
    classification_entry_payload,
    load_network_classification_evidence,
)
from blockwart.services.placement_migration import (
    apply_placement_migration_plan,
    build_placement_migration_plan,
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
        help="Evidence-backed network category mapping YAML for the networks dry run.",
    )
    parser.add_argument(
        "action",
        choices=("upgrade", "check", "integrity", "interfaces", "placements", "networks"),
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


if __name__ == "__main__":
    raise SystemExit(main())
