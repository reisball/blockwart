from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from sqlalchemy.orm import Session

from blockwart.db.migrations import (
    build_alembic_config,
    check_database_revision,
    upgrade_database,
)
from blockwart.db.session import build_engine, transaction
from blockwart.services.catalog import relationship_diagnostics
from blockwart.services.interface_migration import (
    apply_interface_migration_plan,
    build_interface_migration_plan,
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
        help="Apply the interface normalization plan. Default is a read-only dry run.",
    )
    parser.add_argument(
        "action",
        choices=("upgrade", "check", "integrity", "interfaces"),
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


if __name__ == "__main__":
    raise SystemExit(main())
