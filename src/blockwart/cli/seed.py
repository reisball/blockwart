from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from sqlalchemy.orm import sessionmaker

from blockwart.db.migrations import DatabaseMigrationError, upgrade_database
from blockwart.db.session import DatabaseTransactionError, build_engine, transaction
from blockwart.models import AuditEvent, CatalogObject, Relationship
from blockwart.services.seeds import import_seed_file

DEFAULT_SEED_PATH = Path("seeds/pilot_objects.yaml")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="blockwart-seed",
        description="Initialize a Blockwart database and import a seed file.",
    )
    parser.add_argument(
        "--database-url",
        help="SQLAlchemy database URL. Defaults to BLOCKWART_DATABASE_URL or local config.",
    )
    parser.add_argument(
        "--seed",
        default=str(DEFAULT_SEED_PATH),
        help=f"Seed YAML file to import. Default: {DEFAULT_SEED_PATH}",
    )
    parser.add_argument(
        "--create-schema",
        action="store_true",
        help="Upgrade the database schema to the current Alembic revision before importing.",
    )
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="Print current object, relationship, and audit counts without importing.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.create_schema:
        try:
            upgrade_database(args.database_url)
        except DatabaseMigrationError:
            print("seed_error=database_migration_failed", file=sys.stderr)
            return 1

    engine = build_engine(args.database_url)
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    with session_factory() as session:
        if args.summary_only:
            _print_summary(session)
            return 0

        seed_path = Path(args.seed)
        if not seed_path.exists():
            print(f"seed_error=missing_file path={seed_path}", file=sys.stderr)
            return 2

        try:
            with transaction(session):
                result = import_seed_file(session, seed_path)
        except DatabaseTransactionError:
            print("seed_error=database_transaction_failed", file=sys.stderr)
            return 1
        print(
            "seed_imported "
            f"objects={result.objects_imported} "
            f"relationships={result.relationships_imported}"
        )
        _print_summary(session)
        return 0


def _print_summary(session) -> None:
    object_count = session.query(CatalogObject).count()
    relationship_count = session.query(Relationship).count()
    audit_count = session.query(AuditEvent).count()
    print(
        "catalog_summary "
        f"objects={object_count} "
        f"relationships={relationship_count} "
        f"audit_events={audit_count}"
    )


if __name__ == "__main__":
    raise SystemExit(main())
