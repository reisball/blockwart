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
from blockwart.db.session import build_engine
from blockwart.services.catalog import relationship_diagnostics


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="blockwart-db",
        description="Manage and verify the Blockwart database schema.",
    )
    parser.add_argument(
        "--database-url",
        help="SQLAlchemy database URL. Defaults to BLOCKWART_DATABASE_URL or local config.",
    )
    parser.add_argument("action", choices=("upgrade", "check", "integrity"))
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


if __name__ == "__main__":
    raise SystemExit(main())
