from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from blockwart.db.migrations import (
    DatabaseMigrationError,
    check_database_revision,
    upgrade_database,
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
    parser.add_argument("action", choices=("upgrade", "check"))
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        if args.action == "upgrade":
            revision = upgrade_database(args.database_url)
        else:
            revision = check_database_revision(args.database_url)
    except DatabaseMigrationError:
        print(f"database_{args.action}_error=failed", file=sys.stderr)
        return 1

    print(f"database_{args.action}_ok revision={revision}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
