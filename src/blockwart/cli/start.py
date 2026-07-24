from __future__ import annotations

import os
import sys

from blockwart.db.migrations import DatabaseMigrationError, upgrade_database

UVICORN_COMMAND = [
    sys.executable,
    "-m",
    "uvicorn",
    "blockwart.main:app",
    "--host",
    "0.0.0.0",
    "--port",
    "8000",
]


def main() -> int:
    try:
        upgrade_database()
    except DatabaseMigrationError:
        print("startup_error=database_migration_failed", file=sys.stderr)
        return 1

    os.execv(UVICORN_COMMAND[0], UVICORN_COMMAND)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
