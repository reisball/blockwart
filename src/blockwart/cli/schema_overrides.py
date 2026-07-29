from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from blockwart.domain.ui_schema import (
    apply_schema_overrides_migration,
    build_schema_overrides_migration_plan,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="blockwart-schema-overrides",
        description="Plan or apply the version 1 to version 2 UI schema override migration.",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Create a protected backup and apply the migration. Default is dry-run.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        plan = build_schema_overrides_migration_plan()
        backup = apply_schema_overrides_migration() if args.apply and plan.changed else None
    except Exception:  # noqa: BLE001 - CLI boundary must not leak configured content
        print("schema_overrides_migration_error=failed", file=sys.stderr)
        return 1
    mode = "apply" if args.apply else "dry-run"
    print(
        "schema_overrides_migration_ok "
        f"mode={mode} configured={int(plan.configured)} exists={int(plan.exists)} "
        f"source_version={plan.source_version or 0} target_version={plan.target_version} "
        f"changed={int(plan.changed)} kinds={len(plan.kinds)} "
        f"backup_created={int(backup is not None)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
