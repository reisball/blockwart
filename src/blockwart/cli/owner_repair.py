from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from blockwart.db.migrations import build_alembic_config, check_database_revision
from blockwart.db.session import build_engine, build_read_only_engine, read_only_transaction
from blockwart.services.legacy_owner_repair import (
    LegacyOwnerRepairError,
    LegacyOwnerRepairPlan,
    LegacyOwnerRepairResult,
    apply_legacy_owner_repair,
    build_legacy_owner_repair_plan,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="blockwart-owner-repair",
        description=(
            "Preview or apply the audited pre-start repair for a legacy "
            "ownerless catalog."
        ),
    )
    parser.add_argument(
        "--database-url",
        help="SQLAlchemy database URL. Defaults to BLOCKWART_DATABASE_URL or local config.",
    )
    parser.add_argument("--actor-login", required=True)
    parser.add_argument("--target-login", required=True)
    parser.add_argument("--reason", required=True)
    parser.add_argument("--request-id", required=True)
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply the exact plan named by --expected-plan-digest.",
    )
    parser.add_argument(
        "--expected-plan-digest",
        help="SHA-256 plan digest from a reviewed preview.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.apply and args.expected_plan_digest is None:
        print("legacy_owner_repair_error=repair_plan_digest_required", file=sys.stderr)
        return 1
    if not args.apply and args.expected_plan_digest is not None:
        print("legacy_owner_repair_error=apply_required_for_plan_digest", file=sys.stderr)
        return 1

    try:
        revision = check_database_revision(
            args.database_url,
            read_only=not args.apply,
        )
        if args.apply:
            result = _apply(args)
            _print_objects(result.plan)
            print(
                "legacy_owner_repair_ok "
                f"revision={revision} mode=apply "
                f"repaired={result.repaired} remaining={result.remaining} "
                f"plan_digest={result.plan.plan_digest}"
            )
        else:
            plan = _preview(args)
            _print_objects(plan)
            print(
                "legacy_owner_repair_plan "
                f"revision={revision} mode=preview "
                f"ownerless={len(plan.objects)} "
                "counts_by_kind="
                f"{json.dumps(dict(plan.counts_by_kind), sort_keys=True, separators=(',', ':'))} "
                f"plan_digest={plan.plan_digest}"
            )
    except LegacyOwnerRepairError as exc:
        print(f"legacy_owner_repair_error={exc.code}", file=sys.stderr)
        return 1
    except OperationalError as exc:
        code = "repair_concurrent_drift" if _is_concurrent_failure(exc) else "failed"
        print(f"legacy_owner_repair_error={code}", file=sys.stderr)
        return 1
    except Exception:  # noqa: BLE001 - CLI boundary must redact database details
        print("legacy_owner_repair_error=failed", file=sys.stderr)
        return 1
    return 0


def _preview(args: argparse.Namespace) -> LegacyOwnerRepairPlan:
    config = build_alembic_config(args.database_url)
    engine = build_read_only_engine(str(config.attributes["database_url"]))
    try:
        with Session(engine) as session:
            with read_only_transaction(session):
                return build_legacy_owner_repair_plan(
                    session,
                    actor_login=args.actor_login,
                    target_login=args.target_login,
                    reason=args.reason,
                    request_id=args.request_id,
                )
    finally:
        engine.dispose()


def _apply(args: argparse.Namespace) -> LegacyOwnerRepairResult:
    config = build_alembic_config(args.database_url)
    engine = build_engine(str(config.attributes["database_url"])).execution_options(
        isolation_level="SERIALIZABLE"
    )
    try:
        with Session(engine) as session:
            try:
                if session.connection().dialect.name == "sqlite":
                    session.connection().exec_driver_sql("BEGIN IMMEDIATE")
                result = apply_legacy_owner_repair(
                    session,
                    actor_login=args.actor_login,
                    target_login=args.target_login,
                    reason=args.reason,
                    request_id=args.request_id,
                    expected_plan_digest=args.expected_plan_digest,
                )
                session.commit()
                return result
            except Exception:
                session.rollback()
                raise
    finally:
        engine.dispose()


def _print_objects(plan: LegacyOwnerRepairPlan) -> None:
    for item in plan.objects:
        print(
            "legacy_owner_repair_object "
            + json.dumps(
                {
                    "kind": item.kind,
                    "object_id": item.object_id,
                    "ref": item.ref,
                    "revision": item.revision,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )


def _is_concurrent_failure(exc: OperationalError) -> bool:
    original = exc.orig
    sqlstate = getattr(original, "pgcode", None) or getattr(original, "sqlstate", None)
    return sqlstate == "40001" or "database is locked" in str(original).casefold()


if __name__ == "__main__":
    raise SystemExit(main())
