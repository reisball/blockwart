from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from blockwart.services.knowledge_apply import (
    KnowledgeApplyError,
    apply_knowledge,
    apply_result_json_schema,
    backup_receipt_json_schema,
    rollback_knowledge,
    rollback_result_json_schema,
)
from blockwart.services.knowledge_planning import canonical_json_text


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="blockwart-knowledge-apply",
        description="Apply or roll back one digest-bound reviewed Knowledge plan.",
    )
    parser.add_argument(
        "--print-schema",
        choices=("apply-result", "backup-receipt", "rollback-result"),
        help="Print a canonical JSON Schema without opening a database.",
    )
    subparsers = parser.add_subparsers(dest="action")
    apply_parser = subparsers.add_parser("apply", help="Apply one exact Phase-A plan.")
    apply_parser.add_argument("--database-url", required=True)
    apply_parser.add_argument("--manifest", required=True)
    apply_parser.add_argument("--source-root", required=True)
    apply_parser.add_argument("--target-snapshot", required=True)
    apply_parser.add_argument("--expected-classification-digest", required=True)
    apply_parser.add_argument("--expected-target-digest", required=True)
    apply_parser.add_argument("--expected-plan-digest", required=True)
    apply_parser.add_argument("--implementation-commit", required=True)
    apply_parser.add_argument("--implementation-tree", required=True)
    apply_parser.add_argument("--principal-id", required=True)
    apply_parser.add_argument("--backup", required=True)

    rollback_parser = subparsers.add_parser(
        "rollback", help="Restore one protected backup paired to an applied plan."
    )
    rollback_parser.add_argument("--database-url", required=True)
    rollback_parser.add_argument("--receipt", required=True)
    rollback_parser.add_argument("--expected-receipt-digest", required=True)
    rollback_parser.add_argument("--expected-plan-digest", required=True)
    rollback_parser.add_argument("--expected-post-state-digest", required=True)
    rollback_parser.add_argument("--expected-database-state-digest", required=True)
    rollback_parser.add_argument("--principal-id", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.print_schema:
        schemas = {
            "apply-result": apply_result_json_schema,
            "backup-receipt": backup_receipt_json_schema,
            "rollback-result": rollback_result_json_schema,
        }
        print(canonical_json_text(schemas[args.print_schema]()))
        return 0
    if args.action is None:
        print("knowledge_apply_error=missing_action", file=sys.stderr)
        return 2
    try:
        if args.action == "apply":
            result = apply_knowledge(
                database_url=args.database_url,
                manifest_path=args.manifest,
                source_root=args.source_root,
                target_snapshot_path=args.target_snapshot,
                expected_classification_digest=args.expected_classification_digest,
                expected_target_digest=args.expected_target_digest,
                expected_plan_digest=args.expected_plan_digest,
                implementation_commit=args.implementation_commit,
                implementation_tree=args.implementation_tree,
                principal_id=args.principal_id,
                backup_path=args.backup,
            )
        else:
            result = rollback_knowledge(
                database_url=args.database_url,
                receipt_path=args.receipt,
                expected_receipt_digest=args.expected_receipt_digest,
                expected_plan_digest=args.expected_plan_digest,
                expected_post_state_digest=args.expected_post_state_digest,
                expected_database_state_digest=args.expected_database_state_digest,
                principal_id=args.principal_id,
            )
    except KnowledgeApplyError as exc:
        replaced = str(exc.database_replaced).lower()
        print(
            f"knowledge_apply_error={exc.code} database_replaced={replaced}",
            file=sys.stderr,
        )
        return 1
    print(canonical_json_text(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
