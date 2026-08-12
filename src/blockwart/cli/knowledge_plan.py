from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from blockwart.services.knowledge_planning import (
    KnowledgePlanError,
    build_knowledge_plan,
    canonical_json_text,
    load_manifest,
    load_target_snapshot,
    manifest_json_schema,
    result_json_schema,
    result_summary,
    target_snapshot_json_schema,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="blockwart-knowledge-plan",
        description="Build a deterministic, write-free Knowledge classification plan.",
    )
    parser.add_argument(
        "--manifest", help="Reviewed version-1 JSON or YAML classification manifest."
    )
    parser.add_argument(
        "--source-root", help="Read-only root containing the declared source snapshot."
    )
    parser.add_argument("--target-snapshot", help="Optional reviewed sanitized target snapshot.")
    parser.add_argument(
        "--expected-target-digest", help="Optional independently held target snapshot digest."
    )
    parser.add_argument(
        "--implementation-commit", help="Exact implementation commit bound by the manifest."
    )
    parser.add_argument(
        "--implementation-tree", help="Exact implementation tree bound by the manifest."
    )
    parser.add_argument("--format", choices=("json", "summary"), default="summary")
    parser.add_argument(
        "--print-schema",
        choices=("manifest", "target-snapshot", "result"),
        help="Print a canonical JSON Schema without reading planning inputs.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.print_schema is not None:
        schemas = {
            "manifest": manifest_json_schema,
            "target-snapshot": target_snapshot_json_schema,
            "result": result_json_schema,
        }
        schema = schemas[args.print_schema]()
        print(canonical_json_text(schema))
        return 0
    required = {
        "manifest": args.manifest,
        "source_root": args.source_root,
        "implementation_commit": args.implementation_commit,
        "implementation_tree": args.implementation_tree,
    }
    if any(value is None for value in required.values()):
        print("knowledge_plan_error=missing_required_argument", file=sys.stderr)
        return 2
    try:
        manifest = load_manifest(args.manifest)
        target = load_target_snapshot(args.target_snapshot) if args.target_snapshot else None
        result = build_knowledge_plan(
            manifest,
            source_root=args.source_root,
            implementation_commit=args.implementation_commit,
            implementation_tree=args.implementation_tree,
            target_snapshot=target,
            expected_target_digest=args.expected_target_digest,
        )
    except KnowledgePlanError as exc:
        print(f"knowledge_plan_error={exc.code}", file=sys.stderr)
        return 1
    print(canonical_json_text(result) if args.format == "json" else result_summary(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
