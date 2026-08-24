from __future__ import annotations

import argparse
import sys
from collections.abc import Mapping, Sequence
from typing import Any

from blockwart.services.source_coverage_manifest import (
    SourceCoverageManifestError,
    canonical_json_text,
    dry_run,
    manifest_json_schema,
    record_manifest_snapshot,
    result_json_schema,
    target_evidence_json_schema,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="blockwart-source-coverage",
        description=(
            "Validate a closed Knowledge inventory and optionally record its sanitized coverage."
        ),
    )
    parser.add_argument(
        "action",
        nargs="?",
        choices=("dry-run", "record"),
        default="dry-run",
        help="Default: dry-run. Only the explicit record action writes coverage rows.",
    )
    parser.add_argument("--database-url")
    parser.add_argument("--manifest")
    parser.add_argument("--source-root")
    parser.add_argument("--principal-id")
    parser.add_argument("--target-evidence")
    parser.add_argument("--expected-manifest-digest")
    parser.add_argument("--expected-input-digest")
    parser.add_argument("--expected-snapshot-digest")
    parser.add_argument("--expected-target-digest")
    parser.add_argument("--format", choices=("json", "summary"), default="json")
    parser.add_argument(
        "--print-schema",
        choices=("manifest", "target-evidence", "result"),
        help="Print one canonical v1 JSON Schema without opening inputs or a database.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.print_schema is not None:
        schemas = {
            "manifest": manifest_json_schema,
            "target-evidence": target_evidence_json_schema,
            "result": result_json_schema,
        }
        print(canonical_json_text(schemas[args.print_schema]()))
        return 0
    common = {
        "database_url": args.database_url,
        "manifest_path": args.manifest,
        "source_root": args.source_root,
        "principal_id": args.principal_id,
    }
    missing = sorted(key for key, value in common.items() if value is None)
    if args.action == "record":
        record_only = {
            "target_evidence_path": args.target_evidence,
            "expected_manifest_digest": args.expected_manifest_digest,
            "expected_input_digest": args.expected_input_digest,
            "expected_snapshot_digest": args.expected_snapshot_digest,
            "expected_target_digest": args.expected_target_digest,
        }
        missing.extend(sorted(key for key, value in record_only.items() if value is None))
    if missing:
        _print_error("missing_required_argument")
        return 2
    try:
        if args.action == "record":
            result = record_manifest_snapshot(
                **common,
                target_evidence_path=args.target_evidence,
                expected_manifest_digest=args.expected_manifest_digest,
                expected_input_digest=args.expected_input_digest,
                expected_snapshot_digest=args.expected_snapshot_digest,
                expected_target_digest=args.expected_target_digest,
            )
        else:
            result = dry_run(**common)
    except SourceCoverageManifestError as exc:
        _print_error(exc.code)
        return 1
    print(canonical_json_text(result) if args.format == "json" else _summary(result))
    return 0


def _summary(result: Mapping[str, Any]) -> str:
    snapshot = result["source_snapshot"]
    blockers = result["blockers"]
    return (
        f"source_coverage mode={result['mode']} "
        f"manifest_digest={result['manifest_digest']} "
        f"input_digest={result['input_digest']} "
        f"snapshot_digest={snapshot['digest']} "
        f"sources={snapshot['source_count']} entries={snapshot['entry_count']} "
        f"mappings={snapshot['mapping_count']} blockers={len(blockers)} "
        f"record_ready={str(result['record_ready']).lower()} "
        f"semantic_noop={str(result['semantic_noop']).lower()}"
    )


def _print_error(code: str) -> None:
    unsafe_findings = [code] if code.startswith("unsafe_") else []
    print(
        canonical_json_text(
            {
                "schema_version": 1,
                "collector_version": "1",
                "mode": "error",
                "error": code,
                "unsafe_findings": unsafe_findings,
                "blockers": [{"code": code}],
            }
        ),
        file=sys.stderr,
    )


if __name__ == "__main__":
    raise SystemExit(main())
