from __future__ import annotations

import argparse
import sys
from collections.abc import Mapping, Sequence
from typing import Any

from blockwart.release.canonical import canonical_json_text
from blockwart.release.errors import ReleaseError
from blockwart.release.runtime import SubprocessCommandRunner, SystemClock
from blockwart.release.schemas import SCHEMA_NAMES, json_schema
from blockwart.release.spec import REPORT_SCHEMA_VERSION, load_spec
from blockwart.release.workflow import (
    EXIT_FAILED,
    EXIT_OK,
    EXIT_USAGE,
    ReleaseWorkflow,
)


class _ReleaseArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ReleaseError("invalid_cli_arguments")


def build_parser() -> argparse.ArgumentParser:
    parser = _ReleaseArgumentParser(
        prog="blockwart-release",
        description=(
            "Plan and execute one atomic, rollback-safe Blockwart release from an exact "
            "Git commit. The default action is a write-free dry run."
        ),
    )
    parser.add_argument(
        "action",
        nargs="?",
        choices=("plan", "release", "status"),
        default="plan",
        help="Default: plan. Only 'release --apply' mutates the installation.",
    )
    parser.add_argument("--spec", help="Path to the versioned release specification document.")
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Explicitly leave dry-run mode and execute the release.",
    )
    parser.add_argument(
        "--expect-current",
        help=(
            "Release id the operator expects to be current, or 'none' for a first "
            "managed release. A mismatch fails before any mutation."
        ),
    )
    parser.add_argument("--format", choices=("json", "summary"), default="json")
    parser.add_argument(
        "--print-schema",
        choices=SCHEMA_NAMES,
        help="Print one canonical v1 JSON Schema without reading a specification or host state.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
    except ReleaseError as exc:
        _print_error(exc.code)
        return EXIT_USAGE
    if args.print_schema is not None:
        print(canonical_json_text(json_schema(args.print_schema)))
        return EXIT_OK
    if args.spec is None:
        _print_error("missing_required_argument")
        return EXIT_USAGE
    if args.expect_current is not None and args.action != "release":
        _print_error("expect_current_requires_release")
        return EXIT_USAGE
    if args.apply and args.action != "release":
        _print_error("apply_requires_release_action")
        return EXIT_USAGE
    if args.action == "release" and args.apply and args.expect_current is None:
        _print_error("expect_current_required_for_apply")
        return EXIT_USAGE

    try:
        spec = load_spec(args.spec)
        workflow = ReleaseWorkflow(
            spec,
            runner=SubprocessCommandRunner(),
            clock=SystemClock(),
        )
        if args.action == "status":
            payload = workflow.status()
            print(canonical_json_text(payload) if args.format == "json" else _status(payload))
            return EXIT_OK
        if args.action == "release" and args.apply:
            outcome = workflow.apply(expect_current=args.expect_current)
        else:
            outcome = workflow.plan()
    except ReleaseError as exc:
        _print_error(exc.code)
        return EXIT_FAILED
    except Exception:  # noqa: BLE001 - public CLI boundary is always redacted
        _print_error("release_internal_failure")
        return EXIT_FAILED

    report = outcome.report
    print(canonical_json_text(report) if args.format == "json" else _summary(report))
    if report["error"] is not None:
        print(f"release_error={report['error']}", file=sys.stderr)
    return outcome.exit_code


def _summary(report: Mapping[str, Any]) -> str:
    failed = [gate["name"] for gate in report["gates"] if gate["status"] == "failed"]
    return (
        f"blockwart_release mode={report['mode']} outcome={report['outcome']} "
        f"release={report['release_id']} changed={str(report['changed']).lower()} "
        f"replayed={str(report['replayed']).lower()} "
        f"image_digest={report['image']['digest']} "
        f"manifest_digest={report['manifest_digest']} "
        f"schema={report['schema']['expected_revision']} "
        f"failed_gates={','.join(failed) or 'none'} "
        f"error={report['error'] or 'none'} "
        f"report_digest={report['report_digest']}"
    )


def _status(payload: Mapping[str, Any]) -> str:
    current = payload["current"] or {}
    previous = payload["previous"] or {}
    return (
        f"blockwart_release_status release={payload['release_id']} "
        f"current={current.get('release_id', 'none')} "
        f"previous={previous.get('release_id', 'none')} "
        f"history={len(payload['history'])}"
    )


def _print_error(code: str) -> None:
    print(
        canonical_json_text(
            {
                "schema_version": REPORT_SCHEMA_VERSION,
                "mode": "error",
                "outcome": "failed",
                "error": code,
            }
        ),
        file=sys.stderr,
    )


if __name__ == "__main__":
    raise SystemExit(main())
