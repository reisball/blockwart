from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from blockwart.db.migrations import DatabaseMigrationError, upgrade_database
from blockwart.db.session import DatabaseTransactionError, build_engine, transaction
from blockwart.models import AuditEvent, CatalogObject, Relationship
from blockwart.services.markdown_import import (
    MarkdownImportNetworkError,
    build_tools_import_plan,
    import_tools_markdown,
)
from blockwart.services.network_classification import (
    NetworkClassificationError,
    load_network_classification_evidence,
)

DEFAULT_TOOLS_PATH = Path("/home/zoe/.openclaw/workspace/TOOLS.md")
DEFAULT_REFERENCES_ROOT = Path("/home/zoe/.openclaw/workspace")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="blockwart-import-markdown",
        description="Import workspace Markdown infrastructure docs into Blockwart.",
    )
    parser.add_argument(
        "--database-url",
        help="SQLAlchemy database URL. Defaults to BLOCKWART_DATABASE_URL or local config.",
    )
    parser.add_argument(
        "--tools",
        default=str(DEFAULT_TOOLS_PATH),
        help=f"TOOLS.md path. Default: {DEFAULT_TOOLS_PATH}",
    )
    parser.add_argument(
        "--references-root",
        default=str(DEFAULT_REFERENCES_ROOT),
        help=f"Base directory for references/*.md links. Default: {DEFAULT_REFERENCES_ROOT}",
    )
    parser.add_argument(
        "--create-schema",
        action="store_true",
        help="Upgrade the database schema to the current Alembic revision before importing.",
    )
    parser.add_argument(
        "--network-mapping",
        type=Path,
        help=(
            "Reviewed Network category evidence YAML. Required when TOOLS.md "
            "contains Network rows without an explicit category."
        ),
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Write parsed objects to the database. Without this, only prints a dry-run summary.",
    )
    parser.add_argument(
        "--replace",
        action="store_true",
        help="Delete all catalog objects, relationships, and audit events before importing.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    tools_path = Path(args.tools)
    if not tools_path.exists():
        print(f"markdown_import_error=missing_tools path={tools_path}", file=sys.stderr)
        return 2

    try:
        network_evidence = (
            load_network_classification_evidence(args.network_mapping)
            if args.network_mapping is not None
            else {}
        )
        plan = build_tools_import_plan(
            tools_path,
            references_root=Path(args.references_root),
            network_evidence=network_evidence,
        )
    except MarkdownImportNetworkError as exc:
        for diagnostic in exc.diagnostics:
            print(
                f"markdown_import_network_diagnostic code={diagnostic}",
                file=sys.stderr,
            )
        print("markdown_import_error=network_classification_failed", file=sys.stderr)
        return 1
    except NetworkClassificationError:
        print("markdown_import_error=invalid_network_mapping", file=sys.stderr)
        return 1
    except ValueError:
        print("markdown_import_error=invalid_payload", file=sys.stderr)
        return 1
    print(
        "markdown_import_plan "
        f"source_rows={plan.source_rows} "
        f"objects={plan.object_count} "
        f"credential_references={plan.credential_reference_count}"
    )

    if not args.apply:
        print("markdown_import_dry_run apply=false")
        return 0

    if args.create_schema:
        try:
            upgrade_database(args.database_url)
        except DatabaseMigrationError:
            print("markdown_import_error=database_migration_failed", file=sys.stderr)
            return 1

    engine = build_engine(args.database_url)
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    try:
        with session_factory() as session:
            with transaction(session):
                previous_revisions: dict[str, int] = {}
                if args.replace:
                    previous_revisions = dict(
                        session.execute(
                            select(CatalogObject.id, CatalogObject.revision)
                        ).all()
                    )
                    session.query(AuditEvent).delete()
                    session.query(Relationship).delete()
                    session.query(CatalogObject).delete()
                result = import_tools_markdown(
                    session,
                    tools_path,
                    references_root=Path(args.references_root),
                    network_evidence=network_evidence,
                )
                for object_id, previous_revision in previous_revisions.items():
                    row = session.get(CatalogObject, object_id)
                    if row is not None:
                        row.revision = max(row.revision, previous_revision + 1)
                object_count = session.query(CatalogObject).count()
                relationship_count = session.query(Relationship).count()
    except DatabaseTransactionError:
        print("markdown_import_error=database_transaction_failed", file=sys.stderr)
        return 1
    except ValueError:
        print("markdown_import_error=invalid_payload", file=sys.stderr)
        return 1

    print(
        "markdown_import_applied "
        f"objects={result.objects_imported} "
        f"relationships={result.relationships_imported} "
        f"catalog_objects={object_count} "
        f"catalog_relationships={relationship_count}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
