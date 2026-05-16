from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from sqlalchemy.orm import sessionmaker

from blockwart.db.base import Base
from blockwart.db.session import build_engine
from blockwart.models import CatalogObject, Relationship
from blockwart.services.markdown_import import build_tools_import_plan, import_tools_markdown

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
        help="Create database tables before importing.",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Write parsed objects to the database. Without this, only prints a dry-run summary.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    tools_path = Path(args.tools)
    if not tools_path.exists():
        print(f"markdown_import_error=missing_tools path={tools_path}", file=sys.stderr)
        return 2

    plan = build_tools_import_plan(
        tools_path,
        references_root=Path(args.references_root),
    )
    print(
        "markdown_import_plan "
        f"source_rows={plan.source_rows} "
        f"objects={plan.object_count} "
        f"credential_references={plan.credential_reference_count}"
    )

    if not args.apply:
        print("markdown_import_dry_run apply=false")
        return 0

    engine = build_engine(args.database_url)
    if args.create_schema:
        Base.metadata.create_all(bind=engine)

    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    with session_factory() as session:
        result = import_tools_markdown(
            session,
            tools_path,
            references_root=Path(args.references_root),
        )
        object_count = session.query(CatalogObject).count()
        relationship_count = session.query(Relationship).count()
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
