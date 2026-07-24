from __future__ import annotations

import argparse
import json
from pathlib import Path

from blockwart.config import Settings
from blockwart.main import create_app

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = PROJECT_ROOT / "tests" / "contracts" / "openapi.json"


def render_contract() -> str:
    return json.dumps(
        create_app(settings=Settings()).openapi(),
        indent=2,
        sort_keys=True,
    ) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Update the reviewed OpenAPI contract snapshot.")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail when the committed contract differs from the application schema.",
    )
    args = parser.parse_args()
    rendered = render_contract()

    if args.check:
        if not CONTRACT_PATH.is_file() or CONTRACT_PATH.read_text() != rendered:
            parser.error(
                "OpenAPI contract is stale; review the API change and run "
                "python scripts/update_openapi_contract.py"
            )
        return 0

    CONTRACT_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONTRACT_PATH.write_text(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
