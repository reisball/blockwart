#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
PYTHON_BIN=${PYTHON_BIN:-python3}
TEMP_DIR=$(mktemp -d)
SERVER_PID=
SOURCE_DIR="$TEMP_DIR/source"

cleanup() {
  if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID"
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  find "$TEMP_DIR" -mindepth 1 -delete
  rmdir "$TEMP_DIR"
}
trap cleanup EXIT

mkdir "$SOURCE_DIR"
tar \
  --exclude=.git \
  --exclude=.venv \
  --exclude=build \
  --exclude='*.egg-info' \
  -C "$PROJECT_ROOT" \
  -cf - \
  . | tar -C "$SOURCE_DIR" -xf -
"$PYTHON_BIN" -m build --wheel --no-isolation --outdir "$TEMP_DIR/dist" "$SOURCE_DIR"
"$PYTHON_BIN" -m venv "$TEMP_DIR/venv"
VENV_PYTHON="$TEMP_DIR/venv/bin/python"
"$VENV_PYTHON" -m pip install \
  --constraint "$PROJECT_ROOT/requirements/runtime.txt" \
  "$TEMP_DIR"/dist/blockwart-*.whl
"$VENV_PYTHON" -m pip check

mkdir "$TEMP_DIR/outside-repository"
cd "$TEMP_DIR/outside-repository"
export BLOCKWART_DATABASE_URL="sqlite:///$TEMP_DIR/package-smoke.sqlite3"
"$TEMP_DIR/venv/bin/blockwart-db" upgrade
"$TEMP_DIR/venv/bin/blockwart-seed" --seed "$SOURCE_DIR/seeds/pilot_objects.yaml"
mapfile -t OWNER_ANCHORS < <(
  "$VENV_PYTHON" - <<'PY'
import os
from sqlalchemy import select
from sqlalchemy.orm import Session
from blockwart.db.session import build_engine
from blockwart.models import CatalogObject

engine = build_engine(os.environ["BLOCKWART_DATABASE_URL"])
with Session(engine) as session:
    for object_id in session.scalars(select(CatalogObject.id).order_by(CatalogObject.id)):
        print(object_id)
engine.dispose()
PY
)
BOOTSTRAP_ARGS=(
  --database-url "$BLOCKWART_DATABASE_URL"
  bootstrap-owner
  --login package.owner
  --display-name "Package Owner"
  --scope self
  --password-stdin
  --catalog-owner
)
for anchor in "${OWNER_ANCHORS[@]}"; do
  BOOTSTRAP_ARGS+=(--object-id "$anchor")
done
printf '%s\n' 'package-smoke-owner-password' | \
  "$TEMP_DIR/venv/bin/blockwart-auth" "${BOOTSTRAP_ARGS[@]}"
"$TEMP_DIR/venv/bin/blockwart-start" >"$TEMP_DIR/server.log" 2>&1 &
SERVER_PID=$!

if ! "$VENV_PYTHON" "$SOURCE_DIR/scripts/ci/installed_package_smoke.py"; then
  sed -n '1,200p' "$TEMP_DIR/server.log" >&2
  exit 1
fi
"$TEMP_DIR/venv/bin/blockwart-db" check
"$TEMP_DIR/venv/bin/blockwart-db" integrity
"$TEMP_DIR/venv/bin/blockwart-db" interfaces
"$TEMP_DIR/venv/bin/blockwart-db" placements
"$TEMP_DIR/venv/bin/blockwart-db" networks
echo "package_smoke=passed"
