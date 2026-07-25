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
export BLOCKWART_ADMIN_TOKEN=
"$TEMP_DIR/venv/bin/blockwart-db" upgrade
"$TEMP_DIR/venv/bin/blockwart-seed" --seed "$SOURCE_DIR/seeds/pilot_objects.yaml"
"$TEMP_DIR/venv/bin/blockwart-start" >"$TEMP_DIR/server.log" 2>&1 &
SERVER_PID=$!

if ! "$VENV_PYTHON" "$SOURCE_DIR/scripts/ci/installed_package_smoke.py"; then
  sed -n '1,200p' "$TEMP_DIR/server.log" >&2
  exit 1
fi
"$TEMP_DIR/venv/bin/blockwart-db" check
"$TEMP_DIR/venv/bin/blockwart-db" integrity
echo "package_smoke=passed"
