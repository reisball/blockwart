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
# A seed never creates an ownerless object, so the first identity is
# bootstrapped before the seed and named as the explicit first Owner.
printf '%s\n' 'package-smoke-owner-password' | \
  "$TEMP_DIR/venv/bin/blockwart-auth" \
    --database-url "$BLOCKWART_DATABASE_URL" \
    bootstrap-owner \
    --login package.owner \
    --display-name "Package Owner" \
    --password-stdin \
    --catalog-owner
if "$TEMP_DIR/venv/bin/blockwart-seed" --seed "$SOURCE_DIR/seeds/pilot_objects.yaml"; then
  echo "package_smoke_error=seed_accepted_without_owner" >&2
  exit 1
fi
"$TEMP_DIR/venv/bin/blockwart-seed" \
  --seed "$SOURCE_DIR/seeds/pilot_objects.yaml" \
  --owner-login package.owner
"$TEMP_DIR/venv/bin/blockwart-db" owners
# A pre-#232 import could write an object without any Owner. Such a legacy
# catalog must stay non-ready until the protected pre-start adoption repairs it
# for an explicit catalog owner with an explicit reason.
"$VENV_PYTHON" - <<'PY'
import os

from sqlalchemy.orm import Session

from blockwart.db.session import build_engine, transaction
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services.catalog import upsert_object

engine = build_engine(os.environ["BLOCKWART_DATABASE_URL"])
try:
    with Session(engine) as session, transaction(session):
        upsert_object(
            session,
            CatalogObjectIn(
                id="package-smoke-legacy-offline",
                kind="host",
                label="Package Smoke Legacy Offline",
                data={"schema_version": 1},
            ),
        )
finally:
    engine.dispose()
PY
if "$TEMP_DIR/venv/bin/blockwart-db" owners >/dev/null; then
  echo "package_smoke_error=legacy_ownerless_not_reported" >&2
  exit 1
fi
if timeout 60 "$TEMP_DIR/venv/bin/blockwart-start" >"$TEMP_DIR/legacy-start.log" 2>&1; then
  echo "package_smoke_error=legacy_ownerless_started" >&2
  exit 1
fi
if ! grep -q 'startup_error=owner_coverage_incomplete' "$TEMP_DIR/legacy-start.log"; then
  sed -n '1,50p' "$TEMP_DIR/legacy-start.log" >&2
  exit 1
fi
ADOPTION_REASON="Package smoke legacy upgrade"
adoption_preview=$(
  "$TEMP_DIR/venv/bin/blockwart-db" adopt-owners \
    --owner-login package.owner \
    --reason "$ADOPTION_REASON"
)
printf '%s\n' "$adoption_preview"
if [[ "$adoption_preview" != *'"object_id":"package-smoke-legacy-offline"'* ]] || \
   [[ "$adoption_preview" != *" ownerless=1 adopted=0 remaining=1 "* ]]; then
  echo "package_smoke_error=adoption_preview_mismatch" >&2
  exit 1
fi
adoption_digest=$(
  printf '%s\n' "$adoption_preview" |
    sed -n 's/.* plan_digest=\(sha256:[0-9a-f]\{64\}\) .*/\1/p'
)
for expected_adopted in 1 0; do
  adoption_result=$(
    "$TEMP_DIR/venv/bin/blockwart-db" --apply adopt-owners \
      --owner-login package.owner \
      --reason "$ADOPTION_REASON" \
      --request-id package-smoke-adoption \
      --expect-plan-digest "$adoption_digest"
  )
  printf '%s\n' "$adoption_result"
  if [[ "$adoption_result" != *" adopted=$expected_adopted remaining=0 "* ]]; then
    echo "package_smoke_error=adoption_apply_mismatch" >&2
    exit 1
  fi
done
"$TEMP_DIR/venv/bin/blockwart-db" owners
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
"$TEMP_DIR/venv/bin/blockwart-db" monitoring
"$TEMP_DIR/venv/bin/blockwart-db" networks
"$TEMP_DIR/venv/bin/blockwart-db" projects
"$TEMP_DIR/venv/bin/blockwart-db" runbooks
"$TEMP_DIR/venv/bin/blockwart-knowledge-plan" \
  --manifest "$SOURCE_DIR/examples/knowledge-plan/manifest.json" \
  --source-root "$SOURCE_DIR/examples/knowledge-plan/sources" \
  --implementation-commit 1111111111111111111111111111111111111111 \
  --implementation-tree 2222222222222222222222222222222222222222
"$TEMP_DIR/venv/bin/blockwart-knowledge-apply" --print-schema apply-result >/dev/null
"$TEMP_DIR/venv/bin/blockwart-knowledge-apply" --print-schema backup-receipt >/dev/null
"$TEMP_DIR/venv/bin/blockwart-knowledge-apply" --print-schema rollback-result >/dev/null
"$TEMP_DIR/venv/bin/blockwart-source-coverage" --print-schema manifest >/dev/null
"$TEMP_DIR/venv/bin/blockwart-source-coverage" --print-schema target-evidence >/dev/null
"$TEMP_DIR/venv/bin/blockwart-source-coverage" --print-schema result >/dev/null
"$TEMP_DIR/venv/bin/blockwart-release" --print-schema spec >/dev/null
"$TEMP_DIR/venv/bin/blockwart-release" --print-schema manifest >/dev/null
"$TEMP_DIR/venv/bin/blockwart-release" --print-schema report >/dev/null
"$TEMP_DIR/venv/bin/blockwart-release" --print-schema pointer >/dev/null
"$TEMP_DIR/venv/bin/blockwart-release" --print-schema status >/dev/null
"$TEMP_DIR/venv/bin/blockwart-release" --print-schema error >/dev/null
echo "package_smoke=passed"
