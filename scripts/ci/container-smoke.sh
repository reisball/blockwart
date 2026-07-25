#!/usr/bin/env bash
set -euo pipefail

IMAGE=${1:?usage: container-smoke.sh IMAGE EXPECTED_BUILD_REVISION}
EXPECTED_BUILD_REVISION=${2:?usage: container-smoke.sh IMAGE EXPECTED_BUILD_REVISION}
RUN_ID="blockwart-ci-$$-$RANDOM"
EMPTY_VOLUME="$RUN_ID-empty"
MIGRATED_VOLUME="$RUN_ID-migrated"
EMPTY_CONTAINER="$RUN_ID-empty"
MIGRATED_CONTAINER="$RUN_ID-migrated"

cleanup() {
  docker rm -f "$EMPTY_CONTAINER" "$MIGRATED_CONTAINER" >/dev/null 2>&1 || true
  docker volume rm "$EMPTY_VOLUME" "$MIGRATED_VOLUME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

wait_for_candidate() {
  local container=$1

  local payload=
  for _ in $(seq 1 45); do
    if payload=$(
      docker exec "$container" python -c \
        "from urllib.request import urlopen; print(urlopen('http://127.0.0.1:8000/api/health/ready', timeout=7).read().decode())" \
        2>/dev/null
    ); then
      break
    fi
    sleep 1
  done
  if [[ -z "$payload" ]]; then
    docker inspect "$container" --format '{{json .State}}' >&2
    docker logs "$container" >&2
    return 1
  fi
  READY_PAYLOAD="$payload" python3 - "$EXPECTED_BUILD_REVISION" <<'PY'
import json
import os
import sys

expected_revision = sys.argv[1]
payload = json.loads(os.environ["READY_PAYLOAD"])
assert payload["ok"] is True
assert payload["build_revision"] == expected_revision
assert payload["revision"] == "20260724_0004"
assert all(value == "ok" for value in payload["checks"].values())
PY

  for _ in $(seq 1 45); do
    local health
    health=$(docker inspect "$container" --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}')
    [[ "$health" == healthy ]] && break
    if [[ "$health" == unhealthy ]]; then
      docker logs "$container" >&2
      return 1
    fi
    sleep 1
  done
  local final_state
  final_state=$(docker inspect "$container" --format '{{.State.Status}} {{.State.Health.Status}} {{.RestartCount}}')
  if [[ "$final_state" != "running healthy 0" ]]; then
    printf 'unexpected container state: %s\n' "$final_state" >&2
    docker logs "$container" >&2
    return 1
  fi
  docker exec "$container" blockwart-db check
  docker exec "$container" blockwart-db integrity
}

docker image inspect "$IMAGE" >/dev/null
docker volume create "$EMPTY_VOLUME" >/dev/null
docker run -d \
  --name "$EMPTY_CONTAINER" \
  -e BLOCKWART_ENV=production \
  -e BLOCKWART_DATABASE_URL=sqlite:////data/blockwart.sqlite3 \
  -e BLOCKWART_ADMIN_TOKEN= \
  -v "$EMPTY_VOLUME:/data" \
  "$IMAGE" >/dev/null
wait_for_candidate "$EMPTY_CONTAINER"
docker rm -f "$EMPTY_CONTAINER" >/dev/null

docker volume create "$MIGRATED_VOLUME" >/dev/null
docker run --rm -i \
  -e BLOCKWART_DATABASE_URL=sqlite:////data/blockwart.sqlite3 \
  -v "$MIGRATED_VOLUME:/data" \
  --entrypoint python \
  "$IMAGE" - <<'PY'
from alembic import command
from sqlalchemy import create_engine, text

from blockwart.db.migrations import BASELINE_REVISION, build_alembic_config

database_url = "sqlite:////data/blockwart.sqlite3"
command.upgrade(build_alembic_config(database_url), BASELINE_REVISION)
engine = create_engine(database_url)
with engine.begin() as connection:
    connection.execute(
        text(
            "INSERT INTO catalog_objects "
            "(id, kind, label, status, summary, data_json) "
            "VALUES (:id, :kind, :label, :status, :summary, :data_json)"
        ),
        {
            "id": "ci-legacy",
            "kind": "system",
            "label": "CI Legacy",
            "status": "active",
            "summary": "Must survive container startup migration.",
            "data_json": '{"schema_version":1,"future":{"preserve":true}}',
        },
    )
engine.dispose()
print(f"container_fixture=baseline revision={BASELINE_REVISION}")
PY

docker run -d \
  --name "$MIGRATED_CONTAINER" \
  -e BLOCKWART_ENV=production \
  -e BLOCKWART_DATABASE_URL=sqlite:////data/blockwart.sqlite3 \
  -e BLOCKWART_ADMIN_TOKEN= \
  -v "$MIGRATED_VOLUME:/data" \
  "$IMAGE" >/dev/null
wait_for_candidate "$MIGRATED_CONTAINER"
docker exec -i "$MIGRATED_CONTAINER" python - <<'PY'
from sqlalchemy import create_engine, text

engine = create_engine("sqlite:////data/blockwart.sqlite3")
with engine.connect() as connection:
    data_json = connection.execute(
        text("SELECT data_json FROM catalog_objects WHERE id = 'ci-legacy'")
    ).scalar_one()
    integrity = connection.exec_driver_sql("PRAGMA integrity_check").scalar_one()
engine.dispose()
assert data_json == '{"schema_version":1,"future":{"preserve":true}}'
assert integrity == "ok"
print("container_migration=preserved integrity=ok")
PY

echo "container_smoke=passed empty_database=ok migrated_database=ok"
