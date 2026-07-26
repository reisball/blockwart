# Reproducible Builds And CI

Blockwart targets Python 3.12 on Linux. Runtime and development dependency graphs are committed as
exact constraints in `requirements/runtime.txt` and `requirements/dev.txt`. The Docker base image
is pinned by digest, and the Python build backend versions are exact.

## Install From The Committed Locks

For development:

```bash
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install --constraint requirements/dev.txt ".[dev]"
```

For a runtime-only package install:

```bash
python -m pip install --constraint requirements/runtime.txt .
```

Do not update individual transitive versions by hand. The committed files are generated together
from `pyproject.toml`.

## Controlled Dependency Update

Use Python 3.12 on Linux and the exact compiler version:

```bash
python3.12 -m venv /tmp/blockwart-lock-venv
/tmp/blockwart-lock-venv/bin/python -m pip install "pip-tools==7.6.0"
PYTHON_BIN=/tmp/blockwart-lock-venv/bin/python \
  ./scripts/update-dependency-locks.sh
PYTHON_BIN=/tmp/blockwart-lock-venv/bin/python \
  ./scripts/update-dependency-locks.sh --check
```

Review the complete dependency diff, run the full proof below, and commit `pyproject.toml` and both
generated files together. A dependency update is not a deployment.

## Contract Proof

The Gitea workflow in `.gitea/workflows/ci.yml` runs the same commands:

```bash
ruff check --no-cache .
python -m compileall -q src tests scripts
actionlint .gitea/workflows/ci.yml
pytest -q
python scripts/update_openapi_contract.py --check
./scripts/ci/package-smoke.sh
REVISION="$(git rev-parse HEAD)"
docker build \
  --build-arg "BLOCKWART_BUILD_REVISION=$REVISION" \
  --tag "blockwart-ci:$REVISION" \
  .
./scripts/ci/container-smoke.sh "blockwart-ci:$REVISION" "$REVISION"
```

The package smoke builds a wheel, installs it into a clean virtual environment, changes to a
directory outside the repository, starts `blockwart-start`, loads packaged templates and static
assets, runs the relationship-integrity diagnostic, and calls all three tools through the installed
`blockwart-mcp` console command. It also runs the read-only service-interface
normalization and placement-state plans from outside the source tree.

The container smoke starts the built image first with an empty volume and then with a database at
the historical Alembic baseline. Both must reach Docker health and application readiness. The
second run must migrate to Head without losing its legacy JSON row. Both paths must also pass
`blockwart-db integrity` plus the read-only `blockwart-db interfaces` and
`blockwart-db placements` plans.

The OpenAPI snapshot at `tests/contracts/openapi.json` is an intentionally reviewed machine
contract. After an approved API change, update and review it with:

```bash
python scripts/update_openapi_contract.py
```

CI uses no live Blockwart instance, production database, admin token, or other secret. A trusted
Gitea Actions runner labeled `ubuntu-latest` must provide Python 3.12 setup support, `curl`, and a
working Docker daemon. Before installing dependencies, the workflow records load average, Linux
pressure-stall information, root-filesystem usage, and a compact Docker summary so host-level
resource starvation can be distinguished from product failures. Runner provisioning and automated
deployment are separate infrastructure tasks.
