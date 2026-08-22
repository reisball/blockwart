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
/tmp/blockwart-lock-venv/bin/python -m pip install "pip==26.1.2" "pip-tools==7.6.0"
PYTHON_BIN=/tmp/blockwart-lock-venv/bin/python \
  ./scripts/update-dependency-locks.sh
PYTHON_BIN=/tmp/blockwart-lock-venv/bin/python \
  ./scripts/update-dependency-locks.sh --check
```

The bootstrap and development extra currently pin or constrain pip below 26.2 because
`pip-tools 7.6.0` imports a pip compatibility symbol removed in pip 26.2. Keep both
guards until the pinned compiler version supports pip 26.2 or newer.

The update command starts from empty temporary lock bodies and passes `--upgrade`, so it resolves
the newest compatible runtime and development graphs. Check mode instead seeds each temporary
body from its corresponding committed lock and passes `--no-upgrade`. It therefore preserves
compatible committed versions even when newer releases exist, while still failing for missing
locks or graph changes caused by stale, removed, or incompatible requirements. Check mode does not
modify committed lock files: it renders comparison candidates below a temporary directory and
compares them byte for byte with the committed locks. `pip` and `pip-tools` may cache elsewhere.

Review the complete dependency diff, run the full proof below, and commit `pyproject.toml` and both
generated files together. A dependency update is not a deployment.

Routine version updates are reviewed and initiated deliberately; this
repository does not schedule Dependabot version-update pull requests.
Repository-level Dependabot alerts and security updates may still open a
focused pull request for a dependency with a known vulnerability.

## Contract Proof

The Gitea and GitHub workflows in `.gitea/workflows/ci.yml` and
`.github/workflows/ci.yml` are intentionally byte-identical. Each host runs the same proof:

```bash
./scripts/update-dependency-locks.sh --check
cmp .gitea/workflows/ci.yml .github/workflows/ci.yml
actionlint .gitea/workflows/ci.yml .github/workflows/ci.yml
ruff check --no-cache .
python -m compileall -q src tests scripts
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
assets, runs the relationship-integrity diagnostic, and exercises all 31
tools through 38 read/write, preview, Project-workspace, coverage, attention, comment,
audit, and grant-management calls to the installed `blockwart-mcp` console
command. It also runs the read-only service-interface
normalization, placement-state, network-classification, and canonical-Project plans from outside
the source tree, plus the canonical-Runbook classification plan, the write-free synthetic
Knowledge plan, and the installed reviewed-apply machine schemas. Productive Knowledge apply is
covered only with synthetic SQLite catalogs in pytest; package smoke never mutates its seeded
catalog through this workflow.
The installed-package proof also resolves `blockwart-source-coverage` and validates that its
manifest, target-evidence, and result schemas can be printed outside the source tree; it does not
perform a private collection or coverage record.

The container smoke proves that an empty catalog fails the Owner invariant, then starts an
explicitly bootstrapped candidate and a database at the historical Alembic baseline. Ready
candidates must migrate to Head without losing legacy data. Both ready paths must also pass
`blockwart-db integrity` plus the read-only `blockwart-db interfaces` and
`blockwart-db placements` and `blockwart-db monitoring` plans. The monitoring
plan is read-only and never resolves or contacts a catalog target.

The OpenAPI snapshot at `tests/contracts/openapi.json` is an intentionally reviewed machine
contract. After an approved API change, update and review it with:

```bash
python scripts/update_openapi_contract.py
```

CI uses no live Blockwart instance, production database, or production secret. On both hosts, a
trusted Linux runner labeled `ubuntu-latest` must support the immutable
`actions/checkout` v4.4.0 and `actions/setup-python` v5.6.0 commit pins, Python
3.12, `curl`, and a working Docker daemon. The workflow grants only read access
to repository contents and never exposes a repository secret to pull requests.
Before installing
dependencies, the workflow records load average, Linux pressure-stall information,
root-filesystem usage, and a compact Docker summary so host-level resource starvation can be
distinguished from product failures. Runner provisioning and automated deployment are separate
infrastructure tasks.

Service-monitoring tests never contact a live target. They inject deterministic
resolver/socket adapter results and use documentation address ranges only. The
package and container smoke paths leave the poller disabled and the target
allowlist empty; their monitoring database plan is read-only.

The real host differences remain outside the workflow: Gitea Actions uses the Fabrik runner and
Gitea repository permissions, while GitHub Actions uses GitHub repository permissions and
GitHub's own runner, event-delivery, and log-retention environment. `actionlint` and byte parity
prove static syntax and command parity. Runtime parity is additionally proven by successful
GitHub Actions runs on:

- the exact imported Gitea `main` SHA `8d0bd2fcb097c09f1be8863539ef6527f3745d82`
  ([run #1](https://github.com/reisball/blockwart/actions/runs/30751416724)); and
- the canonical post-cutover GitHub `main` SHA
  `ca83e17a0c8bb8b605ab661d8c9e57fe883bbcb9`
  ([run #2](https://github.com/reisball/blockwart/actions/runs/30752565755)).

These CI results do not imply deployment or production readiness.
