# Reproducible Builds And CI

Blockwart targets Python 3.12 on Linux. Runtime and development dependency graphs are committed as
exact constraints in `requirements/runtime.txt` and `requirements/dev.txt`. The Docker base image
is pinned by digest, and the Python build backend versions are exact.

The package version is read statically from `blockwart.__version__` by
setuptools. The installed-wheel smoke checks that distribution metadata,
OpenAPI, liveness/readiness and the MCP initialization handshake agree.
See [Versioning](versioning.md) for release gates and version bumps.

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
/tmp/blockwart-lock-venv/bin/python -m pip install "pip==26.2" "pip-tools==7.6.1"
PYTHON_BIN=/tmp/blockwart-lock-venv/bin/python \
  ./scripts/update-dependency-locks.sh --preserve
PYTHON_BIN=/tmp/blockwart-lock-venv/bin/python \
  ./scripts/update-dependency-locks.sh --check
```

The bootstrap and development extra pin the verified pip 26.2 / pip-tools 7.6.1 pair.
Keep the compiler version in the bootstrap, development extra, and lock script aligned.

The `--preserve` command seeds each temporary body from its committed lock and passes
`--no-upgrade`, retaining compatible versions during focused updates. The default update
command starts from empty temporary lock bodies and passes `--upgrade` to resolve the newest
compatible runtime and development graphs. Check mode also uses the committed versions and
fails for missing locks or graph changes caused by stale, removed, or incompatible requirements.
It does not modify committed lock files: it renders comparison candidates below a temporary
directory and compares them byte for byte with the committed locks. `pip` and `pip-tools` may
cache elsewhere.

Review the complete dependency diff, run the full proof below, and commit `pyproject.toml` and both
generated files together. A dependency update is not a deployment.

Routine version updates are reviewed and initiated deliberately; this
repository does not schedule Dependabot version-update pull requests.
Repository-level Dependabot alerts and security updates may still open a
focused pull request for a dependency with a known vulnerability.

## Disposable PostgreSQL prerequisite

The full proof includes PostgreSQL 16, not only SQLite. Use a **disposable test
server**: tests create/drop databases and need a role with `CREATEDB` (or a
superuser). Never use a production database URL. For example, with Docker:

```bash
docker run --detach --rm --name blockwart-dev-postgres \
  --publish 127.0.0.1:55432:5432 \
  --env POSTGRES_USER=blockwart --env POSTGRES_PASSWORD=blockwart \
  --env POSTGRES_DB=blockwart postgres:16
docker exec blockwart-dev-postgres pg_isready -U blockwart
export BLOCKWART_TEST_PG_URL='postgresql+psycopg2://blockwart:blockwart@127.0.0.1:55432/blockwart'
```

Run the proof only once `pg_isready` reports accepting connections. The example
password is disposable test data. Confirm Python can reach the same server and
the test role can create databases before starting pytest:

```bash
python - <<'PYTHON'
import os
from sqlalchemy import create_engine, text
url = os.environ["BLOCKWART_TEST_PG_URL"].rsplit("/", 1)[0] + "/postgres"
with create_engine(url).connect() as connection:
    assert connection.scalar(text(
        "SELECT rolcreatedb OR rolsuper FROM pg_roles WHERE rolname = current_user"
    )), "The disposable test role needs CREATEDB"
print("PostgreSQL test prerequisite passed")
PYTHON
```

Keep the URL exported for pytest below. Unreachable PostgreSQL otherwise causes
compatibility tests to skip; a green exit with that skip reason is **not** full
PostgreSQL proof. Inspect the `-ra` summary for
`PostgreSQL test database unreachable` and retain the actual passed/skipped
results. CI provisions the equivalent service on port 5432 and explicitly sets
the URL. Remove only your example server after testing with
`docker stop blockwart-dev-postgres`.

## Conservative Documentation Path

Both hosts keep the required check named **`verify`**. The workflow is always
created for pull requests and pushes to `main`; it has no workflow-level path
exclusions. A small `classify` job selects `docs` or `full`, then the final
`verify` job aggregates their results with `if: always()`.

Eligibility is an **exact audited allowlist**, currently only these root files:

- `CONTRIBUTING.md`
- `SECURITY.md`

These files are contributor/security-reporting prose, not runtime inputs,
package metadata, image contents, or executable contract-test inputs. They are
absent from the current wheel and source distribution and from Docker `COPY`
inputs. Do not expand the allowlist based only on a Markdown suffix or directory.
Re-audit packaging, runtime/script/test consumers and contracts before adding a
file or changing how an allowlisted file is consumed.

`README.md` supplies package metadata. All of `docs/` is copied into the image,
and some pages are contract-test inputs. Therefore **every change under `docs/`
(including this page), `README.md`, `CHANGELOG.md` (release evidence), examples,
application code, migrations, dependencies, build/CI configuration, generated
contracts, or any unknown path runs full verification**. Mixed changes do too.
Only regular, non-executable allowlisted files qualify. Prose additions and
deletions are eligible; renames examine both old and new paths, so renaming
between prose and any unlisted path runs full verification.

### Reliable changed-file detection

Checkout fetches complete history. The dependency-free classifier reads the
host's event JSON rather than interpolating event data into shell commands:

- Pull requests use the merge base of the event's base/head commit IDs through
  the head, not merely the last commit. A head checkout is supported. For a
  synthetic merge checkout, both parents must match the event base/head, and
  the diff from base to the actual merge result is also checked.
- Pushes use the complete event `before..after` range, require `after` to match
  the checkout and require a fast-forward history. This includes every commit
  in a multi-commit push.
- Missing/invalid event fields or commits, shallow or unrelated history,
  ambiguous merge bases, new-branch/all-zero `before`, force pushes, unexpected checkout shapes,
  unsupported events, empty diffs and any other uncertain diff select `full`.
  An actual classifier job error (for example, failed checkout or failure to
  write its output) fails the final gate instead of silently skipping proof.

### Lightweight proof and the required gate

The docs job has **no PostgreSQL service, dependency/application install, pytest
application suite, wheel build, Docker build or smoke tests**. It sets up Python
3.12 and runs only these offline, standard-library checks:

```bash
cmp .gitea/workflows/ci.yml .github/workflows/ci.yml
python scripts/ci/check_docs.py
python -m unittest discover -s tests/ci -p 'test_*.py' -v
```

The prose checker verifies UTF-8, nonempty files with final newlines, no trailing
whitespace/conflict markers, closed fenced code blocks and existing in-repository
inline local Markdown link targets (outside code fences). It does not fetch
remote URLs or validate fragment anchors. Absent/deleted prose files are allowed.
The regression suite builds disposable local Git histories to exercise PR and
push ranges, merged/diverged PRs, mixed changes, renames, deletions, file modes,
missing/shallow history, malformed events and fallback behavior.

`verify` succeeds only when classification succeeded, the selected job succeeded
and the unselected job was skipped. A failed, cancelled, unexpectedly skipped or
missing required job, or a missing/unknown mode, is never accepted. Expected
heavy-job skipping on the docs path is distinguished from missing required
proof. Whole-workflow cancellation likewise cannot supply a successful required
check. No branch-protection change is needed; `verify` keeps its existing name.
The existing full proof and its **60-minute** job timeout are retained.

Focused local routing/workflow checks (using the locked development environment)
are:

```bash
python -m unittest discover -s tests/ci -p 'test_*.py' -v
pytest -q -ra tests/ci/test_docs_ci.py tests/test_ci_workflow.py
cmp .gitea/workflows/ci.yml .github/workflows/ci.yml
actionlint .gitea/workflows/ci.yml .github/workflows/ci.yml
```

The workflow tests execute the actual required-gate shell across all combinations
of classifier/docs/full outcomes, and execute the actual lightweight shell in a
disposable repository after a concrete prose-only push. This is local routing
and command proof, not a claim that a hosted GitHub/Gitea run has completed.

## Contract Proof

The Gitea and GitHub workflows in `.gitea/workflows/ci.yml` and
`.github/workflows/ci.yml` are intentionally byte-identical. Each host runs the
same proof. The local equivalent below assumes the locked development install,
`actionlint`, a working Docker daemon and the PostgreSQL prerequisite above.
Command-scoped `PYTHONPATH=src` makes local OpenAPI checks inspect the working
tree after edits to a non-editable install; do not export it globally into the
installed-package smoke.

```bash
./scripts/update-dependency-locks.sh --check
cmp .gitea/workflows/ci.yml .github/workflows/ci.yml
actionlint .gitea/workflows/ci.yml .github/workflows/ci.yml
ruff check --no-cache .
python -m compileall -q src tests scripts
pytest -q -ra
PYTHONPATH=src python scripts/update_openapi_contract.py --check
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
assets, runs the relationship-integrity diagnostic, and verifies the complete
47-tool catalog. Its read/write, preview, Project-workspace, coverage, attention,
activity, comment, audit, grant-management, and ownerless-adoption calls use the
installed `blockwart-mcp` console command. The smoke's `mcp_calls` summary is a
fixed label, not an independently measured count of calls or per-tool coverage.
It also proves identical same-commit
wrapper/API metadata and a fail-fast incompatible diagnosis for a deliberately
reduced materialized tool catalog through both installed CLI paths. Before
seeding it bootstraps the first catalog owner without an anchor, proves that
`blockwart-seed` refuses to run without `--owner-login`, seeds with that
explicit first Owner, and runs the read-only `blockwart-db owners` report.
Before starting, it plants one legacy ownerless object and proves three
things: `blockwart-db owners` reports it, and `blockwart-start` refuses with
`startup_error=owner_coverage_incomplete`. Then the installed
`blockwart-db adopt-owners` previews it for the explicit catalog owner, applies
it with the preview's plan digest, and a rerun adopts nothing.
The MCP proof then recovers a second, post-start legacy ownerless object through
`blockwart.adopt_ownerless_object` and verifies its resulting Owner coverage.
It additionally proves the delegated root-Project authority over REST:
a principal holding only `catalog_role = project_creator` creates one root
Project with Owner/self, is refused a root host, and sees no other object. It
also runs the read-only service-interface
normalization, placement-state, network-classification, and canonical-Project plans from outside
the source tree, plus the canonical-Runbook classification plan, the write-free synthetic
Knowledge plan, and the installed reviewed-apply machine schemas. Productive Knowledge apply is
covered only with synthetic SQLite catalogs in pytest; package smoke never mutates its seeded
catalog through this workflow.
The installed-package proof also resolves `blockwart-source-coverage` and validates that its
manifest, target-evidence, and result schemas can be printed outside the source tree; it does not
perform a private collection or coverage record.
It also resolves the installed `blockwart-release` entry point and validates
that the release specification, manifest, report, pointer, status, and error
JSON Schemas can be printed outside the source tree. CI never invokes its apply
mode or touches a host service.

The container smoke proves that an empty catalog fails the Owner invariant. It then upgrades a
database written at the historical Alembic baseline and explicitly selects its catalog owner.
Next it proves that the image refuses to start with `startup_error=owner_coverage_incomplete`,
and repairs it with the packaged `blockwart-db adopt-owners` preview, digest-bound apply, and
no-op rerun before starting that candidate. Ready
candidates must migrate to Head without losing legacy data. Both ready paths must also pass
`blockwart-db integrity` plus the read-only `blockwart-db interfaces` and
`blockwart-db placements` and `blockwart-db monitoring` plans. The monitoring
plan is read-only and never resolves or contacts a catalog target.

The OpenAPI snapshot at `tests/contracts/openapi.json` is an intentionally reviewed machine
contract. After an approved API change, update and review it with:

```bash
PYTHONPATH=src python scripts/update_openapi_contract.py
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

The real host differences remain outside the workflow: each host uses its own
runner provisioning, repository permissions, event delivery and log retention.
`actionlint` and byte parity prove static syntax and command parity; runtime
success is tied to the exact CI revision, not to a historical migration run.
CI success does not imply deployment or production readiness.

## Historical migration verification

The completed [GitHub migration](github-migration.md) retained successful
same-source parity runs on:

- imported commit `8d0bd2fcb097c09f1be8863539ef6527f3745d82`
  ([run #1](https://github.com/reisball/blockwart/actions/runs/30751416724));
- post-cutover commit `ca83e17a0c8bb8b605ab661d8c9e57fe883bbcb9`
  ([run #2](https://github.com/reisball/blockwart/actions/runs/30752565755)).

These are historical evidence only, not verification of current HEAD or a
requirement to recreate the original host environment.
