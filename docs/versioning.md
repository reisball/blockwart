# Product Versioning And Software Releases

## One version source

`src/blockwart/__init__.py` contains the sole product-version declaration,
`__version__`. Keep it a literal string: setuptools reads it statically via
`[tool.setuptools.dynamic]` without importing application dependencies during a
build. The wheel/source-distribution metadata, FastAPI/OpenAPI, health responses
and MCP server initialization all use that value. No installed Git checkout or
runtime network access is needed to determine the version.

| Identifier | Meaning |
|---|---|
| Product `0.1.0`, Git tag `v0.1.0` | Published software version |
| REST `/api/v1`, MCP protocol version | Independent interface contracts |
| Alembic revision, e.g. `20261022_0027` | Database schema/migration state |
| Full Git commit / `build_revision` | Exact source revision of a build |
| Container deployment release ID | Instance-specific deployment evidence |

Several unreleased commits may share a product version; use the build commit
for exact identification. Never infer the running instance version from the
latest GitHub release, or the migration state from a product version.

## Version increments

Use Semantic Versioning-style `MAJOR.MINOR.PATCH` versions and matching `v`-prefixed
Git tags. Python distribution versions omit the `v` prefix.

- `0.1.0` is the first versioned baseline, not a rewrite of historical releases.
- `0.1.1` is an example bug-fix release; `0.2.0` is an example feature release.
- During `0.x`, document compatibility-affecting changes explicitly and use a
  minor bump for them. Do not conceal breaking changes in a patch release.
- A future `1.0.0` requires an explicit stability/compatibility decision. From
  `1.x`, incompatible public-contract changes require a major bump.
- If a prerelease is needed, use a Python-compatible version such as `0.2.0rc1`,
  tag it `v0.2.0rc1` and mark its GitHub release as a prerelease. Do not assume
  prereleases are stable-monitoring candidates.
- Never move or reuse a published version/tag. Correct released defects in a
  new version; explain the issue in its release notes.

## Prepare the reviewable change

1. Use a matching issue and feature branch. Update `__version__` and add a dated
   changelog entry with features, fixes, compatibility/migrations and known limits.
   Keep an `Unreleased` section and update comparison links.
2. Update related README/API/operating docs. Product publication does not bypass
   the [public-content checklist](public-release.md).
3. Regenerate `tests/contracts/openapi.json` with
   `python scripts/update_openapi_contract.py` when its product version changes;
   review the resulting diff. Dependency locks change only when dependencies do.
4. Run the [CI proof](ci.md), including dependency-lock parity, lint, PostgreSQL
   tests, OpenAPI, installed-wheel and container smokes. The installed-wheel
   smoke checks metadata, OpenAPI, health and the actual MCP handshake together.
   Also build a source distribution and confirm a wheel can be built from it.
5. Record the exact reviewed commit and check results in the PR. Merge only
   within the authorized scope; preserve `Refs #N` when issue closure is deferred.

## Publish the verified main commit

After the PR is merged, bind publication to a **full commit SHA** on canonical
`main`. Verify its tree matches the reviewed source, required main CI is green,
the package/changelog version agrees, and neither the intended tag nor release
already exists. If either exists, inspect it instead of overwriting it.

Build the wheel and source distribution from a clean checkout of that commit:

```bash
python -m build --outdir /tmp/blockwart-release-dist
```

Use a new empty output directory for each release. Validate metadata and a
wheel rebuilt from the source distribution, then record SHA-256 checksums for
any attached artifacts. Retain CI/review links and the exact commit in the
release notes. For the first release the tag is `v0.1.0`.

Create an annotated tag at that exact SHA and push **only** that tag. Publish a
GitHub release from the existing tag with the matching changelog entry, known
limitations, and verified artifacts/checksums. For example, after preparing
`/tmp/blockwart-release-notes.md` and the reviewed artifacts:

```bash
git tag -a v0.1.0 FULL_VERIFIED_COMMIT_SHA -m 'Blockwart v0.1.0'
git push origin refs/tags/v0.1.0
gh release create v0.1.0 --repo reisball/blockwart --verify-tag \
  --title 'Blockwart v0.1.0' --notes-file /tmp/blockwart-release-notes.md \
  /tmp/blockwart-release-dist/blockwart-0.1.0-py3-none-any.whl \
  /tmp/blockwart-release-dist/blockwart-0.1.0.tar.gz \
  /tmp/blockwart-release-dist/SHA256SUMS
```

Read back the peeled tag commit, release URL, draft/prerelease status and asset
checksums before reporting completion. A GitHub release is a software publication,
not a deployment, a production-readiness claim or permission to close other issues.

## Deployment stays separate

Tag pushes do not trigger the current CI workflow (which runs on PRs and main
pushes), and no release event deploys the application. The
[atomic container release workflow](release-workflow.md) remains the explicit,
separately authorized instance operation with its own migration, backup and
rollback gates. In particular, data-bearing Project workspace tables cannot be
silently downgraded; follow their documented recovery contract.
