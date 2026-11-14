# UX v5 release boundaries and generic runbook

## Recorded isolated UI-only release

The release coordinator recorded deployment of
8128797959d4b82ed1b6329e153110e0d02b01d5, after
[exact-head full CI](https://github.com/reisball/blockwart/actions/runs/43525957700)
passed (2,999 tests, 39 subtests, OpenAPI, package and container gates).
Readiness reported the expected source revision and existing schema
20261028_0032; inventory/authorization invariants were reported unchanged.
Detailed operational evidence, backup locations and service metadata stay in
operator-owned records, not this public guide. This is a coordinator-recorded
release result, not a fresh production probe by the upstream integration author.

## Upstream PR is a different artifact

The upstream-ready branch normally merges main
b3c586c39f8d3bfd831565e44cb8f22ccc59d268 while preserving the UI release commits.
It intentionally includes upstream Safe, project instructions, audit code and the
20261111_0033 migration. These must not be dropped to imitate the UI-only release.
Conversely, this branch must **not** be promoted to the pinned UI-only deployment:
its schema/feature surface differs. Preparing or merging a PR is not authority to
run that migration, configure a Safe provider or change production dependencies.
The isolated production revision remains pinned until a separately approved
release plan says otherwise. The older release's green CI is not final-PR CI.

## Before any separately approved rollout

1. Record immutable candidate and currently deployed revisions/images. Verify
   required CI and applicable independent review/forge approval at the candidate.
2. Compare candidate code, dependency/entrypoint and migration heads with the
   deployed artifact. Stop for a separate migration/provider plan if they differ
   beyond the approved rollout scope. Never update a production checkout to main
   merely to make a UI branch current.
3. Record a rollback-compatible previous image and deployment settings. Take and
   validate the backups required by that release's data-risk policy; keep their
   private locations and credentials out of public source and logs.
4. Build the exact approved commit using the normal project release process.
   Change only the approved artifact/settings. Do not combine the UI rollout with
   unrelated schema, identity, permission, provider or historical-data changes.

## Minimal verification and rollback

Check the actual running revision/image, readiness/schema compatibility and the
changed user flow. Compare the agreed inventory/authorization invariants with the
recorded baseline. Reuse matching artifact evidence rather than repeating the
whole suite against production; use only authorized, non-destructive live checks.

On regression, restore the recorded previous artifact/settings only after proving
compatibility with the current database. Do not automatically downgrade schemas,
restore databases or rewrite audit timestamps. Those are separate data-risk
operations requiring their own approved plan. A UI-only artifact rollback needs
no database restore when the schema/data truly stayed unchanged.

Keep deployment and rollback details in the operator runbook; this document does
not contain host addresses, private filesystem paths, unit/container names or
secrets. See the general [deployment guide](../deployment.md) and the
[acceptance/evidence boundaries](ACCEPTANCE.md).
