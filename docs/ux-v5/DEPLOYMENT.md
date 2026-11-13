# Local UI-v5 deployment — 2026-11-13

Owner-authorized local production deployment; no upstream publication.

- Production base: `1574db2cba6b0654a60215ce82f9511189a59865`.
- UI source: frozen `t0449-ux-v5` patch from base `b3c586c39f8d3bfd831565e44cb8f22ccc59d268`; all 28 source-manifest file hashes verified before extraction.
- UI patch backported with three-way application. Only two locale conflicts: retain production dictionaries and apply the 58 UI-changed keys per language; unrelated safe translations excluded.
- No upstream main update, safe deployment, schema migration, dependency or authorization configuration changes.
- Backup on lxc210: `/home/n3o/docker/blockwart/backups/ux-v5-20261113-2255/`: source/git/metadata archive, compose file, PostgreSQL custom dump, before.json. Dump archive readable with pg_restore.
- Baseline: schema `20261028_0032`, 77 catalog objects, 110 grants, four principals, zero ownerless objects.
- Rollback: switch production checkout back to its original `t0363-hardening` branch at `1574db2`, restore the backed-up compose file, force-recreate blockwart. No database restore required for this migration-free UI patch.

Pre-deploy gates: 277 regression tests passed (221.99s), 90 browser checks passed over six viewport/theme runs, zero browser console errors/external requests; Ruff, three changed JS syntax checks and git whitespace check passed. Desktop/mobile screenshots inspected. This is not a full repository suite.

Deployment gates and live evidence are recorded under ignored `exports/deploy/` and `exports/ux-v5/` in the isolated deployment worktree; final rollout verification is also recorded on the Blockwart service object.
