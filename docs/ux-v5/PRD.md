# Blockwart UX v5 — local implementation

Approved scope: five main destinations (catalog, topology, projects, hints, activity), no sidebar; integrations and release updates under Settings. Preserve all object columns and full parent rows. Global smart search defaults to all object types, with separate project-content results; catalog search follows its type. Scope expansion keeps text. Counts distinguish authorized stock, matching objects and visible object rows. Semantic tree levels Roots / Through hosts / Through services include direct hardware services, keyboard and independent saved state. Hint priority links toggle/reset without losing other filters. Activity presents compact Berlin time, defensible attribution and canonical target filters. Settings badge counts authorized available service updates only.

Out of scope: mobile fixed column, project-detail redesign, topology focus mode, identity/auth/RBAC/data-model changes, migrations, runtime configuration, external sends, commit/push/PR/merge/deploy.

Acceptance: focused tests plus real rendered flows at 1440/1024/390 in light/dark; invalid/empty/filter/pagination and direct-service regressions; no JS errors, whole-page horizontal overflow or lost columns; git diff --check clean. Existing inherited changes are preserved and audited, not assumed correct.

Risks: no Blockwart GitNexus index in complete 12-entry registry (caller impact UNKNOWN); trace shared routes/templates/JS directly. Existing principal data does not prove an Agent/System identity: display only evidenced account type; unresolved legacy IDs/logins remain unresolved. UI changes must not rewrite audit attribution or timestamps. Existing query services retain authorization and cursor semantics.

Rollback: uncommitted local diff only; preserve exports/ux-v5/inherited.patch, review/revert only this task's added hunks, never reset foreign changes. No publication or deployment in this task.
