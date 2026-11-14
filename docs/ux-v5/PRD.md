# Blockwart UX v5 — local implementation

Approved scope: five main destinations (catalog, topology, projects, hints, activity), no sidebar; integrations and release updates under Settings. Preserve all object columns and full parent rows. Global smart search defaults to all object types, with separate project-content results; catalog search follows its type. Scope expansion keeps text. Counts distinguish authorized stock, matching objects and visible object rows. Semantic tree levels Roots / Through hosts / Through services include direct hardware services, keyboard and independent saved state. Hint priority links toggle/reset without losing other filters. Activity presents compact Berlin time, defensible attribution and canonical target filters. Settings badge counts authorized available service updates only.

Out of scope: mobile fixed column, project-detail redesign, topology focus mode, identity/auth/RBAC/data-model changes, migrations, runtime configuration, external sends, commit/push/PR/merge/deploy.

Acceptance: focused tests plus real rendered flows at 1440/1024/390 in light/dark; invalid/empty/filter/pagination and direct-service regressions; no JS errors, whole-page horizontal overflow or lost columns; git diff --check clean. Existing inherited changes are preserved and audited, not assumed correct.

Risks: no Blockwart GitNexus index in complete 12-entry registry (caller impact UNKNOWN); trace shared routes/templates/JS directly. Existing principal data does not prove an Agent/System identity: display only evidenced account type; unresolved legacy IDs/logins remain unresolved. UI changes must not rewrite audit attribution or timestamps. Existing query services retain authorization and cursor semantics.

Rollback: uncommitted local diff only; preserve exports/ux-v5/inherited.patch, review/revert only this task's added hunks, never reset foreign changes. No publication or deployment in this task.

## Visual-fidelity delta — 2026-11-13

Baseline: production 2e0fd02aee19b5b719fad1716b4101efaeb67430, isolated
fix/ux-v5-mockup-fidelity. Original UX-V5.md/interaktiv.html and original SOLL
screenshots are the design reference, not functional-test success.

- Catalog: compact search/scope row; stock/type/depth remain visible. View
  naming/save/load moves to the native View / Ansicht disclosure, with Escape
  dismissal and focus return. Right inspector is contextual: hidden initially,
  shown by selecting a row, safely closable; detail links remain.
- Search: compact query/type/Esc row, grouped scrolling results, no full-width
  primary submit or redundant heading. Native dialog focus and existing
  Enter/Escape/type expansion remain; /search works without JavaScript.
- Hints: priorities and actionable results first. All 13 coverage diagnostic rows
  remain in a secondary, initially collapsed disclosure after results. Additional
  filters are collapsible, automatically open when active; severity stays visible.
- Activity: readable target/event/date controls; kind/parent remain under More
  filters, open when active. Friendly date explicitly means UTC date; editing
  sends midnight UTC as RFC3339, clearing removes it. An existing exact instant
  including offset/time is preserved untouched until date is edited. Without JS
  the original RFC3339 input remains functional. Berlin event display, stored
  timestamps, attribution and backend filters remain unchanged. Service-account
  type is labelled Servicekonto / Service account, not Agent.
- Projects: remove redundant hero copy, keep workspace search and project links;
  category/status controls are reachable by disclosure, open when active.
- Scoped typography/spacing only: no object-editor, schema, auth, identity,
  migration or monitoring changes. Tables preserve data and scroll locally.

Acceptance: existing behavioral assertions plus disclosure/date/label checks;
actual Chromium screenshots at 1440/1024/390 in Light/Dark, inspected against
original SOLL; measured toolbar/first-result coordinates; zero application console
errors or whole-page overflow. Differences from synthetic SOLL data and local table
scrolling are documented, not disguised as pixel-identical parity. Parent owns
release, independent review if needed, remote CI, deployment and upstream PR.

Timestamp discrepancy is separate: database/session-local audit defaults are not
repaired by subtracting an hour in the UI. See exports/ux-v5-polish/HANDOFF.md.

## Upstream integration phase (2026-11-14)

The original local-only publication/rollback boundary above is historical, not a
claim that the implementation remains uncommitted. The isolated UI release is
committed and separately deployed at 8128797. This phase preserves its approved
criteria and compact SOLL composition while normally merging upstream main and
refreshing public evidence/runbook documentation. Main owns publication, final-head
CI and review gates. No additional production changes or migrations are authorized
by this integration; upstream Safe/schema content is retained in the PR only.
