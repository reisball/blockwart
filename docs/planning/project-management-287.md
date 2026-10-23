# Project management implementation plan · #287

Authorized 2026-10-23. Candidate 0.2.0 is a post-completion decision, not a release or version bump. Main baseline: `c0d6c8d1b53bcbdca650dae69c45c7361cb51530`.

## Scope and evidence

Implement all nine child issues with the synthetic practice scenarios recorded in their comments. The general RBAC concept #297 and OpenClaw wrapper #173 are separate. Existing projects are never automatically reclassified.

| Issue | Deliverable | Verification |
|---|---|---|
| [#288](https://github.com/reisball/blockwart/issues/288) | Feature/Projekte: Use Cases, Anforderungen und Task-Zuordnungen typisiert modellieren | Shared service + API/MCP/UI; acceptance criteria from issue and practice comments |
| [#295](https://github.com/reisball/blockwart/issues/295) | Feature/API/MCP: Gezielte Projektaktionen und konfliktarme Record-Versionierung ergänzen | Shared service + API/MCP/UI; acceptance criteria from issue and practice comments |
| [#289](https://github.com/reisball/blockwart/issues/289) | Feature/UI: Projekt-Hierarchie als navigierbaren Baum mit kurzen Kennungen darstellen | Shared service + API/MCP/UI; acceptance criteria from issue and practice comments |
| [#290](https://github.com/reisball/blockwart/issues/290) | Feature/Projekte: Aufgaben-Detailansicht mit eigener Kommentar-Timeline ergänzen | Shared service + API/MCP/UI; acceptance criteria from issue and practice comments |
| [#291](https://github.com/reisball/blockwart/issues/291) | Feature/Projekte: Abnahmekriterien, Nachweise und fachliche Abdeckung getrennt führen | Shared service + API/MCP/UI; acceptance criteria from issue and practice comments |
| [#292](https://github.com/reisball/blockwart/issues/292) | Feature/Projekte: Prioritäten, Abhängigkeiten, Zuständigkeit und Archivierung für Tasks | Shared service + API/MCP/UI; acceptance criteria from issue and practice comments |
| [#293](https://github.com/reisball/blockwart/issues/293) | Feature/Projekte: GitHub-Repositories und Issue-/PR-/Commit-Bezüge strukturiert verknüpfen | Shared service + API/MCP/UI; acceptance criteria from issue and practice comments |
| [#296](https://github.com/reisball/blockwart/issues/296) | Feature/Projekte: Kanonischen Arbeitsstand und expliziten Übergang von Legacy-Listen klären | Shared service + API/MCP/UI; acceptance criteria from issue and practice comments |
| [#294](https://github.com/reisball/blockwart/issues/294) | Feature/GitHub: Lesenden Task-Statusabgleich mit eindeutiger Führungsregel anbieten | Shared service + API/MCP/UI; acceptance criteria from issue and practice comments |

## Delivery sequence

1. Typed models, immutable history and additive migration; record-scoped CAS actions without weakening project invariants (#288/#295).
2. Hierarchy, task detail/discussion, planning, repository references (#289/#290/#292/#293).
3. Requirement baselines/revisions, scoped evidence, explicit acceptance and legacy authority (#291/#296).
4. Opt-in read-only GitHub observation with one leading issue and explicit freshness/error state (#294).
5. Full regression, SQLite/PostgreSQL migration preservation, API/MCP parity and browser workflow; independent exact-revision review and documented fixes.

## Invariants

- Task done, implemented, criteria verified and requirement/use-case acceptance are separate facts.
- Decision completion never supplies implementation proof; evidence binds a requirement revision, criterion set, subject/run/version and scope.
- Old evidence is not silently reused on changed requirements. Explicit reuse decisions and exceptions retain actor/time/reason.
- Existing UUIDs, record JSON, history, project lists and curated summaries survive migration. New short codes supplement UUIDs.
- Legacy imports are explicit, deduplicated and retain original text; imported entries point to the structured authority, not two current sources.
- Project instance, authorization, trusted channel provenance, idempotency and atomic project CAS remain enforced.
- No credential values in data or GitHub; integration is opt-in, GET-only, no implicit acceptance, no background integration credential provisioning.

## Data-preserving verification

Use synthetic databases first. For live-state migration rehearsal use a verified consistent backup in an isolated test instance; compare original objects, relationships, grants, records and append-only histories before/after. Do not migrate or overwrite the live instance merely to run tests. Any authorized instance test creates isolated synthetic records; existing POC content is not edited. Preserve recoverable backup and document integrity evidence before any rollout.

## Coordination

Nova owns integration, repository evidence, implementation and final verification. Bounded native subagents audit acceptance/migration and GitHub semantics and implement non-overlapping UI files. Workboard `blockwart`; session Goal tracks the full objective. PRs reference issues without automatic closure. Merge, issue closure and final release are separate decisions unless explicitly authorized.
