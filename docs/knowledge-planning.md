# Write-free Knowledge planning

`blockwart-knowledge-plan` is the Phase-A trust boundary for reviewed
classification of private source inventories. It reads one versioned manifest,
the exact declared local source set, and optionally one controller-supplied
sanitized target snapshot. It has no database, HTTP, authentication, runtime,
subprocess, comment, audit, or apply integration and exposes no mutation flag.

The source disposition vocabulary is closed:
`asset_fact`, `runbook`, `decision`, `project_research`, `external_document`,
`historical`, `retired`, `migration`, and `ignored`. Comments are absent from
version 1; `comment_candidate` and every other unknown class are rejected.
Historical, retired, migration, template, and general documentation entries
cannot carry a planned target or relation.

## Version-1 inputs

The manifest uses `schema_version: 1` and `planner_version: "1"`. It binds the
exact implementation commit/tree, a closed source set with per-document
SHA-256 values and a canonical bundle digest, and complete document-to-entry
coverage. Each entry records a disposition, optional typed target, explicit
source-to-target field mappings, non-operational typed relations, provenance,
ambiguity and conflict state, exact missing requirements, unsafe findings, and
a bounded review rationale. Unknown fields, duplicate map keys, duplicate or
partial coverage, unstable IDs, conflicting field mappings, secret-shaped
content, ACL-shaped content, invalid target kinds, and invalid relations fail
closed.

Field mappings use `evidence: explicit`; the planner never supplies an omitted
status, risk, approval, author, timestamp, command, provenance, fallback,
category, conclusion, or relationship. A candidate is validated through the
same canonical catalog object and typed-reference contracts as other Blockwart
writers. An existing asset fact must name an existing asset in the sanitized
target snapshot. Credential references remain typed references only; secret
values are rejected at every nesting depth. Source command text is inert data
and is never executed.

Print the reviewed machine contracts with:

```bash
blockwart-knowledge-plan --print-schema manifest
blockwart-knowledge-plan --print-schema target-snapshot
blockwart-knowledge-plan --print-schema result
```

The optional target snapshot also uses version 1. It contains only the exact
relevant object IDs, kinds, positive revisions, sanitized canonical object
state, and presence evidence for every proposed relation. Its embedded digest
is recomputed with domain separation; a controller can additionally provide an
independently retained digest with `--expected-target-digest`. Missing, extra,
stale, or kind-mismatched evidence prevents a plan digest.

## Digests and output

Canonical JSON is UTF-8, uses sorted object keys and compact separators, rejects
non-finite numbers, and normalizes every semantically unordered collection by
stable identity. Digests prepend `blockwart:knowledge:<domain>:v1` plus a line
feed before hashing with SHA-256.

`classification_digest` binds the normalized complete manifest, including the
exact source snapshot, reviewed mappings, schema/planner versions, and
implementation commit/tree. `target_snapshot_digest` binds the supplied target
evidence. `plan_digest` binds both digests and every accepted version and is
present only when the target snapshot is complete. A source-only plan is always
`apply_ready=false` with the exact `missing_target_snapshot` blocker; its
classification digest must never be represented as an apply-ready plan digest.

JSON output contains deterministic source, entry, disposition, target-action,
relationship, coverage, unsafe, missing-evidence, conflict, and blocker counts.
Comment and audit deltas are fixed at zero. The summary form contains counts and
digests only:

```bash
blockwart-knowledge-plan \
  --manifest examples/knowledge-plan/manifest.json \
  --source-root examples/knowledge-plan/sources \
  --implementation-commit 1111111111111111111111111111111111111111 \
  --implementation-tree 2222222222222222222222222222222222222222
```

Adding the synthetic `target-snapshot.json` demonstrates a complete digest, but
the command remains a dry run and still has no apply path. Any productive
catalog mutation, backup/rollback execution, comment, audit record, coverage
snapshot, or routing change requires a separately reviewed later phase.
