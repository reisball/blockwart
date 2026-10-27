---
name: blockwart
description: "Use Blockwart for scoped infrastructure knowledge, access-reference routing and project records, with contract-led writes and canonical readback."
---

# Blockwart

## 1. Establish the route and boundary

Use the configured MCP connection for the **current agent's own service account**.
Public tool names below are `blockwart.*`; the host may add a connection prefix
such as `blockwart-<agent>`. The prefix is not an authorization boundary: confirm
the configured account, scoped grants and token audience with the operator.
Never switch accounts or broaden grants to work around a denial.

Treat Blockwart as canonical for mutable infrastructure knowledge, endpoints,
access references, topology, Runbooks and Project state. Keep implementation,
tests and repository decisions in their repository and link them. Keep secret
values only in the operator-designated protected store, never in catalog data,
tool arguments, chat, a quick reference or Git. A readable credential reference
is metadata, not permission to retrieve a secret or use the target system.

Use a verified exact route already supplied by trusted task context or the
workspace routing rule directly. Consult Blockwart for missing details,
conflicting sources, suspected drift and catalog work; do not make a catalog
preflight mandatory for every known repository action. An optional local index
is described in [Quick-reference workflow](references/quick-reference.md).
**Check:** target, agent connection, authorized scope and persistence home are clear.

## 2. Read the smallest sufficient context

- Reuse a known bare object ID; use typed `kind:id` references only where the
  published schema requests them. Never substitute a label for an ID.
- For unresolved targets, use `blockwart.search` with `projection: compact`,
  explicit filters and a small limit. Resolve each result's `capability_set`
  through `capability_sets`; summaries and discover-only stubs are not full data.
- Use `blockwart.get_context` for a bounded search with details. Use
  `blockwart.get_object_context` for one full object/current strong ETag or
  `blockwart.get_object_contexts` for up to 20 known IDs with `projection: full`
  when a bounded write set needs complete authorized state.
- Use dedicated access, graph, chronology or Project-record reads for those
  resources. Object context is not a substitute for `get_project_record`.
- Reuse resolved contracts, state and tokens while unchanged. Read again after
  relevant writes, stale preconditions, observed drift or changed task facts.
  A partial page, concealed ID or stub never proves absence or complete coverage.

**Check:** exact identity, visibility, current capabilities and required detail
are proven; unresolved or denied targets are not speculative write candidates.

## 3. Prepare one bounded catalog change

Freeze the target resources, operations, references and expected results within
the user's authorization. Read current full writable state for object changes,
access state for grants, and record state for targeted Project actions.

Call `blockwart.describe_schema` once per distinct kind and fully qualified
write intent, requesting `object_fields`, `write_intents`, `minimal_example` and
only the additional `relationships`/`errors` sections needed. Reuse the unchanged
contract across matching payloads. Inspect its creation path and authorization;
root creation, placement-child creation, device attachment and service-bound
credential-reference creation are not interchangeable alternatives after denial.
For Project records/actions, use the published tool input schemas instead.

Prefer a narrow command, such as `rename_object` for a label or
`act_on_project_record` for a targeted record action. An ordinary `update_object`
is replacement, not PATCH: preserve unrelated writable fields, summary, data and
provenance, not the entire read-response envelope. Never submit a compact result
as replacement data. For `credential_reference`, protected `data.reference` has
separate read/write permissions: omitted content is preserved, explicit `{}`
clears it. Do not reconstruct hidden content or request extra rights just to
preserve it. Read permission on metadata does not expose locator content.

Use an available update/rename preview when its reviewed diff is useful; it
neither reserves a revision nor grants authority. For operational access routing,
resolve the service's matching access method, endpoint and referenced credential
metadata before considering any external action. Load the separately authorized
procedure for the target; do not infer provider commands or secret-store access.
**Check:** contract, complete preserved state, exact authority and expected diff agree.

## 4. Write with the resource's own preconditions

| Operation | Required write basis |
| --- | --- |
| Object update/rename/delete; relationship change | Target object's current strong `etag` as `if_match` |
| Grant create/update/revoke; ownerless adoption | Current access-resource ETag; inspect Owner coverage and exact authority |
| Root, child or attached-device creation | Intent-specific authority and idempotency key; these tools have no `if_match` |
| Service-bound credential-reference creation | Service ETag, revision-bound zero-based `access_method_index`, idempotency key and `create_credential_reference` on that service |
| Legacy `save_project_record` | Project ETag plus idempotency key; preserve existing fields under that record contract |
| Targeted `act_on_project_record` | Exact record's `record_etag` as `if_match`, plus idempotency key for every action |
| Object comment / Project chronology append | Authorized target plus idempotency key; no `if_match` |

Pass opaque strong ETags unchanged; do not reconstruct them from revisions or
exchange object, access, Project and record tokens. Access ETags track the object
revision, so a real grant change can invalidate a previously read object ETag.
Keep one unique idempotency key with each exact request (16–128 visible ASCII
characters); reuse it only for an exact retry within the documented retention
window. A changed request is a new operation, not a retry with the old key.

For Owner changes, inspect access sources and any separately reported global
authority; ordinary write capability is not Owner authority. Preserve last-owner
and self-lockout protections. Ownerless objects need the dedicated, separately
authorized adoption command, not an ordinary grant edit or database workaround.
**Check:** every submitted command is authorized and bound to its own current state.

## 5. Verify and recover without guessing

Read back the affected resource: compare intended fields, preserved content,
links, visibility, permissions and revision; verify creation's Owner/self result
and service-bound linkage. A replay creates nothing again: object capabilities
are current, but original operation metadata may retain an old service/parent
ETag. Re-read that anchor before another conditional write.

Use Project record/history/assessment reads for structured work. Do not implicitly
convert legacy lists into records or remove adopted source text. Keep task
completion, requirement verification and use-case acceptance distinct. Chronology
is history, not a substitute for current canonical fields or repository evidence.

On `412`/stale ETag, stop dependent writes, re-read affected facts and reconcile
before preparing a new request; never just replace the ETag on an old payload.
On ambiguous timeout, establish the original outcome or retry the retained exact
idempotent request/key; do not duplicate creation/appends with a fresh key.
Handle validation errors using the published contract and sanitized field details.
Stop on permission mismatch, concealment, source conflict or unavailability;
report which work is blocked and continue only independent authorized work.
Do not try another agent, broader credentials, legacy inventory or direct database
access as an automatic fallback.

Report verified catalog/repository results separately from unperformed work.
Blockwart permissions and this skill do **not** authorize Runbook execution,
secret retrieval, authentication changes, infrastructure changes or deployment.
**Check:** readback proves the requested effect, and unresolved work is explicit.
