# Canonical Decision Objects

Decision is a top-level knowledge-object kind for durable, agent-readable choices. It uses the
existing catalog identity, provenance, authorization, revision, ETag, idempotency, audit, and
secret-safety contracts. It is not an asset: `lifecycle` and `health` are always absent and are
rejected on writes. The compatibility `status` field remains independent of the Decision
lifecycle below.

## Canonical data

`blockwart.domain.object_schema` is the validation source used by UI, REST/API v1, Agent API,
MCP, seed/import services, and the checked-in OpenAPI projection. MCP
`blockwart.describe_schema(kind="decision")` publishes the executable contract, including the
closed `decision_status` values:

- `proposed`: recorded for consideration, not yet adopted;
- `accepted`: adopted and complete enough to act on;
- `superseded`: replaced by the Decision in `superseded_by`;
- `deprecated`: still historical but intentionally discouraged or no longer applicable;
- `rejected`: considered and explicitly declined.

The canonical data fields are:

| Field | Shape | Contract |
|---|---|---|
| `decision_status` | enum | Required; one of the five values above |
| `context`, `decision`, `rationale` | text | Trimmed; all three are nonblank for `accepted` |
| `alternatives`, `consequences` | text arrays | Up to 50 nonblank entries, each at most 2,000 characters |
| `decided_at`, `effective_at` | RFC 3339 timestamp | `decided_at` is required for `accepted`; timestamps require a timezone and normalize to UTC |
| `review_after` | RFC 3339 timestamp | Optional review trigger |
| `applies_to` | typed-reference array | Existing `host`, `system`, `network`, `device`, or `service` targets |
| `related_projects` | typed-reference array | Existing `project` targets |
| `related_runbooks` | typed-reference array | Existing `runbook` targets |
| `related_decisions` | typed-reference array | Existing `decision` targets |
| `supersedes` | typed-reference array | Decisions replaced by this Decision |
| `superseded_by` | typed reference | The successor required by `superseded` |
| `docs` | source-entry array | Up to 25 closed source entries; see below |

Each `docs` entry has this exact machine-readable shape:

| Entry field | Contract |
|---|---|
| `source_type` | Required: `original`, `documentation`, or `reference` |
| `title` | Required nonblank human label, at most 200 characters |
| `url` | Required absolute HTTP(S) URL, at most 2,048 characters, with no embedded username/password or secret-shaped query parameter |
| `published_at` | Optional RFC 3339 timestamp with a timezone, normalized to UTC |

No other entry keys are allowed. The global nested secret-key/value checks still apply. Schemes
such as `javascript:` and `data:`, credential-bearing URLs, and executable payload fields are
rejected. The UI renders a valid URL as an external link with `noopener noreferrer`; Blockwart
does not fetch, preview, or execute the source.

Unknown extension fields remain preserved under the additive catalog compatibility policy.
Globally forbidden secret-shaped keys and values remain rejected at every nesting depth.

Every typed reference must resolve to an existing object of the asserted allowed kind. Authorized
commands additionally require read access to every target. Missing, kind-mismatched, and concealed
targets share the same fail-closed public result. Read projections omit links to targets the caller
cannot discover; filters never turn those targets into an existence oracle.

Supersession is directed from the replaced Decision to its successor. `superseded_by` and the
inverse meaning of `supersedes` feed one shared graph validator. Self-links and direct or indirect
cycles are rejected before persistence.

## Accepted to superseded example

An accepted Decision can be recorded as:

```json
{
  "id": "deploy-blue-green",
  "kind": "decision",
  "label": "Use blue-green deployment",
  "status": "active",
  "data": {
    "schema_version": 1,
    "decision_status": "accepted",
    "context": "In-place releases make rollback slow and unpredictable.",
    "decision": "Deploy application releases with a blue-green environment pair.",
    "rationale": "Traffic switching gives a small, observable rollback boundary.",
    "alternatives": ["Continue in-place upgrades", "Adopt canary releases"],
    "consequences": [
      "Operate two environments during a release.",
      "Reserve enough capacity for the inactive environment."
    ],
    "decided_at": "2026-08-11T12:00:00Z",
    "effective_at": "2026-08-18T08:00:00Z",
    "review_after": "2027-02-11T12:00:00Z",
    "applies_to": ["service:blockwart"],
    "related_projects": ["project:delivery-modernization"],
    "related_runbooks": ["runbook:blue-green-release"],
    "docs": [
      {
        "source_type": "original",
        "title": "Architecture review record",
        "url": "https://engineering.example/records/blue-green",
        "published_at": "2026-08-11T12:00:00Z"
      }
    ]
  }
}
```

Before superseding it, append an operational note to that exact Decision through the shared object
comment timeline. For example, the MCP tool request is:

```json
{
  "object_id": "deploy-blue-green",
  "body": "Rollout observation: rollback completed within the agreed five-minute window.",
  "idempotency_key": "deploy-blue-green-comment-0001"
}
```

Send that object as the arguments to `blockwart.add_comment`. The tool uses its configured
MCP-audience service token; credentials are runtime configuration and are not tool arguments. This
is an append-only object comment on `deploy-blue-green`, not a Decision data field. Its Markdown
body remains separate from the Decision mutation audit payload; the audit timeline receives only
minimal `comment_create` metadata. The comment stays in the object's timeline when its Decision
status later changes. See [Object comments](object-comments.md) for the complete authorization,
idempotency, audience, rendering, timeline, and audit contract.

Later, create the accepted successor Decision `deploy-progressive` and include
`supersedes: ["decision:deploy-blue-green"]` on it. Finally, update the old
`deploy-blue-green` record to `decision_status: "superseded"` with
`superseded_by: "decision:deploy-progressive"`. Each object update retains its own ETag and audit
event. This chronology writes the successor first and the original second; either side may be
submitted first because graph integrity is enforced after every write, and the final reciprocal
form is explicit and agent-readable.

## Search and context

API v1 `/objects` and `/context`, Agent API `/search` and `/context`, and MCP `search` and
`get_context` accept `decision_status` and `applies_to`. `applies_to` uses one exact asset
`kind:id` reference. Attribute filters require detail visibility; discover-only Decision stubs do
not match. A concealed `applies_to` target yields no match and no distinguishing target detail.

## Legacy classification and migration

Existing free-form Decision rows without `decision_status`, and rows whose historical `docs`
values do not match the closed source-entry shape, remain readable and keep their IDs and data.
Any attempted rewrite must supply a complete canonical Decision; Blockwart never guesses a status
or converts ambiguous source values. A mapping may explicitly replace `docs` after human review;
the dry run reports invalid canonical source values as blockers and never discards them.

`blockwart-db decisions` is a read-only dry run by default. It reports every canonical row and an
explicit blocker for each legacy or invalid row. A reviewed version-1 YAML mapping may supply a
shallow `data_patch` and the SHA-256 of the exact canonical JSON representation of the old data.
The patch is merged over the old document, so unmentioned legacy fields are preserved:

```yaml
version: 1
decisions:
  - object_id: deploy-blue-green
    expected_data_sha256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    data_patch:
      decision_status: accepted
      context: In-place releases make rollback unpredictable.
      rationale: Traffic switching provides a bounded rollback.
      decided_at: "2026-08-11T12:00:00Z"
```

Review the dry run first:

```bash
blockwart-db --mapping decisions.yaml decisions
```

Only the separately explicit apply command mutates storage:

```bash
blockwart-db --mapping decisions.yaml --apply decisions
```

Apply fails if any blocker remains or any row changed after planning. Successful changes increment
the existing revision and add a `decision_normalize` audit event. The implementation changes no
table shape, so no Alembic revision is required; the same workflow operates on SQLite and
PostgreSQL 16 while preserving catalog IDs, foreign-key/sequence state, and unrelated rows.
