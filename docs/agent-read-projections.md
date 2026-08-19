# Agent Read Projections

An authorized read can be correct and still be too expensive. A fifty-hit
discovery page repeats a parent capability block for every hit, a twenty-object
batch loads a comment preview nobody asked for, and preparing one small write
used to mean reading the complete generated write contract.

Blockwart answers that with **projections**: a versioned, closed, server-side
choice of which published sections a read serializes. A projection is a
serialization decision and never an authorization one.

## What a projection never changes

A projected read and the full read of the same request agree on all of:

- which objects are returned, in which order, and under which cursor;
- the visibility decision for each object — detail, stub, or concealed;
- the identity (`id`, `ref`, `kind`, `label`) and `revision` of each object;
- the effective permissions of each object;
- the strong ETag, whenever the read serializes one at all;
- the concealment contract: a concealed id and a missing id stay
  indistinguishable under every profile and every field mask.

Because of that, `identity` and `state` are not selectable sections. They carry
exactly those invariants and are always serialized.

The contract version is published as `READ_PROJECTION_VERSION` and echoed in
every projected response. It is currently `1`.

## Profiles

`projection` selects one closed server-defined profile.

| Profile | Serializes | Use it for |
|---|---|---|
| `compact` | identity, state, the type-aware knowledge fields, and the orientation line | wide discovery, candidate lists, cheap known-id batches |
| `context` | `compact` plus network, integrity, monitoring, and the detail document | working on a bounded set of objects |
| `full` | the complete historical contract, including the comment preview | unchanged existing behavior |

`full` is the default. Sending no projection argument, or sending
`projection=full` with no field mask, returns exactly the response the surface
returned before this contract existed — same keys, same bytes. No existing
client is affected.

## The field mask

`fields` is the only field mask, and it is a closed server-defined vocabulary,
not a client-supplied path expression. There is no way to name a stored field,
so a mask can never widen a read or reach past an authorization decision.

The selectable sections are `knowledge`, `orientation`, `network`, `integrity`,
`monitoring`, `detail`, and `activity`.

A mask can only narrow: the resolved read is the intersection of the profile,
the surface, and the mask, plus the always-present core. Asking for `detail`
under `compact` therefore adds nothing, and the echoed `sections` list always
names what the response actually contains, so the narrowing is never silent.

## The comment preview

`include_recent_comments` switches the `activity` section — the bounded
newest-first comment preview and, for Projects, the chronology preview — on or
off independently of the profile. With an omitted projection, the
backward-compatible `full` default includes it. Explicit `compact` and
`context` reads omit it unless `include_recent_comments=true` asks for it.

Switching it off also stops the preview from being *read*: a discovery or batch
page that does not want the preview does not pay for it in database work either.

`list_comments` and `GET /api/v1/objects/{object_id}/comments` remain the
complete authorized comment history and are unchanged. The preview is a
convenience, never the record.

## Capability deduplication

A projected page or batch publishes one response-level `capability_sets` table,
and each item carries a `capability_set` key into it instead of its own
capability list.

Deduplication is by *exact* permission set. The key is derived from the exact
permissions in registry order, so two objects share a key only when their
effective rights are identical — a discover-only object and a fully writable one
can never collapse onto one capability block. A concealed placeholder
contributes no entry, so the table cannot become an existence oracle.

Full reads keep their inline `capabilities` list and never carry a
`capability_set`; projected reads do the opposite. The two contracts cannot be
confused for one another.

## Absent keys in a projected read

A projected read omits a key whose value would be null or empty rather than
serializing a placeholder. In a projected read an absent key means exactly what
a null value means in the full contract: this read carries no such value.

`summary` and its derived `search_snippet` are the one deliberate merge: a
projected read publishes the canonical `summary` and adds the snippet only when
it actually differs, which happens when there is no summary or when the snippet
had to be truncated.

## Type-aware compact projections

Under `compact` and `context`, an object publishes only the canonical short
fields of its own kind:

| Kind | Fields |
|---|---|
| `decision` | `decision_status`, `applies_to` |
| `project` | `project_category`, `project_status`, `related_assets` |
| `runbook` | `runbook_status`, `runbook_risk`, `runbook_applies_to` |

An asset kind carries no knowledge block at all, and a Runbook never carries
empty Decision or Project fields. Placement and operational state stay in the
always-present `state` section.

## Surfaces

| Surface | Projection controls |
|---|---|
| `GET /api/v1/objects`, `blockwart.search` | `projection`, `fields` |
| `GET /api/v1/context`, `blockwart.get_context` | `projection`, `fields`, `include_recent_comments` |
| `POST /api/v1/object-contexts`, `blockwart.get_object_contexts` | same three, in the request body |

`GET /api/v1/objects/{object_id}` and `blockwart.get_object_context` keep the
unchanged full contract. A single known-object read has nothing to deduplicate
and is the case where the complete detail is what the caller wanted.

## Scoped schema reads

`blockwart.describe_schema` is generated locally from the domain registry and
reads no catalog data. It can now be scoped three ways, all of which only ever
remove published material:

- `kind` — one object kind and the relationship types that accept it;
- `write_intent` — exactly one of the four write-intent tools;
- `sections` — a closed selection of `object_fields`, `write_intents`,
  `minimal_example`, `relationships`, and `errors`.

`relationships` contains only the relationship vocabulary, directed endpoint,
metadata-shape, and graph-rule contract. Relationship rejection and metadata
violation codes belong only to `errors`, alongside the object violation policy.
Select both sections when preparing a relationship write.

`minimal_example` gates every generated example, both the per-kind
`minimal_example` and the per-intent `example`. Selecting `minimal_example`
without `write_intents` returns each intent reduced to its identity and its
example.

Sending no scope returns the complete historical contract exactly as before.
Scoped reads echo `requested_write_intent` and the resolved `sections` fields.

## Measured before and after

These numbers are measured against the deterministic synthetic catalog in
`tests/synthetic_projection_catalog.py` and enforced by
`tests/test_read_projection_budget.py`. **They describe a synthetic audit case
only.** They are not a claim about the size of any real Blockwart instance, and
concrete instance sizes are deliberately not a public product contract.

Estimated agent tokens use a fixed, deterministic four-bytes-per-token
approximation over the exact serialized response. It is an auditable stand-in,
not a provider tokenizer result.

Synthetic 50-hit search page (`GET /api/v1/objects?limit=50`):

| Profile | Bytes | Estimated tokens | Share of full |
|---|---|---|---|
| `full` | 74,735 | 18,684 | 100% |
| `context` | 53,460 | 13,365 | 72% |
| `compact` | 20,165 | 5,042 | 27% |

Synthetic 20-object known-id batch (`POST /api/v1/object-contexts`):

| Profile | Bytes | Estimated tokens | Share of full |
|---|---|---|---|
| `full` | 72,234 | 18,059 | 100% |
| `context` | 32,640 | 8,160 | 45% |
| `compact` | 7,952 | 1,988 | 11% |

Generated write contract (`blockwart.describe_schema`):

| Scope | Bytes | Share of full |
|---|---|---|
| complete contract | 161,555 | 100% |
| one kind, one write intent, `object_fields` + `minimal_example` | 13,265 | 8% |
| one kind, one write intent, `minimal_example` only | 469 | 0.3% |

## Adoption guidance for agents

Prefer this ladder. Each step is cheap enough that skipping ahead is rarely
worth it.

1. **Discover** with `blockwart.search` and `projection=compact`. You get every
   candidate's id, ref, kind, label, revision, placement, operational state, the
   type-aware knowledge fields, and its effective permissions via
   `capability_sets`. Resolve `capability_set` once and reuse it.
2. **Narrow** by reading the compact page, not by fetching details for every
   hit. The compact page already tells you what you may do with each object.
3. **Work** on the objects you actually chose. Use
   `blockwart.get_object_contexts` with `projection=context` for a bounded set,
   or `blockwart.get_object_context` for one object when you want the complete
   detail.
4. **Ask for comments explicitly.** Batch and discovery reads carry no comment
   preview. Use `include_recent_comments` for a preview, or `list_comments` when
   you need the actual history.
5. **Prepare a write with a scoped schema read.** Call
   `blockwart.describe_schema` with the one `kind`, the one `write_intent`, and
   `sections: ["object_fields", "minimal_example"]`. Load `relationships` only
   when you are actually writing a relationship.
6. **Keep using full reads when you need them.** Nothing about the full
   contract changed, and a projection is never a substitute for an authorization
   decision, an audit record, or the complete comment history.

Client-side redaction is not an alternative to any of this: the server decides
what a caller may see, and a projection only decides how much of that already
authorized answer is serialized.

## Related contracts

- [Application read models](read-models.md)
- [API v1](api-v1.md) and the [API boundary contract](api-boundary-contract.md)
- [MCP server](mcp.md)
- [Object comments](object-comments.md)
- [Authentication and object authorization](auth-rbac.md)
