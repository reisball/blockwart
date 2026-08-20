# Source coverage and import drift

Source coverage is a read-only inventory contract. It answers whether each
configured source entry is current, stale, absent, ambiguous, duplicated,
intentionally excluded, or orphaned from the visible catalog. It never creates,
updates, or deletes a catalog object; a future productive apply workflow is a
separate concern.

## Snapshot model

An explicit collector records an immutable snapshot with a content-based SHA-256
digest. Each entry has a stable sanitized source URI, optional stable entry ID,
controlled classification and catalog intent, controlled decision reason,
presence, observed time, and opaque entry/source fingerprints. Mapping edges
form an explicit many-to-many registry and carry object ID, primary/derived
role, imported entry fingerprint, and import/verification times.

The database stores no Markdown row, excerpt, reference prose, arbitrary source
file, or credential value. `CatalogProvenance.source_ref` remains object
provenance and is not this mapping registry. Coverage of an inventory URI also
does not mean its reference content is stored in Blockwart.

Classifications are `operational`, `retired`, `historical`, `research`,
`migration`, `generated`, and `ignored`. States are `mapped_current`,
`mapped_stale`, `unmapped_operational`, `intentionally_unmapped`,
`orphaned_catalog_reference`, `missing_source`, `ambiguous_mapping`,
`duplicate_mapping`, and `source_changed_since_import`. The domain resolver is
the only implementation of this vocabulary; Markdown dry-run, REST, and MCP
project it rather than maintaining separate rules.

An identical normalized inventory has the same digest regardless of collector
row order, database row order, mapping order, or collection timestamp. A new
semantic snapshot becomes current by `collected_at`, with digest as the stable
tie-breaker. Prior entries absent from a later Markdown collection are retained
as `missing_source`; source content itself is not retained.

## Trust and authorization boundary

Only the explicit offline collectors open declared source files:
`blockwart-import-markdown` opens `TOOLS.md`, and
`blockwart-source-coverage` hashes the exact closed source set declared by a
reviewed manifest. Their record operations are separate from catalog apply.
API, MCP, UI, and other runtime requests read only the recorded snapshot and
referenced catalog rows; they do not crawl a workspace, open source URIs, or
persist a refreshed result. See [Reviewed Knowledge source
coverage](source-coverage-manifest.md) for the generic collector contract.

The ordinary `mapped` projection removes mappings without object `read`
permission before state resolution. Entries left without a visible mapping are
omitted. Thus hidden object existence cannot affect ordinary details, states,
counts, response digests, cursors, or errors. Source-only facts have no object
ACL: only the explicit existing platform `admin` authority may request
`scope=all`. That platform role does not bypass catalog ACLs: concealed existing
mappings remain absent, while missing targets and entries without object edges
use the source-only authority.

Authorization and exact filters precede summary/count calculation. The summary,
snapshot counts, optional total, and every paginated detail page therefore
describe the same authorized filtered set. Coverage cursors bind principal and
effective policy, normalized filters, scope, direction, page size, ordering,
and the authorized projection digest.

## Lifecycle

1. Run the Markdown command without flags to review the dry-run states.
2. Run it again with the reviewed inputs, database URL, and
   `--record-coverage` to persist only the snapshot.
3. Query `GET /api/v1/source-coverage` or
   `blockwart.get_source_coverage`; use `scope=all` only from a platform-admin
   principal when source-only gaps are required.
4. Re-collect after a reviewed source or mapping change. Runtime requests never
   refresh the snapshot implicitly.

See `markdown-import.md` for collector columns and CLI output, `api-v1.md` for
REST pagination, `mcp.md` for the tool projection, and `provenance.md` for the
boundary between mapping edges and object provenance.
