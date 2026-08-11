# Markdown Import

Blockwart can import workspace infrastructure tables from TOOLS.md.

The importer is intentionally conservative:

- dry-run by default
- explicit apply flag required for database writes
- creates catalog system objects from infrastructure rows
- creates credential_reference objects only as pointers
- never resolves or stores credential values
- requires reviewed category evidence for every imported Network row
- merges known pilot objects instead of replacing their curated seed data
- emits a sanitized, content-digest-bound source coverage snapshot

## Dry Run

Use blockwart-import-markdown with the workspace TOOLS.md path, references root,
and the reviewed Network mapping. Classification is part of plan construction,
so missing, unknown, or conflicting evidence fails before schema or catalog
writes.

~~~bash
blockwart-import-markdown \
  --tools /home/zoe/.openclaw/workspace/TOOLS.md \
  --references-root /home/zoe/.openclaw/workspace \
  --network-mapping seeds/pilot_network_mapping.yaml
~~~

Example output:

~~~text
markdown_import_plan source_rows=39 objects=70 credential_references=0
source_coverage_snapshot digest=<sha256> entries=39 mappings=0 states={...}
markdown_import_dry_run apply=false
~~~

The dry run classifies each `System`/`Name` row without reading linked reference
prose. An omitted classification is `operational`; an explicit
`Classification` or `Source Classification` cell may be `operational`,
`retired`, `historical`, `research`, `migration`, `generated`, or `ignored`.
The optional `Catalog Intent`/`Mapping Intent` and `Decision Reason` cells use
the closed vocabulary printed by the command. A new operational row is
`unmapped_operational`; a historical or research row defaults to
`intentionally_unmapped` with its controlled, auditable reason. Classification
is never guessed from free-form usage, auth, or reference text.

`--record-coverage` records this dry-run snapshot in the database without
creating, updating, or deleting any catalog object. It is intentionally
incompatible with `--apply`:

~~~bash
blockwart-import-markdown \
  --database-url "$BLOCKWART_DATABASE_URL" \
  --tools /home/zoe/.openclaw/workspace/TOOLS.md \
  --references-root /home/zoe/.openclaw/workspace \
  --source-uri workspace://TOOLS.md \
  --create-schema --record-coverage
~~~

Only the stable source URI and entry ID, classification/intent/reason,
fingerprints, timestamps, presence, and explicit object mappings are recorded.
Markdown rows, source excerpts, credentials, arbitrary reference content, and
absolute collector paths are not stored in the coverage tables. Repeating the
same normalized inventory produces the same digest even at a later collection
time. A later snapshot carries deleted or renamed prior entries as
`missing_source`; changed fingerprints and deleted targets remain visible as
drift until the collector records a newer reviewed state.

## Apply

Use blockwart-import-markdown with database-url, apply, tools,
references-root, and the exact mapping accepted in dry-run. The deployed SQLite
database is under /opt/blockwart-data/blockwart.sqlite3.

~~~bash
blockwart-import-markdown \
  --database-url "$BLOCKWART_DATABASE_URL" \
  --tools /home/zoe/.openclaw/workspace/TOOLS.md \
  --references-root /home/zoe/.openclaw/workspace \
  --network-mapping seeds/pilot_network_mapping.yaml \
  --create-schema --apply
~~~

The parsed plan and every object schema are validated before database work
begins. Apply, including `--replace`, uses one database transaction for old-row
cleanup, all imported objects and relationships, and audit data. Any constraint,
lock, or unexpected import failure rolls the entire operation back; `--replace`
cannot leave an empty or partially replaced catalog.

Rows that do not define a canonical parent remain in the plan with
`data.placement.state=unassigned`. The importer does not infer placement from a
label, IP address, platform text, or linked reference document. A later explicit
`hosts` relationship clears that marker atomically.

## Notes

This importer is a bridge from the current Markdown operations index into Blockwart. It does not
parse arbitrary prose from references/*.md yet; it preserves links to those files as
source_references so humans and agents can jump back to the detailed runbooks.

Coverage means that an inventory entry is mapped or intentionally excluded. It
does not mean Blockwart stores the referenced runbook or its full source
content. HTTP and MCP never invoke this collector and never crawl the OpenClaw
workspace; they project only the latest already-recorded sanitized snapshot.
