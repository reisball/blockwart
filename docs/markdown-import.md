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
markdown_import_plan source_rows=39 objects=70 credential_references=33
markdown_import_dry_run apply=false
~~~

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
