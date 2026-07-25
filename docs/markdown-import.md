# Markdown Import

Blockwart can import workspace infrastructure tables from TOOLS.md.

The importer is intentionally conservative:

- dry-run by default
- explicit apply flag required for database writes
- creates catalog system objects from infrastructure rows
- creates credential_reference objects only as pointers
- never resolves or stores credential values
- merges known pilot objects instead of replacing their curated seed data

## Dry Run

Use blockwart-import-markdown with the workspace TOOLS.md path and references root.

Example output:

~~~text
markdown_import_plan source_rows=39 objects=70 credential_references=33
markdown_import_dry_run apply=false
~~~

## Apply

Use blockwart-import-markdown with database-url, apply, tools, and references-root. The deployed
SQLite database is under /opt/blockwart-data/blockwart.sqlite3.

The parsed plan is built before destructive work begins. Apply, including `--replace`, uses one
database transaction for old-row cleanup, all imported objects and relationships, and audit data.
Any validation, constraint, lock, or unexpected import failure rolls the entire operation back;
`--replace` cannot leave an empty or partially replaced catalog.

Rows that do not define a canonical parent remain in the plan with
`data.placement.state=unassigned`. The importer does not infer placement from a
label, IP address, platform text, or linked reference document. A later explicit
`hosts` relationship clears that marker atomically.

## Notes

This importer is a bridge from the current Markdown operations index into Blockwart. It does not
parse arbitrary prose from references/*.md yet; it preserves links to those files as
source_references so humans and agents can jump back to the detailed runbooks.
