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

## Notes

This importer is a bridge from the current Markdown operations index into Blockwart. It does not
parse arbitrary prose from references/*.md yet; it preserves links to those files as
source_references so humans and agents can jump back to the detailed runbooks.
