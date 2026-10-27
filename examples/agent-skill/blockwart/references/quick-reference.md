# Optional workspace quick reference

This is an opt-in, manually maintained **derived index**, not a second inventory.
Blockwart remains authoritative. The [skill](../SKILL.md) works without this file;
this example adds no automatic generation or synchronization feature.
All IDs, dates, labels and counts below are fictional documentation examples.
Public links target `main`, which may describe the next release; use the matching
reviewed revision for your installed application and MCP wrapper.

## Copyable workspace routing rule

Copy and adapt this rule into your workspace instructions if useful:

```text
Blockwart is authoritative for catalog facts and project progress. Our optional
quick-reference.md is a dated routing index, not operational documentation.
Use an already known, verified route directly for an authorized task; consult
Blockwart for missing, conflicting or changed routes, drift and catalog work.
Resolve exact returned IDs; never infer authority from the index. Keep secrets,
secret locators and changing operational/project details out of this index.
After authorized catalog changes, re-read and reconcile only the checked facts.
Keep unresolved entries visible; absence or concealment is not deletion proof.
```

An exact endpoint, if locally included, is only a derived routing hint. Revalidate
it against Blockwart when stale, conflicting or showing drift. It is not a
runbook, execution instruction, or proof that the destination is authorized.

## Define the scope before collecting

1. Record an **explicitly authorized scope**: a selected set of object/project
   IDs, an agreed project boundary, or another precisely defined selection.
   State whether descendants are included. Read authority is not write authority.
2. Establish the expected set using the authorized source for that definition.
   Direct Owner assignments are one **optional example**, not a global rule,
   not a requirement for using this skill, and not the same as effective access.
3. If adopting a principal-assignment audit, use the complete paged
   `blockwart.list_admin_principal_assignments` views: traverse both
   `assignment_type=direct` and `assignment_type=effective` to null `next_cursor`.
   This requires existing admin authority and reveals only objects where the
   caller has `manage_access`; do not obtain broader credentials for the index.
   Filter direct Owner targets from the direct view, not inherited/effective
   rows. Effective rows can repeat an object across sources: merge by exact
   `object_id`, not label, and do not count sources as objects.
4. For the caller's own direct grants, `blockwart.list_own_direct_grants` with
   `role=owner` is a self-only alternative requiring no admin role. Follow every
   `next_cursor` to null. It excludes inherited/effective access; a `subtree`
   grant is one anchor, not a list of descendants. Expand descendants only if
   the chosen scope explicitly includes them, using authorized catalog reads.
5. Assignment visibility is caller-relative, never proof of whole-catalog
   coverage. If traversal is interrupted, output truncated, authority changes,
   or the selection cannot be enumerated, report **partial** coverage. Restart
   invalid cursors and re-traverse if grants change; paging is not a snapshot.

See [permissions and scope](https://github.com/reisball/blockwart/blob/main/docs/auth-rbac.md) and
[paged assignment reads](https://github.com/reisball/blockwart/blob/main/docs/mcp.md).
An empty search or a principal summary is not a complete scope enumeration.

## Build the smallest useful index

Read each selected object with `blockwart.get_object_context`; confirm full
`visibility: "detail"`, exact identity and kind. A discover-only stub is not a
verified full read. Use current authorized Project reads for project identity;
leave its changing workspace information in Blockwart.

Store only routing facts: label, brief purpose, kind, exact bare ID, canonical
entry or responsible Runbook/skill link, optional typed reference, and check date.
IDs below are examples, not IDs to substitute into another catalog. `demo-service` and `demo-runbook` match the
fictional [quickstart seed](https://github.com/reisball/blockwart/blob/main/seeds/quickstart.yaml); the other two
IDs illustrate optional entries not supplied by that seed.

### Objects — fictional reconciliation 2026-10-27

| Label | Brief purpose | Kind | Exact bare ID | Typed reference | Responsible skill | Last verified |
| --- | --- | --- | --- | --- | --- | --- |
| Example service | Demonstrate a connected service | service | `demo-service` | `service:demo-service` | [Catalog workflow](../SKILL.md) | 2026-10-27 |
| Inspect Example service | Document an inspection | runbook | `demo-runbook` | `runbook:demo-runbook` | [Catalog workflow](../SKILL.md) | 2026-10-27 |
| Example credential reference | Identify credential metadata | credential_reference | `demo-credential-reference` | `credential_reference:demo-credential-reference` | [Catalog workflow](../SKILL.md) | 2026-10-20 |

The credential-reference entry is **unresolved in this fictional pass**; its old
check date is retained, not refreshed. A credential-reference ID is neither a
credential nor authority to access its secret store. Do not copy its protected
locator (`reference.name`, `path`, `key`, `item_hint`) or secret value here.

### Projects — fictional reconciliation 2026-10-27

| Label | Brief purpose | Kind | Exact bare ID | Typed reference | Responsible skill | Last verified |
| --- | --- | --- | --- | --- | --- | --- |
| Example project | Group related work | project | `demo-project` | `project:demo-project` | [Catalog workflow](../SKILL.md) | 2026-10-27 |

Keep status, blockers, next actions, versions, deployment details, commands and
access procedures in Blockwart, not these tables. The same applies to passwords,
tokens, private keys, session data, credential contents and secret-store locators.

### Bare ID versus typed reference

Arguments for `blockwart.get_object_context` (not a shell command); pass the exact
returned bare ID to `object_id`, for example:

```json
{"object_id": "demo-service"}
```

`service:demo-service` is a typed reference for fields whose published schema
requires one; it is **not** the `object_id`. Do not construct IDs from labels,
strip prefixes from opaque IDs by guesswork, or interchange these forms.
See the [first authorized read](https://github.com/reisball/blockwart/blob/main/docs/agent-quickstart.md#first-success-list--search--full-context).

## Reconcile and report coverage

1. Re-enumerate the same defined scope and compare **unique IDs** with the index.
   Distinguish expected targets, retained entries, verified entries and unresolved
   entries; counts alone cannot establish that the sets match.
2. Re-read relevant canonical objects/projects after an authorized change. Update
   only verified routing facts and their dates, not every date in the file.
   A reconciliation date records a pass, not blanket freshness of all entries.
3. Retain unresolved entries with the previous verified facts/date and mark the
   verification gap. A concealed/missing `404`, denied read, failed search or
   vanished assignment does not prove deletion. Do not remove on that evidence;
   resolve through the authorized scope owner/source, without privilege probing.
4. Mark coverage **complete** only relative to the declared scope when enumeration
   completed and every target was checked. Otherwise mark **partial**, explain
   gaps and keep the expected count unknown if it cannot be established.
5. Example report for the fictional selected set above: **partial**; expected
   unique IDs 4, indexed 4, verified this pass 3, unresolved 1. Objects: 2/3
   verified; projects: 1/1. No entry was removed. The unresolved credential
   reference still carries its older date. These counts describe index coverage,
   not project delivery or catalog-wide access.
