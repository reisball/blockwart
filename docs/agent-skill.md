# Reusable agent skill

After the [agent quickstart](agent-quickstart.md) has produced a successful scoped
read, use the repository's [Blockwart skill template](../examples/agent-skill/blockwart/SKILL.md)
to give an assistant a repeatable read → prepare → write → verify workflow.
It is optional client-side guidance, not a server feature, an authorization
grant or an automatically installed integration.

The template complements the new human/agent onboarding paths: it starts with
an **already connected** client and does not repeat installation, token issuance
or the complete API reference. It can also guide a non-agent automation design.
No LLM is required on the Blockwart server.

## Copy and adapt

1. Use a reviewed repository checkout matching the application's installed
   release/revision. Documentation on `main` may describe the **next** release;
   neither a merged template nor a GitHub release deploys an instance. Complete
   the [stdio setup and first read](agent-quickstart.md#configure-a-stdio-mcp-client)
   before adding workflow instructions.
2. Copy the **whole** `examples/agent-skill/blockwart/` directory, preserving
   `SKILL.md` and `references/quick-reference.md`, into a skill directory your
   client supports. For a client that discovers workspace `.agents/skills`, a
   copy from the reviewed checkout's root could be:

   ```bash
   mkdir -p /absolute/path/to/agent-workspace/.agents/skills
   cp -R examples/agent-skill/blockwart /absolute/path/to/agent-workspace/.agents/skills/blockwart
   ```

   The destination must not already exist; review or back it up before replacing
   an existing skill. This example is not a universal client installation path.
   Clients without AgentSkills support can adopt the workflow in their normal
   instruction mechanism; do not claim automatic skill discovery there.
3. Keep valid `name`/`description` YAML metadata. Bind the agent's **own** MCP
   connection and document the client-visible tool prefix in local instructions.
   The quickstart's `mcpServers.blockwart` entry is a connection name, not a
   required namespace: a host may expose `blockwart-<agent>` or another prefix.
   All refer to the published `blockwart.*` tools only if that connection is
   configured accordingly. A name does not establish identity or grants.
4. Choose the canonical data-routing rule, approved secret-store provider and
   relevant Runbook/skill links for your installation. Do not copy another
   workspace's identity, private URLs, account credentials, paths or broad roles.
   Store only secret **references**, never secret values, in catalog/workflow
   data; keep the bearer-token file protected as in the quickstart. Credentials
   and external actions still require their own authorization.
5. Optionally adopt the [quick-reference workflow and synthetic example](../examples/agent-skill/blockwart/references/quick-reference.md).
   Choose an explicit authorized scope and a workspace-visible location, then
   add the routing rule there. No particular memory filename is required;
   respect the host's shared-session visibility rules. Skip the index entirely
   if a direct catalog lookup already works well.
6. Ask the client to discover/load the copied skill according to its own docs.
   Check that its supporting reference is readable from the copied directory,
   then repeat the quickstart's **read-only** search/full-context exercise with
   the intended scoped account. Adoption requires no write or broad access grant.

## Check compatibility at installation and upgrades

Use the installed wrapper's `blockwart-mcp --doctor` in its normal configured
environment to check the wrapper/API contract. `tools/list` alone checks only
local discovery; it does not prove reachability or grants. Read
[MCP transport and compatibility](mcp.md) if the diagnostic fails.

Compare template tool names, arguments and semantics with that installed
`tools/list`, the generated `blockwart.describe_schema` for the intended kind
and write intent, and the matching [REST/OpenAPI](api-v1.md) and
[permission](auth-rbac.md) references. For record actions use their published
input schemas. Adapt or omit unsupported branches rather than guessing payloads
or treating a template from another revision as a contract. Never test
compatibility by attempting a write the account cannot perform.

The template keeps full-object replacement, grant/access ETags, Project ETags,
record ETags and append idempotency separate. In particular, credential-reference
metadata and locator content have [separate permissions](auth-rbac.md); preserve
omitted protected content instead of reconstructing a hidden locator.

Host-specific tool prefixes, context limits, discovery paths and concurrency
restrictions belong in the local adaptation. A serialization workaround for one
host is **not** a universal Blockwart product requirement. The portable template
requires dependent operations to use current state; it imposes no blanket ban on
independent reads.

## Optional quick reference: derived routing, not another database

The [bundled workflow](../examples/agent-skill/blockwart/references/quick-reference.md)
includes a copyable routing rule, a dated object/Project example and reconciliation
steps. Its fictional Example service matches the [human quickstart](quickstart.md);
additional example entries are illustrative, not promised seed data.

Keep names/aliases, brief purposes, exact IDs and verified canonical links or
entry points, with credential-reference IDs and responsible Runbook/skill links
where appropriate. Keep mutable project status, blockers, next actions, versions,
operating details and all secret values out of the index. A routing hint can go
stale; consult Blockwart for a conflict or suspected drift rather than treating
the local file as authority.

A review states its date, the **explicit scope**, checked IDs and complete/partial
coverage. Complete means every authorized ID in that defined scope and its
relevant route was checked, not merely that the first page returned successfully.
Do not infer global coverage from visibility or request broader roles just to
fill a local index. Unresolved or concealed entries remain clearly unverified;
a failed read is not proof of deletion. Reconciliation is a deliberate workflow,
not an automatic indexing/synchronization feature.

## Reference

- [Agent quickstart](agent-quickstart.md): connection, first success, recovery and concurrency table
- [MCP reference](mcp.md): current tools, payloads, safe errors and transport
- [Project workspace](project-workspace.md) and [typed actions](project-management.md)
- [Runbooks](runbooks.md): knowledge and execution boundary
