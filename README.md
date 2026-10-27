# Blockwart

**Infrastructure knowledge for humans and AI agents.**

Blockwart is a self-hosted infrastructure knowledge base that connects your
systems, services, networks, and devices with the knowledge needed to operate
them. Keep dependencies, runbooks, decisions, and project documentation in one
connected catalog — accessible through a web interface, a REST API, and the
Model Context Protocol (MCP).

[Documentation](docs/README.md) ·
[Try it locally](docs/quickstart.md) ·
[Installation](docs/deployment.md) ·
[MCP integration](docs/mcp.md) ·
[Releases](https://github.com/reisball/blockwart/releases)

## Why Blockwart?

Infrastructure documentation is most useful when it explains both what exists
and how it fits together. Blockwart links operational knowledge directly to the
systems and services it describes, giving people and agents a shared source of
context.

- **Understand your infrastructure.** Catalog hosts, systems, services, networks,
  and devices. Explore their placement, dependencies, and network topology.
- **Keep knowledge connected.** Link runbooks and decisions to the infrastructure
  they describe, with lifecycle and review information.
- **Organize project work.** Track tasks, questions, and blockers alongside
  versioned knowledge pages, external access references, and project history.
- **Give agents scoped access.** Let AI tools search and maintain authorized
  catalog data through MCP or REST, using object-level permissions.
- **Spot what needs attention.** Review documentation and catalog issues, with
  optional service-health checks and GitHub release observations.
- **Keep changes accountable.** Manage human and service accounts with
  role-based access, object grants, and an audit trail.

Blockwart stores **credential references, not secrets**. Passwords, tokens, and
private keys stay in your existing secret store.

## Is it for you?

For self-hosters, infrastructure operators and teams maintaining **curated**
operational knowledge. Start with a question such as: “Where does this service
run, what depends on it, and which operating instruction applies?”

- **Not automatic inventory discovery.** You or your integrations maintain the
  catalog; optional health observations do not discover your infrastructure.
- **Not an executor or secret vault.** Runbooks are inert instructions, not jobs;
  credential references identify secrets held elsewhere.
- **Not a general document/RAG engine.** Catalog search is bounded and
  deterministic. Project pages/tasks have project-local search, not global
  cross-project search. The reviewed import accepts documented structured
  Markdown/YAML shapes, not arbitrary document folders.
- **Not a replacement for an issue tracker or monitoring stack.** Project work
  complements external tracking. HTTP/Gatus service observations and public
  GitHub stable-release checks are opt-in; release checks do not install updates.

## Getting started

**Human evaluation:** follow [First useful catalog](docs/quickstart.md), from
checkout and local HTTPS to a signed-in browser, a host → runtime → service
chain, a linked runbook, and your first saved catalog edit. The guide includes
an optional four-object fictional seed and screenshots of the actual UI.

**Agent integration:** use the [Agent quickstart](docs/agent-quickstart.md) for
client configuration, scoped access, and a first read-only result. The stdio
wrapper runs beside your MCP client and connects to the separately running API;
Blockwart itself requires no model, GPU or paid service.

**Installation effort:** choose Python **3.12+** or a source-built container.
You need database migration, an initial owner and owned catalog data, and HTTPS
for browser login. Docker alone does not configure browser access. The complete
local guide uses SQLite and Caddy; Linux is the CI target. Setup time and minimum
hardware have not been benchmarked. See [prerequisites](docs/quickstart.md#before-downloading)
before choosing a path.

For an operated instance, use [Installation and operation](docs/deployment.md)
for network boundaries, backups, readiness, upgrades and production HTTPS.
`main` can contain unreleased work; choose a published tag and its matching
documentation for a pinned release.

### See the connected catalog

![Fictional host, runtime and service in the Blockwart UI](docs/images/quickstart-topology.png)

*Where does the service run? Follow placement, then open the service and its
linked operating knowledge. [Take the complete tour](docs/quickstart.md#4-take-the-tour).*

## Connect your tools

Use the web interface for interactive catalog and project work. Use the
[REST API](docs/api-v1.md) for integrations and automation, or the
[MCP server](docs/mcp.md) to connect compatible AI assistants.

All three interfaces use the same authorization model. Agent access is assigned
to service accounts and limited by their granted permissions; connecting an
agent does not give it unrestricted access to the catalog.

Existing documentation can be brought into the catalog through the
[reviewed Markdown/YAML import workflow](docs/markdown-import.md).

## Documentation

- [Documentation index](docs/README.md)
- [Installation and operation](docs/deployment.md)
- [Configuration](docs/config.md)
- [Authentication and permissions](docs/auth-rbac.md)
- [REST API](docs/api-v1.md) and [MCP integration](docs/mcp.md)
- [Project workspace](docs/project-workspace.md)

For changes between versions, see the [changelog](CHANGELOG.md) and
[GitHub releases](https://github.com/reisball/blockwart/releases).

## Contributing and support

Found a bug or have an idea? Search the existing
[issues](https://github.com/reisball/blockwart/issues) or open a new one.
For development setup, checks, and the contribution workflow, see
[Contributing](CONTRIBUTING.md).

Please report vulnerabilities through the process described in the
[security policy](SECURITY.md), rather than a public issue.

## License

Blockwart is licensed under the [Apache License 2.0](LICENSE).
