# Blockwart

**Infrastructure knowledge for humans and AI agents.**

Blockwart is a self-hosted infrastructure knowledge base that connects your
systems, services, networks, and devices with the knowledge needed to operate
them. Keep dependencies, runbooks, decisions, and project documentation in one
searchable catalog — accessible through a web interface, a REST API, and the
Model Context Protocol (MCP).

[Documentation](docs/README.md) ·
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

## Getting started

Blockwart can run as a Python application or in a container. Python installations
require **Python 3.12 or newer**.

1. Follow the [installation guide](docs/deployment.md) to install Blockwart,
   initialize the database, and create the first administrator and catalog owner.
2. Configure HTTPS for browser access and review the
   [configuration reference](docs/config.md).
3. Start building your catalog in the web interface, or connect a client using
   the [REST API](docs/api-v1.md) or [MCP server](docs/mcp.md).

The installation guide also covers backups, readiness checks, and upgrades.

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
