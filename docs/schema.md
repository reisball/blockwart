# Blockwart Schema

Date: 2026-05-17
Status: v1 draft

This document defines the canonical English schema for Blockwart infrastructure objects.
All database keys, API fields, import/export fields, audit field names, and internal schema
metadata use English. Translated UI labels may be added later as a presentation layer only.

## Language Rules

- Canonical schema language: English.
- Stored object kinds use English: `host`, `system`, `network`, `service`.
- Stored field names use English snake_case.
- UI translations must not change stored field names.
- German legacy values may be accepted during migration, but must be normalized to English
  before becoming canonical data.

## Object Kinds

### `host`

A host-level platform that carries systems. Examples: Proxmox host, NAS, Windows host,
router-like infrastructure host.

Canonical fields:

- `schema_version`
- `hostname`
- `platform`
- `os`
- `os_version`
- `specs`
- `interfaces`
- `endpoints`
- `access_methods`

### `system`

A runnable machine, VM, LXC, container, or workload that belongs to a host.

Canonical fields:

- `schema_version`
- `host_ref`
- `hostname`
- `platform`
- `os`
- `os_version`
- `specs`
- `interfaces`
- `endpoints`
- `access_methods`

### `service`

An application or service running on a system.

Canonical fields:

- `schema_version`
- `system_ref`
- `endpoints`
- `access_methods`

A service inherits the following from its linked `system` and must not store its own copy:

- `hostname`
- `platform`
- `os`
- `os_version`
- `specs`
- `interfaces`

### `network`

A network-level object for network segments, shared network documentation, or non-hosted
network resources.

Canonical fields:

- `schema_version`
- `name`
- `interfaces`
- `endpoints`
- `access_methods`

## Nested Structures

### `specs`

```json
{
  "cpu": "2 cores",
  "memory": "4096 MB",
  "gpu": "none",
  "storage": "32G local-lvm"
}
```

Fields:

- `cpu`
- `memory`
- `gpu`
- `storage`

### `interfaces[]`

```json
{
  "id": "eth0",
  "name": "eth0",
  "ip": "192.168.50.83",
  "mac": "02:42:AC:11:00:7F"
}
```

Fields:

- `id`: stable local identifier, unique within the object
- `name`: interface name
- `ip`: IP address
- `mac`: MAC address

### `endpoints[]`

```json
{
  "type": "SSH",
  "url": "ssh://192.168.50.83:22",
  "port": 22
}
```

Fields:

- `type`: endpoint type (`Web`, `REST API`, `MCP`, `HEC`, `SSH`)
- `url`: endpoint URL
- `port`: TCP/UDP port number

Legacy standalone `ports[]` may exist in older stored data but is not part of the current public
write contract.

### `access_methods[]`

```json
{
  "id": "ssh-main",
  "type": "ssh",
  "endpoint": "ssh://zoe@192.168.50.83:22",
  "username": "zoe",
  "credential_reference": "credential_reference:n8n-zoe-ssh-key"
}
```

Fields:

- `id`: stable local identifier, unique within the object
- `type`: access type
- `endpoint`: URL or endpoint string for the access method
- `username`
- `credential_reference`: reference only, never a secret value

## Relationship Rules

- Hierarchy: `host -> system -> service`.
- A `host` can have many `systems`.
- A `system` should have exactly one `host_ref`.
- A `system` can have many `services`.
- A `service` must have exactly one `system_ref`.
- A `service` must not own host-level or system-level facts.
- A `service` owns only its service-specific `endpoints` and `access_methods`.

## Validation Rules

- `schema_version` must be `1`.
- `endpoint.port` must be an integer from `1` to `65535`.
- `endpoint.type` must be one of `Web`, `REST API`, `MCP`, `HEC`, or `SSH`.
- `interface.ip` must be a valid IP address.
- `interface.mac` must be a valid MAC address.
- `access_methods[].endpoint` should reference a documented endpoint where applicable.
- `credential_reference` stores only a reference, never a raw credential or token.
- Raw credential-like keys such as `value`, `raw`, `plaintext`, or `secret_value`
  are forbidden in credential references.

## Delete Rules

- Deleting a `host` with linked systems must be blocked.
- Deleting a `system` with linked services must be blocked.
- Deleting a system interface referenced by endpoints/access methods must be blocked or must clear
  the reference explicitly as part of the same operation.

## Audit Rules

- New comments are append-only entries under `data.comments[]` with `text`, `actor`, and
  `created_at`. Legacy single `data.comment` values remain readable.
- Comment audit entries show only the comment text.
- Field changes use this format:

```text
Field "fieldname" with value "oldvalue" replaced by "newvalue"
```

- Audit field names use canonical English schema names.
- Generic update noise must not be shown.
- Normal field changes must not be rendered as raw JSON blobs.
- `specs` changes are logged per concrete field, for example `cpu`, not as one large
  `specs` object.

## Legacy Migration Rules

Known old fields and values:

- `netzwerk` -> `network`
- `model` -> removed
- legacy `ports` -> migrated into `endpoints` where possible
- service-owned `network.hostnames` -> removed; service inherits `hostname`
- service-owned platform/spec fields -> removed; service inherits from linked system
- old `network.addresses[]` and `network.mac_addresses[]` -> merged into `interfaces[]`
- old `access_methods[].auth_mode` -> removed
- old `access_methods[].credential_references[]` -> collapsed to `credential_reference`
  where the UI only accepts one reference for now

Legacy German audit text may be parsed for display, but newly written audit text must use
English.
