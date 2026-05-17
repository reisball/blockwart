from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from blockwart.models import CatalogObject, Relationship
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services.catalog import create_relationship, upsert_object
from blockwart.services.seeds import SeedImportResult

STATUS_MAP = {
    "✅": "active",
    "🟢": "active",
    "🟡": "inactive",
    "⚠️": "inactive",
    "❌": "inactive",
}

ACCESS_TYPES = {
    "ssh": "ssh",
    "web": "web",
    "api": "api",
    "smb": "smb",
    "host": "other",
    "openclaw": "api",
}

CANONICAL_LABEL_IDS = {
    "brieftraeger": "brieftraeger",
    "denkstube": "denkstube",
    "fabrik-proxmox": "fabrik",
    "n8n": "n8n",
    "ollama-fabrik": "ollama",
    "paperless-ngx": "paperless-ngx",
    "splunk": "splunk",
    "vaultwarden": "vaultwarden",
}


@dataclass(frozen=True)
class MarkdownImportPlan:
    payload: dict[str, Any]
    source_rows: int
    object_count: int
    credential_reference_count: int


def build_tools_import_plan(
    tools_path: str | Path,
    *,
    references_root: str | Path | None = None,
) -> MarkdownImportPlan:
    path = Path(tools_path)
    references_base = Path(references_root) if references_root else path.parent
    rows = _parse_markdown_tables(path.read_text(encoding="utf-8"))

    objects: list[dict[str, Any]] = []
    relationships: list[dict[str, str]] = []
    seen_ids: set[str] = set()

    for row in rows:
        label = row.get("System") or row.get("Name")
        if not label:
            continue
        if _is_non_infra_row(row):
            continue

        slug_label = _slugify(_plain_text(label))
        is_canonical_row = slug_label in CANONICAL_LABEL_IDS
        base_id = CANONICAL_LABEL_IDS.get(slug_label, slug_label)
        typ = _plain_text(row.get("Typ", "") or row.get("Type", ""))
        is_hosted_service = _is_hosted_service_row(row) and not is_canonical_row
        object_id = _unique_id(base_id, seen_ids)
        system_id = (
            _unique_id(_host_system_id(base_id, typ), seen_ids)
            if is_hosted_service
            else object_id
        )
        service_id = object_id
        status = _status_from_cell(row.get("Status", ""))
        ip_port = row.get("IP:Port", "") or row.get("Ort", "")
        access = row.get("Access", "") or row.get("Access/Auth", "")
        auth = row.get("Auth", "") or row.get("Access/Auth", "")
        usage = _plain_text(row.get("Nutzung", "") or row.get("Usage", ""))
        ref_cell = row.get("Ref", "")
        source_references = _source_references(path, references_base, ref_cell)
        addresses = _addresses_from_cell(ip_port)
        ports = _ports_from_cell(ip_port)
        system_ports = _system_ports(ports) if is_hosted_service else ports
        service_ports = _service_ports(ports) if is_hosted_service else ports

        system_data: dict[str, Any] = {
            "schema_version": 1,
            "type": typ.lower() or "unknown",
            "source": "workspace_markdown_import",
            "source_references": source_references,
            "network": {
                "hostnames": [_slugify(_plain_text(label))],
                "addresses": addresses,
            },
            "ports": system_ports,
            "access_methods": _access_methods(
                _system_access_text(access) if is_hosted_service else access,
                addresses,
                system_ports,
                [],
            ),
            "import_notes": {
                "tools_row_type": typ,
                "import_role": "host_system" if is_hosted_service else "system",
                "access_summary": _plain_text(access),
                "auth_reference_summary": _plain_text(auth),
            },
        }
        platform = _platform_from_type(typ)
        if platform:
            system_data["platform"] = platform
        if is_hosted_service:
            system_data["container"] = _container_data(typ)
        if usage:
            system_data["purpose"] = usage

        objects.append(
            {
                "id": system_id,
                "kind": "system",
                "label": _host_system_label(_plain_text(label), typ)
                if is_hosted_service
                else _plain_text(label),
                "status": status,
                "summary": (
                    f"Runtime host for {_plain_text(label)}."
                    if is_hosted_service
                    else usage or typ or "Imported from workspace TOOLS.md."
                ),
                "data": system_data,
            }
        )
        if is_hosted_service:
            service_ref = f"service:{service_id}"
            system_ref = f"system:{system_id}"
            system_data["related_services"] = [service_ref]
            objects.append(
                {
                    "id": service_id,
                    "kind": "service",
                    "label": _plain_text(label),
                    "status": status,
                    "summary": usage or f"Service running on {system_id}.",
                    "data": _service_data(
                        label=_plain_text(label),
                        usage=usage,
                        typ=typ,
                        system_ref=system_ref,
                        platform=platform,
                        addresses=addresses,
                        ports=service_ports,
                        source_references=source_references,
                        access=access,
                        auth=auth,
                    ),
                }
            )
            relationships.append(
                {
                    "from_ref": system_ref,
                    "relation_type": "hosts",
                    "to_ref": service_ref,
                }
            )

    payload = {
        "schema_version": 1,
        "owner": "Kai + Zoe",
        "source": str(path),
        "objects": objects,
        "relationships": relationships,
    }
    return MarkdownImportPlan(
        payload=payload,
        source_rows=len(rows),
        object_count=len(objects),
        credential_reference_count=0,
    )


def import_tools_markdown(
    session: Session,
    tools_path: str | Path,
    *,
    references_root: str | Path | None = None,
) -> SeedImportResult:
    plan = build_tools_import_plan(tools_path, references_root=references_root)
    objects = plan.payload["objects"]
    relationships = plan.payload["relationships"]
    if not isinstance(objects, list):
        raise ValueError("Markdown import payload must contain objects")
    if not isinstance(relationships, list):
        raise ValueError("Markdown import payload must contain relationships")

    for raw_object in objects:
        payload = CatalogObjectIn.model_validate(raw_object)
        existing = session.get(CatalogObject, payload.id)
        if existing is not None and existing.kind == payload.kind:
            payload = _merge_existing_object(existing, payload)
        upsert_object(session, payload)

    inserted_relationships = 0
    for relationship in relationships:
        _remove_stale_workspace_host_relationships(session, relationship)
        existing = session.scalar(
            select(Relationship).where(
                Relationship.from_ref == relationship["from_ref"],
                Relationship.relation_type == relationship["relation_type"],
                Relationship.to_ref == relationship["to_ref"],
            )
        )
        create_relationship(
            session,
            from_ref=relationship["from_ref"],
            relation_type=relationship["relation_type"],
            to_ref=relationship["to_ref"],
        )
        if existing is None:
            inserted_relationships += 1

    return SeedImportResult(
        objects_imported=len(objects),
        relationships_imported=inserted_relationships,
    )


def _remove_stale_workspace_host_relationships(
    session: Session,
    relationship: dict[str, str],
) -> None:
    if relationship["relation_type"] != "hosts" or not relationship["to_ref"].startswith(
        "service:"
    ):
        return
    stale_relationships = session.scalars(
        select(Relationship).where(
            Relationship.relation_type == "hosts",
            Relationship.to_ref == relationship["to_ref"],
            Relationship.from_ref != relationship["from_ref"],
        )
    ).all()
    for stale_relationship in stale_relationships:
        stale_object_id = stale_relationship.from_ref.split(":", 1)[1]
        stale_object = session.get(CatalogObject, stale_object_id)
        if stale_object is None:
            continue
        stale_data = json.loads(stale_object.data_json)
        if stale_data.get("source") != "workspace_markdown_import":
            continue
        session.delete(stale_relationship)
        session.flush()
        remaining_relationship = session.scalar(
            select(Relationship).where(
                (Relationship.from_ref == stale_relationship.from_ref)
                | (Relationship.to_ref == stale_relationship.from_ref)
            )
        )
        if remaining_relationship is None:
            session.execute(delete(CatalogObject).where(CatalogObject.id == stale_object_id))
    session.commit()


def _merge_existing_object(existing: CatalogObject, imported: CatalogObjectIn) -> CatalogObjectIn:
    existing_data = json.loads(existing.data_json)
    if existing_data.get("source") == "workspace_markdown_import":
        return imported
    merged_data = {
        **existing_data,
        "workspace_markdown_import": imported.data,
    }
    return CatalogObjectIn(
        id=existing.id,
        kind=existing.kind,  # type: ignore[arg-type]
        label=existing.label,
        status=existing.status,
        summary=existing.summary,
        data=merged_data,
    )


def _parse_markdown_tables(markdown: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    header: list[str] | None = None
    awaiting_separator = False

    for raw_line in markdown.splitlines():
        line = raw_line.strip()
        if not line.startswith("|") or not line.endswith("|"):
            header = None
            awaiting_separator = False
            continue

        cells = _split_markdown_row(line)
        if not cells:
            continue
        if _is_separator_row(cells):
            awaiting_separator = False
            continue
        if header is None:
            header = cells
            awaiting_separator = True
            continue
        if awaiting_separator:
            header = cells
            continue
        if len(cells) != len(header):
            continue
        rows.append(dict(zip(header, cells, strict=True)))

    return rows


def _split_markdown_row(line: str) -> list[str]:
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def _is_separator_row(cells: list[str]) -> bool:
    return all(re.fullmatch(r":?-{3,}:?", cell.strip()) for cell in cells)


def _is_non_infra_row(row: dict[str, str]) -> bool:
    typ = row.get("Typ", "").casefold()
    if typ in {"typ", ""}:
        return True
    return "Zeitplan" in row or "Activity" in row


def _is_hosted_service_row(row: dict[str, str]) -> bool:
    typ = _plain_text(row.get("Typ", "") or row.get("Type", "")).casefold()
    if not typ:
        return False
    host_markers = ("ct", "vm", "lxc", "container")
    non_service_markers = ("host", "network", "raspberry pi", "wsl2")
    return any(marker in typ for marker in host_markers) and not any(
        marker == typ for marker in non_service_markers
    )


def _host_system_id(base_id: str, typ: str) -> str:
    container = _container_data(typ)
    container_id = str(container.get("id") or "")
    if container_id:
        return container_id
    return f"{base_id}-runtime"


def _host_system_label(label: str, typ: str) -> str:
    return label


def _container_data(typ: str) -> dict[str, str]:
    text = _plain_text(typ)
    match = re.search(r"\b(CT|VM|LXC)\s+(\d+)\b", text, flags=re.IGNORECASE)
    if match:
        container_type = match.group(1).lower()
        number = match.group(2)
        normalized_type = "ct" if container_type in {"ct", "lxc"} else "vm"
        return {
            "id": f"{normalized_type}-{number}",
            "type": normalized_type,
            "number": number,
            "label": f"{normalized_type.upper()} {number}",
        }
    return {
        "id": "",
        "type": "container",
        "number": "",
        "label": text,
    }


def _platform_from_type(typ: str) -> str:
    text = _plain_text(typ).casefold()
    if re.search(r"\b(ct|lxc)\b", text):
        return "LXC"
    if re.search(r"\bvm\b", text):
        return "VM"
    if re.search(r"\bwsl2?\b", text):
        return "WSL"
    return ""


def _system_ports(ports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    system_port_numbers = {22, 445}
    return [
        {
            **port,
            "scope": "system",
        }
        for port in ports
        if port.get("port") in system_port_numbers
    ]


def _service_ports(ports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    system_port_numbers = {22, 445}
    return [
        {
            **port,
            "scope": "service",
        }
        for port in ports
        if port.get("port") not in system_port_numbers
    ]


def _service_data(
    *,
    label: str,
    usage: str,
    typ: str,
    system_ref: str,
    platform: str,
    addresses: list[dict[str, str]],
    ports: list[dict[str, Any]],
    source_references: list[dict[str, str]],
    access: str,
    auth: str,
) -> dict[str, Any]:
    data: dict[str, Any] = {
        "schema_version": 1,
        "type": "application",
        "source": "workspace_markdown_import",
        "system_id": system_ref,
        "purpose": usage,
        "endpoints": _endpoints_from_network(label, addresses, ports),
        "access_methods": _access_methods(
            _service_access_text(access),
            addresses,
            ports,
            [],
        ),
        "auth": {
            "mode": _auth_mode(_plain_text(auth or access)),
        },
        "source_references": source_references,
        "import_notes": {
            "tools_row_type": typ,
            "import_role": "hosted_service",
            "access_summary": _plain_text(access),
            "auth_reference_summary": _plain_text(auth),
        },
    }
    if platform:
        data["platform"] = platform
    return data


def _system_access_text(access: str) -> str:
    return _filter_access_chunks(access, {"ssh", "smb", "host"})


def _service_access_text(access: str) -> str:
    return _filter_access_chunks(access, {"web", "api", "openclaw"})


def _filter_access_chunks(access: str, allowed_markers: set[str]) -> str:
    chunks: list[str] = []
    for chunk in re.split(r"\s+·\s+|,\s*", access):
        text = _plain_text(chunk)
        if not text or text == "-":
            continue
        lower = text.casefold()
        if any(marker in lower for marker in allowed_markers):
            chunks.append(text)
    return " · ".join(chunks)


def _endpoints_from_network(
    label: str,
    addresses: list[dict[str, str]],
    ports: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if not addresses:
        return []
    ip = addresses[0]["ip"]
    endpoints = []
    for port in ports:
        port_number = port["port"]
        scheme = "https" if port_number in {443, 8443, 8006} else "http"
        endpoints.append(
            {
                "name": label,
                "url": f"{scheme}://{ip}:{port_number}",
                "port": port_number,
                "protocol": port.get("protocol", "tcp"),
                "exposure": port.get("exposure", "lan"),
                "scope": "service",
            }
        )
    return endpoints


def _plain_text(value: str) -> str:
    text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r"\1", value)
    text = text.replace(chr(96), "")
    return re.sub(r"\s+", " ", text).strip()


def _slugify(value: str) -> str:
    slug = value.casefold()
    replacements = {"ä": "ae", "ö": "oe", "ü": "ue", "ß": "ss"}
    for source, target in replacements.items():
        slug = slug.replace(source, target)
    slug = re.sub(r"\([^)]*\)", "", slug)
    slug = re.sub(r"[^a-z0-9]+", "-", slug).strip("-")
    return slug or "object"


def _unique_id(base: str, seen: set[str]) -> str:
    candidate = base
    index = 2
    while candidate in seen:
        candidate = f"{base}-{index}"
        index += 1
    seen.add(candidate)
    return candidate


def _status_from_cell(value: str) -> str:
    for marker, status in STATUS_MAP.items():
        if marker in value:
            return status
    text = _plain_text(value).casefold()
    if "deleted" in text:
        return "deleted"
    if "inactive" in text:
        return "inactive"
    if "active" in text:
        return "active"
    return "inactive"


def _source_references(
    tools_path: Path,
    references_base: Path,
    ref_cell: str,
) -> list[dict[str, str]]:
    refs = [{"label": "TOOLS.md", "uri": str(tools_path)}]
    for label, uri in re.findall(r"\[([^\]]+)\]\(([^)]+)\)", ref_cell):
        if uri.startswith("references/"):
            refs.append({"label": label, "uri": str(references_base / uri)})
        else:
            refs.append({"label": label, "uri": uri})
    return refs


def _addresses_from_cell(value: str) -> list[dict[str, str]]:
    addresses = []
    seen = set()
    for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", value):
        if ip in seen:
            continue
        seen.add(ip)
        addresses.append(
            {
                "ip": ip,
                "family": "ipv4",
                "interface": "",
                "network": "192.168.50.0/24" if ip.startswith("192.168.50.") else "",
                "scope": "lan",
            }
        )
    return addresses


def _ports_from_cell(value: str) -> list[dict[str, Any]]:
    ports = []
    seen = set()
    for port_text in re.findall(r":(\d{1,5})\b", value):
        port = int(port_text)
        if not 1 <= port <= 65535 or port in seen:
            continue
        seen.add(port)
        ports.append(
            {
                "port": port,
                "protocol": "tcp",
                "purpose": _purpose_for_port(port),
                "exposure": "lan",
            }
        )
    return ports


def _purpose_for_port(port: int) -> str:
    known = {
        22: "SSH",
        80: "HTTP",
        443: "HTTPS",
        445: "SMB",
        8000: "Web/API",
        8006: "Proxmox Web UI/API",
        8089: "Management API",
        11434: "Ollama API",
    }
    return known.get(port, "Documented service port")


def _credential_reference_id(object_id: str, auth: str) -> str | None:
    text = _plain_text(auth).casefold()
    if not text or text in {"-", "none"}:
        return None
    if "no auth" in text and not any(term in text for term in ("ssh", "web", "vault", "secret")):
        return None
    credential_terms = ("vault", "secret", "key", "password", "token", "login", "setup")
    if any(term in text for term in credential_terms):
        return f"{object_id}-access-reference"
    return None


def _credential_reference_object(
    object_id: str,
    *,
    label: str,
    auth: str,
    system_ref: str,
    service_ref: str = "",
    source_references: list[dict[str, str]],
) -> dict[str, Any]:
    text = _plain_text(auth)
    service_refs = [service_ref] if service_ref else []
    return {
        "id": object_id,
        "kind": "credential_reference",
        "label": f"{label} access reference",
        "status": "active",
        "summary": (
            "Credential pointer imported from workspace documentation; "
            "no secret value stored."
        ),
        "data": {
            "schema_version": 1,
            "provider": _credential_provider(text),
            "reference": {"item_hint": text},
            "scope": {
                "access_type": _access_type_from_auth(text),
                "systems": [system_ref],
                "services": service_refs,
            },
            "source_references": source_references,
            "handling_rules": {
                "telegram_allowed": False,
                "markdown_secret_allowed": False,
                "agents_may_read_value": False,
            },
            "secret_value_stored": False,
        },
    }


def _credential_provider(auth: str) -> str:
    text = auth.casefold()
    if "vault" in text:
        return "vaultwarden"
    if "secrets.json" in text:
        return "secrets_json"
    if ".env" in text or "env" in text:
        return "env_file"
    if "local" in text:
        return "local_file"
    return "external"


def _access_type_from_auth(auth: str) -> str:
    text = auth.casefold()
    if "ssh" in text:
        return "ssh"
    if "api" in text:
        return "api"
    if "token" in text:
        return "token"
    if "smb" in text:
        return "smb"
    if "sudo" in text:
        return "sudo"
    if "web" in text or "login" in text:
        return "web"
    return "other"


def _access_methods(
    access: str,
    addresses: list[dict[str, str]],
    ports: list[dict[str, Any]],
    credential_references: list[str],
) -> list[dict[str, Any]]:
    methods = []
    ip = addresses[0]["ip"] if addresses else ""
    port_numbers = {port["port"] for port in ports}
    for chunk in re.split(r"\s+·\s+|,\s*", access):
        text = _plain_text(chunk)
        if not text or text == "-":
            continue
        method_type = _method_type(text)
        endpoint = _endpoint_for_method(method_type, ip, port_numbers)
        methods.append(
            {
                "type": method_type,
                "endpoint": endpoint,
                "auth_mode": _auth_mode(text),
                "notes": text,
            }
        )
        if credential_references:
            methods[-1]["credential_references"] = credential_references
    return methods


def _method_type(value: str) -> str:
    text = value.casefold()
    for marker, method_type in ACCESS_TYPES.items():
        if marker in text:
            return method_type
    return "other"


def _endpoint_for_method(method_type: str, ip: str, ports: set[int]) -> str:
    if not ip:
        return ""
    if method_type == "ssh":
        return f"ssh://{ip}:22"
    if method_type == "web":
        web_ports = {80, 443, 8000, 8006, 8080, 8443}
        port = next((item for item in sorted(ports) if item in web_ports), None)
        scheme = "https" if port in {443, 8443, 8006} else "http"
        return f"{scheme}://{ip}:{port}" if port else f"http://{ip}"
    if method_type == "api":
        port = next((item for item in sorted(ports) if item not in {22}), None)
        return f"http://{ip}:{port}" if port else f"http://{ip}"
    if method_type == "smb":
        return f"//{ip}"
    return ip


def _auth_mode(value: str) -> str:
    text = value.casefold()
    if "no auth" in text or "offen" in text:
        return "none"
    if "key" in text:
        return "key"
    if "token" in text:
        return "token"
    if "password" in text or "login" in text:
        return "password"
    return "documented"
