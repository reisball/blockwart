from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from blockwart.models import CatalogObject
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services.catalog import upsert_object
from blockwart.services.seeds import SeedImportResult

STATUS_MAP = {
    "✅": "active",
    "🟢": "active",
    "🟡": "partial",
    "⚠️": "partial",
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
    seen_ids: set[str] = set()
    credential_refs: dict[str, dict[str, Any]] = {}

    for row in rows:
        label = row.get("System") or row.get("Name")
        if not label:
            continue
        if _is_non_infra_row(row):
            continue

        slug_label = _slugify(_plain_text(label))
        base_id = CANONICAL_LABEL_IDS.get(slug_label, slug_label)
        object_id = _unique_id(base_id, seen_ids)
        status = _status_from_cell(row.get("Status", ""))
        ip_port = row.get("IP:Port", "") or row.get("Ort", "")
        access = row.get("Access", "") or row.get("Access/Auth", "")
        auth = row.get("Auth", "") or row.get("Access/Auth", "")
        usage = _plain_text(row.get("Nutzung", "") or row.get("Usage", ""))
        typ = _plain_text(row.get("Typ", "") or row.get("Type", ""))
        ref_cell = row.get("Ref", "")
        source_references = _source_references(path, references_base, ref_cell)
        addresses = _addresses_from_cell(ip_port)
        ports = _ports_from_cell(ip_port)
        credential_ref_id = _credential_reference_id(object_id, auth)

        credential_references: list[str] = []
        if credential_ref_id:
            credential_refs[credential_ref_id] = _credential_reference_object(
                credential_ref_id,
                label=_plain_text(label),
                auth=auth,
                object_ref=f"system:{object_id}",
                source_references=source_references,
            )
            credential_references.append(f"credential_reference:{credential_ref_id}")

        data: dict[str, Any] = {
            "schema_version": 1,
            "type": typ.lower() or "unknown",
            "source": "workspace_markdown_import",
            "source_references": source_references,
            "network": {
                "hostnames": [_slugify(_plain_text(label))],
                "addresses": addresses,
            },
            "ports": ports,
            "access_methods": _access_methods(access, addresses, ports, credential_references),
            "credential_references": credential_references,
            "import_notes": {
                "tools_row_type": typ,
                "access_summary": _plain_text(access),
                "auth_reference_summary": _plain_text(auth),
            },
        }
        if usage:
            data["purpose"] = usage

        objects.append(
            {
                "id": object_id,
                "kind": "system",
                "label": _plain_text(label),
                "status": status,
                "summary": usage or typ or "Imported from workspace TOOLS.md.",
                "data": data,
            }
        )

    objects.extend(credential_refs.values())
    payload = {
        "schema_version": 1,
        "owner": "Kai + Zoe",
        "source": str(path),
        "objects": objects,
        "relationships": [],
    }
    return MarkdownImportPlan(
        payload=payload,
        source_rows=len(rows),
        object_count=len(objects),
        credential_reference_count=len(credential_refs),
    )


def import_tools_markdown(
    session: Session,
    tools_path: str | Path,
    *,
    references_root: str | Path | None = None,
) -> SeedImportResult:
    plan = build_tools_import_plan(tools_path, references_root=references_root)
    objects = plan.payload["objects"]
    if not isinstance(objects, list):
        raise ValueError("Markdown import payload must contain objects")

    for raw_object in objects:
        payload = CatalogObjectIn.model_validate(raw_object)
        existing = session.get(CatalogObject, payload.id)
        if existing is not None and existing.kind == payload.kind:
            payload = _merge_existing_object(existing, payload)
        upsert_object(session, payload)

    return SeedImportResult(objects_imported=len(objects), relationships_imported=0)


def _merge_existing_object(existing: CatalogObject, imported: CatalogObjectIn) -> CatalogObjectIn:
    existing_data = json.loads(existing.data_json)
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
    return text or "unknown"


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
    object_ref: str,
    source_references: list[dict[str, str]],
) -> dict[str, Any]:
    text = _plain_text(auth)
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
                "systems": [object_ref],
                "services": [],
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
                "credential_references": credential_references,
                "notes": text,
            }
        )
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
