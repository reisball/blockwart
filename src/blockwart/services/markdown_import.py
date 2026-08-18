from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from blockwart.domain.asset_state import AssetState
from blockwart.domain.provenance import (
    CatalogProvenance,
    load_provenance,
)
from blockwart.domain.source_coverage import (
    CLASSIFICATION_DEFAULTS,
    COLLECTOR_MARKDOWN_TOOLS,
    DECISION_REASONS,
    MAPPING_INTENTS,
    MAX_ENTRY_ID_LENGTH,
    SOURCE_CLASSIFICATIONS,
    DecisionReason,
    MappingIntent,
    SourceClassification,
    SourceEntry,
    SourceMapping,
    SourceSnapshot,
    content_fingerprint,
    normalize_entry_id,
    normalize_source_uri,
    source_fingerprint,
    validate_snapshot,
)
from blockwart.domain.timestamps import format_rfc3339_utc
from blockwart.models import CatalogObject, Relationship
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services.access import (
    active_owner_covered_object_ids,
    ensure_owner_coverage_preserved,
)
from blockwart.services.catalog import (
    create_relationship,
    current_object_kinds,
    delete_object,
    delete_relationship,
    upsert_object,
)
from blockwart.services.network_classification import NetworkClassificationEvidence
from blockwart.services.seeds import SeedImportResult

STATUS_MARKER_STATES = {
    "✅": AssetState("active", "unknown", "active"),
    "🟢": AssetState("active", "unknown", "active"),
    "🟡": AssetState("active", "degraded", "active"),
    "⚠️": AssetState("active", "degraded", "active"),
    "❌": AssetState("active", "down", "inactive"),
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
    coverage_snapshot: SourceSnapshot


class MarkdownImportNetworkError(ValueError):
    """The reviewed mapping does not classify the exact imported Network set."""

    def __init__(self, diagnostics: tuple[str, ...]) -> None:
        super().__init__("Markdown import Network classification is incomplete")
        self.diagnostics = diagnostics


def build_tools_import_plan(
    tools_path: str | Path,
    *,
    references_root: str | Path | None = None,
    network_evidence: Mapping[str, NetworkClassificationEvidence] | None = None,
    source_uri: str = "workspace://TOOLS.md",
    observed_at: str | None = None,
    previous_snapshot: SourceSnapshot | None = None,
    mapped_object_ids: frozenset[str] = frozenset(),
) -> MarkdownImportPlan:
    path = Path(tools_path)
    references_base = Path(references_root) if references_root else path.parent
    rows = _parse_markdown_tables(path.read_text(encoding="utf-8"))

    objects: list[dict[str, Any]] = []
    relationships: list[dict[str, str]] = []
    seen_ids: set[str] = set()
    hosted_system_refs: list[str] = []
    coverage_rows: list[
        tuple[
            dict[str, str],
            SourceClassification,
            MappingIntent,
            DecisionReason,
            tuple[str, ...],
        ]
    ] = []

    for row in rows:
        label = row.get("System") or row.get("Name")
        if not label:
            continue
        classification, intent, decision_reason = _source_decision(row)
        if classification != "operational" or intent == "no_catalog_object":
            coverage_rows.append((row, classification, intent, decision_reason, ()))
            continue

        slug_label = _slugify(_plain_text(label))
        base_id = CANONICAL_LABEL_IDS.get(slug_label, slug_label)
        typ = _plain_text(row.get("Typ", "") or row.get("Type", ""))
        is_hosted_service = _is_hosted_service_row(row)
        system_id = (
            _unique_id(_host_system_id(base_id, typ), seen_ids)
            if is_hosted_service
            else _unique_id(base_id, seen_ids)
        )
        service_id = _unique_id(_service_id(system_id, base_id), seen_ids)
        display_label = _display_label(_plain_text(label))
        asset_state = _state_from_cell(row.get("Status", ""))
        ip_port = row.get("IP:Port", "") or row.get("Ort", "")
        access = row.get("Access", "") or row.get("Access/Auth", "")
        auth = row.get("Auth", "") or row.get("Access/Auth", "")
        usage = _plain_text(row.get("Nutzung", "") or row.get("Usage", ""))
        ref_cell = row.get("Ref", "")
        source_references = _source_references(path, references_base, ref_cell)
        addresses = _addresses_from_cell(ip_port)
        ports = _ports_from_cell(ip_port)
        documented_urls = _urls_from_cell(ip_port)
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
                documented_urls,
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
                "kind": "system" if is_hosted_service else _object_kind_from_type(typ),
                "label": _host_system_label(display_label, typ)
                if is_hosted_service
                else display_label,
                "status": asset_state.status,
                "lifecycle": asset_state.lifecycle,
                "health": asset_state.health,
                "summary": (
                    f"Runtime host for {display_label}."
                    if is_hosted_service
                    else usage or typ or "Imported from workspace TOOLS.md."
                ),
                "data": system_data,
            }
        )
        mapped_candidates = [system_id]
        if is_hosted_service:
            service_ref = f"service:{service_id}"
            system_ref = f"system:{system_id}"
            system_data["related_services"] = [service_ref]
            objects.append(
                {
                    "id": service_id,
                    "kind": "service",
                    "label": display_label,
                    "status": asset_state.status,
                    "lifecycle": asset_state.lifecycle,
                    "health": asset_state.health,
                    "summary": usage or f"Service running on {system_id}.",
                    "data": _service_data(
                        label=display_label,
                        usage=usage,
                        typ=typ,
                        addresses=addresses,
                        ports=service_ports,
                        source_references=source_references,
                        access=access,
                        auth=auth,
                        documented_urls=documented_urls,
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
            hosted_system_refs.append(system_ref)
            mapped_candidates.append(service_id)
        coverage_rows.append(
            (
                row,
                classification,
                intent,
                decision_reason,
                tuple(mapped_candidates),
            )
        )

    if any(obj["id"] == "fabrik" and obj["kind"] == "host" for obj in objects):
        relationships.extend(
            {
                "from_ref": "host:fabrik",
                "relation_type": "hosts",
                "to_ref": system_ref,
            }
            for system_ref in hosted_system_refs
        )

    _apply_network_evidence(objects, network_evidence or {})
    _mark_unassigned_assets(objects, relationships)
    provenance = CatalogProvenance(
        source_type="import",
        source_ref=str(path),
        managed_by="Blockwart Markdown Import",
        manual_override=False,
    ).model_dump()
    for obj in objects:
        obj["provenance"] = provenance
        CatalogObjectIn.model_validate(obj)
    payload = {
        "schema_version": 1,
        "owner": "Blockwart Markdown Import",
        "source": str(path),
        "objects": objects,
        "relationships": relationships,
    }
    coverage_snapshot = _build_coverage_snapshot(
        coverage_rows,
        source_uri=source_uri,
        observed_at=observed_at,
        previous_snapshot=previous_snapshot,
        mapped_object_ids=mapped_object_ids,
    )
    return MarkdownImportPlan(
        payload=payload,
        source_rows=len(rows),
        object_count=len(objects),
        credential_reference_count=0,
        coverage_snapshot=coverage_snapshot,
    )


def _build_coverage_snapshot(
    rows: list[
        tuple[
            dict[str, str],
            SourceClassification,
            MappingIntent,
            DecisionReason,
            tuple[str, ...],
        ]
    ],
    *,
    source_uri: str,
    observed_at: str | None,
    previous_snapshot: SourceSnapshot | None,
    mapped_object_ids: frozenset[str],
) -> SourceSnapshot:
    stable_uri = normalize_source_uri(source_uri)
    timestamp = observed_at or format_rfc3339_utc(datetime.now(UTC)) or ""
    previous_by_key = {
        entry.key: entry
        for entry in (previous_snapshot.entries if previous_snapshot is not None else ())
        if entry.source_uri == stable_uri
    }

    normalized_rows: list[
        tuple[
            str,
            str,
            dict[str, str],
            SourceClassification,
            MappingIntent,
            DecisionReason,
            tuple[str, ...],
        ]
    ] = []
    base_id_counts: dict[str, int] = {}
    for row, classification, intent, reason, candidates in rows:
        label = _plain_text(row.get("System") or row.get("Name") or "")
        explicit_id = (
            row.get("Entry ID")
            or row.get("Source Entry ID")
            or row.get("Source ID")
        )
        base_id = normalize_entry_id(explicit_id) if explicit_id else _slugify(label)
        if base_id is None:
            raise ValueError("Markdown source entry id is required")
        normalized_row = {
            _plain_text(key): _plain_text(value)
            for key, value in sorted(row.items())
        }
        fingerprint = content_fingerprint([normalized_row])
        normalized_rows.append(
            (
                base_id,
                fingerprint,
                normalized_row,
                classification,
                intent,
                reason,
                candidates,
            )
        )
        base_id_counts[base_id] = base_id_counts.get(base_id, 0) + 1

    current_entries: list[SourceEntry] = []
    current_keys: set[tuple[str, str]] = set()
    for (
        base_id,
        fingerprint,
        _normalized_row,
        classification,
        intent,
        reason,
        candidates,
    ) in sorted(normalized_rows, key=lambda item: (item[0], item[1], item[6])):
        entry_id = (
            base_id
            if base_id_counts[base_id] == 1
            else f"{base_id[: MAX_ENTRY_ID_LENGTH - 14]}--{fingerprint[:12]}"
        )
        key = (stable_uri, entry_id)
        if key in current_keys:
            raise ValueError("duplicate indistinguishable Markdown source entries")
        current_keys.add(key)
        previous = previous_by_key.get(key)
        if previous is not None:
            mappings = previous.mappings
        else:
            existing_candidates = tuple(
                object_id
                for object_id in candidates
                if object_id in mapped_object_ids
            )
            mappings = tuple(
                SourceMapping(
                    object_id=object_id,
                    role="primary" if index == 0 else "derived",
                    imported_entry_fingerprint=fingerprint,
                    imported_at=timestamp,
                    verified_at=timestamp,
                )
                for index, object_id in enumerate(existing_candidates)
            )
        current_entries.append(
            SourceEntry(
                source_uri=stable_uri,
                entry_id=entry_id,
                classification=classification,
                intent=intent,
                decision_reason=reason,
                entry_fingerprint=fingerprint,
                source_fingerprint="0" * 64,
                observed_at=timestamp,
                mappings=mappings,
            )
        )

    aggregate_fingerprint = source_fingerprint(
        entry.entry_fingerprint for entry in current_entries
    )
    entries = [
        replace(entry, source_fingerprint=aggregate_fingerprint)
        for entry in current_entries
    ]
    for key, previous in sorted(previous_by_key.items()):
        if key in current_keys:
            continue
        entries.append(
            replace(
                previous,
                source_fingerprint=aggregate_fingerprint,
                observed_at=timestamp,
                presence="absent",
            )
        )
    snapshot = SourceSnapshot(
        collector=COLLECTOR_MARKDOWN_TOOLS,
        collected_at=timestamp,
        entries=tuple(sorted(entries, key=lambda entry: entry.key)),
    ).with_digest()
    return validate_snapshot(snapshot)


def _apply_network_evidence(
    objects: list[dict[str, Any]],
    evidence: Mapping[str, NetworkClassificationEvidence],
) -> None:
    network_objects = {
        str(obj["id"]): obj
        for obj in objects
        if obj.get("kind") == "network" and isinstance(obj.get("id"), str)
    }
    diagnostics = [
        f"unknown_mapping_ref:network:{object_id}"
        for object_id in sorted(set(evidence) - set(network_objects))
    ]
    for object_id, obj in sorted(network_objects.items()):
        data = obj.get("data")
        network = data.get("network") if isinstance(data, dict) else None
        current_category = network.get("category") if isinstance(network, dict) else None
        classification = evidence.get(object_id)
        if classification is None and current_category is None:
            diagnostics.append(f"missing_category_evidence:network:{object_id}")
        elif (
            classification is not None
            and current_category is not None
            and current_category != classification.target_category
        ):
            diagnostics.append(f"conflicting_category_evidence:network:{object_id}")
    if diagnostics:
        raise MarkdownImportNetworkError(tuple(diagnostics))

    for object_id, obj in network_objects.items():
        classification = evidence.get(object_id)
        if classification is None:
            continue
        data = obj["data"]
        data["network"]["category"] = classification.target_category
        data["import_notes"]["network_category_evidence"] = (
            classification.evidence_source
        )


def _mark_unassigned_assets(
    objects: list[dict[str, Any]],
    relationships: list[dict[str, str]],
) -> None:
    placed_refs = {
        relationship["to_ref"]
        for relationship in relationships
        if relationship["relation_type"] == "hosts"
    }
    for obj in objects:
        kind = obj.get("kind")
        object_id = obj.get("id")
        data = obj.get("data")
        if (
            kind not in {"system", "service"}
            or not isinstance(object_id, str)
            or not isinstance(data, dict)
            or f"{kind}:{object_id}" in placed_refs
        ):
            continue
        data["placement"] = {
            "state": "unassigned",
            "reason": "No canonical parent is defined by the workspace import.",
        }


def import_tools_markdown(
    session: Session,
    tools_path: str | Path,
    *,
    references_root: str | Path | None = None,
    network_evidence: Mapping[str, NetworkClassificationEvidence] | None = None,
    source_uri: str = "workspace://TOOLS.md",
) -> SeedImportResult:
    previously_covered_ids = active_owner_covered_object_ids(session)
    plan = build_tools_import_plan(
        tools_path,
        references_root=references_root,
        network_evidence=network_evidence,
        source_uri=source_uri,
    )
    objects = plan.payload["objects"]
    relationships = plan.payload["relationships"]
    if not isinstance(objects, list):
        raise ValueError("Markdown import payload must contain objects")
    if not isinstance(relationships, list):
        raise ValueError("Markdown import payload must contain relationships")

    object_payloads = [CatalogObjectIn.model_validate(raw_object) for raw_object in objects]
    known_object_kinds = current_object_kinds(session)
    known_object_kinds.update({payload.id: payload.kind for payload in object_payloads})

    imported_objects = 0
    protected_refs: set[str] = set()
    for payload in object_payloads:
        existing = session.get(CatalogObject, payload.id)
        if existing is not None:
            payload = _merge_existing_object(existing, payload)
            if payload is None:
                protected_refs.add(f"{existing.kind}:{existing.id}")
                continue
        upsert_object(
            session,
            payload,
            known_object_kinds=known_object_kinds,
        )
        imported_objects += 1

    _remove_stale_workspace_services(session, objects)

    inserted_relationships = 0
    for relationship in relationships:
        if (
            relationship["from_ref"] in protected_refs
            or relationship["to_ref"] in protected_refs
        ):
            continue
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

    ensure_owner_coverage_preserved(
        session,
        previously_covered_ids=previously_covered_ids,
    )
    return SeedImportResult(
        objects_imported=imported_objects,
        relationships_imported=inserted_relationships,
    )


def _remove_stale_workspace_services(session: Session, objects: list[dict[str, Any]]) -> None:
    imported_service_ids = {
        str(obj["id"])
        for obj in objects
        if obj.get("kind") == "service"
        and isinstance(obj.get("data"), dict)
        and obj["data"].get("source") == "workspace_markdown_import"
    }
    imported_services = {
        str(obj["label"]): str(obj["id"])
        for obj in objects
        if obj.get("kind") == "service"
        and isinstance(obj.get("data"), dict)
        and obj["data"].get("source") == "workspace_markdown_import"
    }
    if not imported_services:
        return

    rows = session.scalars(select(CatalogObject).where(CatalogObject.kind == "service")).all()
    for row in rows:
        if row.id in imported_service_ids:
            continue
        expected_id = imported_services.get(row.label)
        if not expected_id or row.id == expected_id:
            continue
        if not _is_workspace_import(row):
            continue
        stale_ref = f"service:{row.id}"
        stale_relationships = session.scalars(
            select(Relationship).where(
                (Relationship.from_ref == stale_ref) | (Relationship.to_ref == stale_ref)
            )
        ).all()
        for stale_relationship in stale_relationships:
            delete_relationship(
                session,
                stale_relationship.id,
                audit_action="markdown_relationship_delete",
                audit_actor="markdown-import",
                enforce_owner_coverage=False,
            )
        delete_object(session, row.id)
    session.flush()


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
        if not _is_workspace_import(stale_object):
            continue
        delete_relationship(
            session,
            stale_relationship.id,
            audit_action="markdown_relationship_delete",
            audit_actor="markdown-import",
            enforce_owner_coverage=False,
        )
        remaining_relationship = session.scalar(
            select(Relationship).where(
                (Relationship.from_ref == stale_relationship.from_ref)
                | (Relationship.to_ref == stale_relationship.from_ref)
            )
        )
        if remaining_relationship is None:
            delete_object(session, stale_object_id)
    session.flush()


def _is_workspace_import(row: CatalogObject) -> bool:
    provenance, valid = load_provenance(row.provenance_json)
    if (
        not valid
        or provenance.manual_override
        or provenance.source_type != "import"
        or provenance.source_ref is None
    ):
        return False
    source_ref = provenance.source_ref.replace("\\", "/")
    return (
        source_ref == "workspace_markdown_import"
        or source_ref == "TOOLS.md"
        or source_ref.endswith("/TOOLS.md")
    )


def workspace_import_object_ids(session: Session) -> frozenset[str]:
    """Return existing Markdown-import targets without reading any source file."""
    return frozenset(
        row.id
        for row in session.scalars(select(CatalogObject).order_by(CatalogObject.id))
        if _is_workspace_import(row)
    )


def _merge_existing_object(
    existing: CatalogObject,
    imported: CatalogObjectIn,
) -> CatalogObjectIn | None:
    existing_provenance, valid = load_provenance(existing.provenance_json)
    if (
        valid
        and not existing_provenance.manual_override
        and existing_provenance.source_type == "import"
        and existing_provenance.source_ref
        in {"workspace_markdown_import", imported.provenance.source_ref}
    ):
        return imported
    return None


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
    typ = (row.get("Typ", "") or row.get("Type", "")).casefold()
    if typ in {"typ", ""}:
        return True
    return "Zeitplan" in row or "Activity" in row


def _source_decision(
    row: dict[str, str],
) -> tuple[SourceClassification, MappingIntent, DecisionReason]:
    raw_classification = _plain_text(
        row.get("Classification", "")
        or row.get("Source Classification", "")
    ).casefold()
    if raw_classification:
        if raw_classification not in SOURCE_CLASSIFICATIONS:
            raise ValueError("unknown Markdown source classification")
        classification: SourceClassification = raw_classification  # type: ignore[assignment]
    elif _is_non_infra_row(row):
        classification = "ignored"
    else:
        classification = "operational"

    default_intent, default_reason = CLASSIFICATION_DEFAULTS[classification]
    raw_intent = _plain_text(
        row.get("Catalog Intent", "")
        or row.get("Mapping Intent", "")
    ).casefold()
    if raw_intent:
        if raw_intent not in MAPPING_INTENTS:
            raise ValueError("unknown Markdown mapping intent")
        intent: MappingIntent = raw_intent  # type: ignore[assignment]
    else:
        intent = default_intent

    raw_reason = _plain_text(row.get("Decision Reason", "")).casefold()
    if raw_reason:
        if raw_reason not in DECISION_REASONS:
            raise ValueError("unknown Markdown decision reason")
        reason: DecisionReason = raw_reason  # type: ignore[assignment]
    elif classification == "ignored" and _is_non_infra_row(row):
        reason = "not_infrastructure"
    else:
        reason = default_reason
    return classification, intent, reason


def _is_hosted_service_row(row: dict[str, str]) -> bool:
    typ = _plain_text(row.get("Typ", "") or row.get("Type", "")).casefold()
    if not typ:
        return False
    host_markers = ("ct", "vm", "lxc", "container")
    non_service_markers = ("host", "network", "raspberry pi", "wsl2")
    return any(marker in typ for marker in host_markers) and not any(
        marker == typ for marker in non_service_markers
    )


def _object_kind_from_type(typ: str) -> str:
    text = _plain_text(typ).casefold()
    if text == "host" or "raspberry pi" in text:
        return "host"
    if text == "network":
        return "network"
    if "service" in text:
        return "service"
    return "system"


def _host_system_id(base_id: str, typ: str) -> str:
    container = _container_data(typ)
    container_id = str(container.get("id") or "")
    if container_id:
        return container_id
    return f"{base_id}-runtime"


def _service_id(system_id: str, base_id: str) -> str:
    return f"{system_id}_{base_id}"


def _host_system_label(label: str, typ: str) -> str:
    return label


def _display_label(label: str) -> str:
    cleaned = re.sub(r"\s+\([^)]*\)$", "", label).strip()
    return cleaned or label


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
    addresses: list[dict[str, str]],
    ports: list[dict[str, Any]],
    source_references: list[dict[str, str]],
    access: str,
    auth: str,
    documented_urls: list[str],
) -> dict[str, Any]:
    data: dict[str, Any] = {
        "schema_version": 1,
        "type": "application",
        "source": "workspace_markdown_import",
        "purpose": usage,
        "endpoints": _endpoints_from_network(label, addresses, ports),
        "access_methods": _access_methods(
            _service_access_text(access),
            addresses,
            ports,
            [],
            documented_urls,
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
                "type": "Web",
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


def _state_from_cell(value: str) -> AssetState:
    for marker, state in STATUS_MARKER_STATES.items():
        if marker in value:
            return state
    text = _plain_text(value).casefold()
    if any(term in text for term in ("deleted", "retired", "decommissioned")):
        return AssetState("retired", "unknown", "deleted")
    if any(term in text for term in ("planned", "inactive")):
        return AssetState("planned", "unknown", "inactive")
    if "maintenance" in text:
        return AssetState("active", "maintenance", "inactive")
    if any(term in text for term in ("partial", "degraded", "warning")):
        return AssetState("active", "degraded", "active")
    if any(term in text for term in ("down", "offline", "failed")):
        return AssetState("active", "down", "inactive")
    if "healthy" in text:
        return AssetState("active", "healthy", "active")
    return AssetState("active", "unknown", "active")


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
        address = ipaddress.ip_address(ip)
        network = (
            str(ipaddress.ip_network(f"{address}/24", strict=False))
            if address.is_private
            else ""
        )
        addresses.append(
            {
                "ip": ip,
                "family": "ipv4",
                "interface": "",
                "network": network,
                "scope": "lan",
            }
        )
    return addresses


def _urls_from_cell(value: str) -> list[str]:
    urls: list[str] = []
    for raw_url in re.findall(r"https?://[^\s·`]+", value):
        url = raw_url.rstrip(".,;)")
        if url not in urls:
            urls.append(url)
    return urls


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
    documented_urls: list[str],
) -> list[dict[str, Any]]:
    methods = []
    ip = addresses[0]["ip"] if addresses else ""
    port_numbers = {port["port"] for port in ports}
    for chunk in re.split(r"\s+·\s+|,\s*", access):
        text = _plain_text(chunk)
        if not text or text == "-":
            continue
        method_type = _method_type(text)
        endpoint = _endpoint_for_method(
            method_type,
            ip,
            port_numbers,
            documented_urls,
        )
        if not endpoint:
            continue
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


def _endpoint_for_method(
    method_type: str,
    ip: str,
    ports: set[int],
    documented_urls: list[str],
) -> str:
    if documented_urls and method_type in {"web", "api", "other"}:
        return documented_urls[0]
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
