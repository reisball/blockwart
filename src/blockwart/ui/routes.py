import json
import re
from collections import Counter
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.domain.security import find_secret_violations
from blockwart.domain.ui_schema import (
    create_field_payload,
    get_ui_schema,
    load_editable_schema_settings,
    save_editable_schema_settings,
    schema_field_payload,
    ui_schema_payload,
)
from blockwart.models import Relationship
from blockwart.schemas.catalog import (
    ENDPOINT_TYPE_OPTIONS,
    OBJECT_STATUSES,
    PUBLIC_OBJECT_KINDS,
    CatalogObjectIn,
    CatalogObjectOut,
)
from blockwart.services.catalog import (
    create_relationship,
    get_object,
    list_audit_events_for_object,
    list_objects,
    list_relationships_for_object,
    search_objects,
    upsert_object,
)

templates = Jinja2Templates(directory="src/blockwart/ui/templates")
router = APIRouter(tags=["ui"])

OBJECT_KINDS = PUBLIC_OBJECT_KINDS
OBJECT_STATUSES_UI = OBJECT_STATUSES
RELATION_TYPES = ("hosts", "depends_on", "uses", "documents", "related_to")
PLATFORM_TYPES = ("LXC", "VM", "WSL")
UI_KIND_PRIORITY = {kind: index for index, kind in enumerate(OBJECT_KINDS)}
SAFE_DATA_JSON_FALLBACK = "{\n  \"schema_version\": 1\n}"
HARDWARE_OBJECT_KINDS = {"host", "system"}
NETWORK_ADDRESS_EDIT_KINDS = {"host", "system", "netzwerk"}
NETWORK_PORT_EDIT_KINDS: set[str] = set()
NETWORK_ENDPOINT_EDIT_KINDS = {"host", "system", "netzwerk", "service"}
ENDPOINT_TYPES = ENDPOINT_TYPE_OPTIONS


def _metadata_timestamp(value: str | None) -> str:
    if not value:
        return "-"
    parsed = _parse_timestamp(value)
    if parsed is None:
        return value
    exact = parsed.strftime("%d.%m.%Y, %H:%M Uhr")
    return f"{exact} - {_relative_timestamp(parsed)}"


def _audit_summary_lines(value: str | None) -> list[str]:
    if not value:
        return []
    return [line.strip() for line in value.split("; ") if line.strip()]


def _parse_timestamp(value: str) -> datetime | None:
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = f"{normalized[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(UTC).replace(tzinfo=None)
    return parsed


def _relative_timestamp(value: datetime) -> str:
    now = datetime.now(UTC).replace(tzinfo=None)
    delta_seconds = int((now - value).total_seconds())
    if delta_seconds < 0:
        return "gerade eben"
    minute = 60
    hour = 60 * minute
    day = 24 * hour
    if delta_seconds < minute:
        return "gerade eben"
    if delta_seconds < hour:
        minutes = delta_seconds // minute
        return f"vor {minutes} Minute" if minutes == 1 else f"vor {minutes} Minuten"
    if delta_seconds < day:
        hours = delta_seconds // hour
        return f"vor {hours} Stunde" if hours == 1 else f"vor {hours} Stunden"
    days = delta_seconds // day
    return f"vor {days} Tag" if days == 1 else f"vor {days} Tagen"


templates.env.filters["metadata_timestamp"] = _metadata_timestamp
templates.env.filters["audit_summary_lines"] = _audit_summary_lines


@router.get("/", response_class=HTMLResponse)
def index(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    q: str = "",
    kind: str = "",
    create: str = "",
    cols: str = "1",
):
    normalized_kind = kind if kind in OBJECT_KINDS else ""
    layout_cols = cols if cols in {"1", "2", "3"} else "1"
    objects = _visible_objects(
        search_objects(session, query=q.strip() or None, kind=normalized_kind or None)
    )
    all_objects = _sort_for_browse(list_objects(session))
    systems = _sort_for_browse(search_objects(session, kind="system"))
    relation_targets = _visible_objects(all_objects)
    object_map = {f"{obj.kind}:{obj.id}": obj for obj in all_objects}
    object_counts = Counter(obj.kind for obj in _visible_objects(search_objects(session)))
    total_objects = sum(object_counts.values())
    display_names = {obj.id: _primary_name_value(obj) for obj in all_objects}
    return templates.TemplateResponse(
        request,
        "index.html",
        context={
            "title": "Blockwart",
            "objects": objects,
            "q": q,
            "kind": normalized_kind,
            "layout_cols": layout_cols,
            "object_kinds": OBJECT_KINDS,
            "object_statuses": OBJECT_STATUSES_UI,
            "platform_types": PLATFORM_TYPES,
            "ui_schemas": ui_schema_payload(),
            "form_ui_schema": get_ui_schema(_empty_form()["kind"]),
            "create_fields_by_key": _fields_by_key(
                schema_field_payload(get_ui_schema(_empty_form()["kind"]))
            ),
            "display_names": display_names,
            "object_counts": object_counts,
            "total_objects": total_objects,
            "error": None,
            "form": _empty_form(),
            "systems": systems,
            "relation_targets": relation_targets,
            "relation_types": RELATION_TYPES,
            "show_create_form": create == "1",
            "index_relationships": _index_relationship_cards(session, objects, object_map),
        },
    )


@router.get("/settings/schema", response_class=HTMLResponse)
def schema_settings(
    request: Request,
    kind: str = "system",
    saved: str = "",
):
    selected_kind = kind if kind in OBJECT_KINDS else "system"
    schema = get_ui_schema(selected_kind)
    schema_fields = schema_field_payload(schema)
    return templates.TemplateResponse(
        request,
        "schema_settings.html",
        context={
            "title": "Schema Settings - Blockwart",
            "object_kinds": OBJECT_KINDS,
            "selected_kind": selected_kind,
            "ui_schema": schema,
            "schema_fields": schema_fields,
            "schema_fields_by_key": _fields_by_key(schema_fields),
            "create_fields": create_field_payload(schema),
            "ui_schemas": ui_schema_payload(),
            "saved": saved == "1",
            "error": None,
        },
    )


@router.post("/settings/schema", response_class=HTMLResponse)
async def update_schema_settings(
    request: Request,
):
    form = await request.form()
    selected_kind = str(form.get("kind") or "system")
    if selected_kind not in OBJECT_KINDS:
        selected_kind = "system"
    current = load_editable_schema_settings(selected_kind)
    field_keys = [str(key) for key in current["field_order"]]
    try:
        field_order = _schema_field_order_from_form(form, field_keys)
        fields = _schema_fields_from_form(form, field_keys)
        save_editable_schema_settings(
            selected_kind,
            field_order=field_order,
            fields=fields,
        )
    except ValueError as exc:
        schema = get_ui_schema(selected_kind)
        schema_fields = schema_field_payload(schema)
        return templates.TemplateResponse(
            request,
            "schema_settings.html",
            context={
                "title": "Schema Settings - Blockwart",
                "object_kinds": OBJECT_KINDS,
                "selected_kind": selected_kind,
                "ui_schema": schema,
                "schema_fields": schema_fields,
                "schema_fields_by_key": _fields_by_key(schema_fields),
                "create_fields": create_field_payload(schema),
                "ui_schemas": ui_schema_payload(),
                "saved": False,
                "error": _safe_error_message(exc),
            },
            status_code=422,
        )
    return RedirectResponse(url=f"/settings/schema?kind={selected_kind}&saved=1", status_code=303)


@router.get("/objects/{object_id}", response_class=HTMLResponse)
def object_detail(
    request: Request,
    object_id: str,
    session: Annotated[Session, Depends(get_session)],
    edit: str = "",
):
    catalog_object = get_object(session, object_id)
    if catalog_object is None:
        raise HTTPException(status_code=404, detail="Catalog object not found")
    all_objects = _sort_for_browse(list_objects(session))
    relationships = list_relationships_for_object(session, catalog_object)
    object_map = {f"{obj.kind}:{obj.id}": obj for obj in all_objects}
    relationship_groups = _group_relationships(catalog_object, relationships, object_map)
    relationship_targets = [
        obj for obj in all_objects if obj.id != catalog_object.id and obj.kind in OBJECT_KINDS
    ]
    object_data = catalog_object.data
    ui_schema = get_ui_schema(catalog_object.kind)
    access_methods = _display_access_methods(
        catalog_object,
        relationship_groups,
        object_map,
    )
    network = _network_summary(object_data)
    hardware = _hardware_summary(object_data)
    hardware_fields = _hardware_schema_fields(ui_schema, hardware)
    ports = _list_of_mappings(object_data.get("ports"))
    endpoints = _list_of_mappings(object_data.get("endpoints"))
    return templates.TemplateResponse(
        request,
        "object_detail.html",
        context={
            "title": f"{catalog_object.label} - Blockwart",
            "object": catalog_object,
            "relationships": relationships,
            "relationship_groups": relationship_groups,
            "relationship_targets": relationship_targets,
            "relation_types": RELATION_TYPES,
            "comment": str(object_data.get("comment") or ""),
            "audit_events": list_audit_events_for_object(session, catalog_object.id),
            "ui_schema": ui_schema,
            "schema_fields_by_key": _fields_by_key(schema_field_payload(ui_schema)),
            "primary_name_value": _primary_name_value(catalog_object),
            "network": network,
            "hardware": hardware,
            "hardware_fields": hardware_fields,
            "supports_hardware": catalog_object.kind in HARDWARE_OBJECT_KINDS,
            "container": _container_summary(object_data),
            "ports": ports,
            "endpoints": endpoints,
            "network_address_rows": _padded_mappings(
                network["addresses"],
                max(1, len(network["addresses"])),
            ),
            "port_rows": _padded_mappings(ports, max(1, len(ports))),
            "endpoint_rows": _endpoint_edit_rows(endpoints),
            "endpoint_types": ENDPOINT_TYPES,
            "can_edit_network_addresses": catalog_object.kind in NETWORK_ADDRESS_EDIT_KINDS,
            "can_edit_network_ports": catalog_object.kind in NETWORK_PORT_EDIT_KINDS,
            "can_edit_network_endpoints": catalog_object.kind in NETWORK_ENDPOINT_EDIT_KINDS,
            "access_methods": access_methods,
            "access_method_rows": _access_method_rows(catalog_object, access_methods),
            "credential_references": [],
            "data_json": json.dumps(
                _without_credential_references(catalog_object.data),
                indent=2,
                sort_keys=True,
            ),
            "object_kinds": OBJECT_KINDS,
            "object_statuses": OBJECT_STATUSES_UI,
            "error": None,
            "edit_section": edit,
        },
    )


@router.post("/objects", response_class=HTMLResponse)
def save_object(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    object_id: Annotated[str, Form()],
    kind: Annotated[str, Form()],
    label: Annotated[str | None, Form()] = None,
    primary_name: Annotated[str | None, Form()] = None,
    labels: Annotated[str, Form()] = "",
    platform: Annotated[str, Form()] = "",
    hostname: Annotated[str | None, Form()] = None,
    status: Annotated[str, Form()] = "active",
    summary: Annotated[str, Form()] = "",
    data_json: Annotated[str, Form()] = "{}",
    hosted_on_system_id: Annotated[str, Form()] = "",
    relation_target_ref: Annotated[str, Form()] = "",
    relation_type: Annotated[str, Form()] = "hosts",
):
    form = {
        "id": object_id,
        "kind": kind,
        "label": label or "",
        "primary_name": primary_name or hostname or label or "",
        "labels": labels,
        "platform": platform,
        "hostname": hostname or "",
        "status": status,
        "summary": summary,
        "data_json": data_json,
        "hosted_on_system_id": hosted_on_system_id,
        "relation_target_ref": relation_target_ref,
        "relation_type": relation_type,
    }
    try:
        data = json.loads(data_json or "{}")
        _reject_secret_shaped_form_data(data)
        ui_schema = get_ui_schema(kind)
        if platform and platform not in PLATFORM_TYPES:
            raise ValueError("Unsupported platform")
        label_values = _split_label_values(labels)
        if label_values:
            data["labels"] = label_values
        else:
            data.pop("labels", None)
        if ui_schema.supports_platform and platform:
            data["platform"] = platform
        else:
            data.pop("platform", None)
        primary_value = (primary_name or hostname or label or object_id).strip()
        _apply_primary_name(data, ui_schema, primary_value)
        hosted_on_system_id = hosted_on_system_id.strip()
        relation_target_ref = relation_target_ref.strip()
        if hosted_on_system_id and not relation_target_ref:
            relation_target_ref = f"system:{hosted_on_system_id}"
            relation_type = "hosts"
        if relation_target_ref:
            if relation_type not in RELATION_TYPES:
                raise ValueError("Unsupported relation type")
            _require_existing_ref(session, relation_target_ref)
        if kind == "service" and hosted_on_system_id:
            _require_existing_ref(session, f"system:{hosted_on_system_id}")
            data["system_id"] = f"system:{hosted_on_system_id}"
        elif (
            kind == "service"
            and relation_type == "hosts"
            and relation_target_ref.startswith("system:")
        ):
            data["system_id"] = relation_target_ref
        payload = CatalogObjectIn(
            id=object_id,
            kind=kind,
            label=primary_value or object_id,
            status=status or "active",
            summary=summary or None,
            data=data,
        )
        upsert_object(session, payload)
        if relation_target_ref:
            create_relationship(
                session,
                from_ref=relation_target_ref,
                relation_type=relation_type,
                to_ref=f"{payload.kind}:{payload.id}",
            )
    except (json.JSONDecodeError, ValidationError, ValueError) as exc:
        form["data_json"] = SAFE_DATA_JSON_FALLBACK
        objects = _visible_objects(search_objects(session))
        all_objects = _sort_for_browse(list_objects(session))
        object_map = {f"{obj.kind}:{obj.id}": obj for obj in all_objects}
        object_counts = Counter(obj.kind for obj in objects)
        return templates.TemplateResponse(
            request,
            "index.html",
            context={
                "title": "Blockwart",
                "objects": objects,
                "q": "",
                "kind": "",
                "layout_cols": "1",
                "object_kinds": OBJECT_KINDS,
                "object_statuses": OBJECT_STATUSES_UI,
                "platform_types": PLATFORM_TYPES,
                "ui_schemas": ui_schema_payload(),
                "form_ui_schema": get_ui_schema(kind),
                "create_fields_by_key": _fields_by_key(schema_field_payload(get_ui_schema(kind))),
                "display_names": {obj.id: _primary_name_value(obj) for obj in all_objects},
                "object_counts": object_counts,
                "total_objects": sum(object_counts.values()),
                "error": _safe_error_message(exc),
                "form": form,
                "systems": _sort_for_browse(search_objects(session, kind="system")),
                "relation_targets": _visible_objects(all_objects),
                "relation_types": RELATION_TYPES,
                "show_create_form": True,
                "index_relationships": _index_relationship_cards(
                    session,
                    objects,
                    object_map,
                ),
            },
            status_code=422,
        )
    return RedirectResponse(url=f"/objects/{payload.id}", status_code=303)


@router.post("/objects/{object_id}/relationships", response_class=HTMLResponse)
def save_relationship(
    object_id: str,
    session: Annotated[Session, Depends(get_session)],
    direction: Annotated[str, Form()],
    relation_type: Annotated[str, Form()],
    target_ref: Annotated[str, Form()],
):
    catalog_object = get_object(session, object_id)
    if catalog_object is None:
        raise HTTPException(status_code=404, detail="Catalog object not found")
    if relation_type not in RELATION_TYPES:
        raise HTTPException(status_code=422, detail="Unsupported relation type")
    _require_existing_ref(session, target_ref)
    object_ref = f"{catalog_object.kind}:{catalog_object.id}"
    if direction == "inbound":
        from_ref, to_ref = target_ref, object_ref
    else:
        from_ref, to_ref = object_ref, target_ref
    create_relationship(
        session,
        from_ref=from_ref,
        relation_type=relation_type,
        to_ref=to_ref,
    )
    return RedirectResponse(url=f"/objects/{object_id}", status_code=303)


@router.post("/objects/{object_id}/comment", response_class=HTMLResponse)
def update_comment(
    object_id: str,
    session: Annotated[Session, Depends(get_session)],
    comment: Annotated[str, Form()] = "",
):
    existing_object = get_object(session, object_id)
    if existing_object is None:
        raise HTTPException(status_code=404, detail="Catalog object not found")
    data = _editable_data_copy(existing_object.data)
    cleaned_comment = comment.strip()
    if cleaned_comment:
        data["comment"] = cleaned_comment
    else:
        data.pop("comment", None)
    _reject_secret_shaped_form_data(data)
    upsert_object(
        session,
        CatalogObjectIn(
            id=existing_object.id,
            kind=existing_object.kind,
            label=existing_object.label,
            status=existing_object.status,
            summary=existing_object.summary,
            data=data,
        ),
    )
    return RedirectResponse(url=f"/objects/{object_id}", status_code=303)


@router.post("/objects/{object_id}", response_class=HTMLResponse)
def update_object(
    request: Request,
    object_id: str,
    session: Annotated[Session, Depends(get_session)],
    label: Annotated[str | None, Form()] = None,
    primary_name: Annotated[str | None, Form()] = None,
    kind: Annotated[str | None, Form()] = None,
    status: Annotated[str | None, Form()] = None,
    summary: Annotated[str | None, Form()] = None,
    hostname: Annotated[str | None, Form()] = None,
    container_id: Annotated[str | None, Form()] = None,
    container_label: Annotated[str | None, Form()] = None,
    hardware_model: Annotated[str | None, Form()] = None,
    hardware_cpu_vendor: Annotated[str | None, Form()] = None,
    hardware_cpu_name: Annotated[str | None, Form()] = None,
    hardware_cpu_cores: Annotated[str | None, Form()] = None,
    hardware_memory: Annotated[str | None, Form()] = None,
    hardware_gpu: Annotated[str | None, Form()] = None,
    hardware_storage: Annotated[str | None, Form()] = None,
    data_json: Annotated[str | None, Form()] = None,
):
    submitted_hardware = any(
        value is not None
        for value in (
            hardware_model,
            hardware_cpu_vendor,
            hardware_cpu_name,
            hardware_cpu_cores,
            hardware_memory,
            hardware_gpu,
            hardware_storage,
        )
    )
    try:
        existing_object = get_object(session, object_id)
        if existing_object is None:
            raise HTTPException(status_code=404, detail="Catalog object not found")
        target_kind = kind or existing_object.kind
        data = _editable_data_copy(
            existing_object.data if data_json is None else json.loads(data_json or "{}")
        )
        ui_schema = get_ui_schema(target_kind)
        primary_value = None
        if primary_name is not None or hostname is not None or label is not None:
            primary_value = (primary_name or hostname or label or "").strip()
            _apply_primary_name(data, ui_schema, primary_value)
        if container_id is not None or container_label is not None:
            container = dict(
                data.get("container") if isinstance(data.get("container"), Mapping) else {}
            )
            if container_id is not None:
                container["id"] = container_id.strip()
            if container_label is not None:
                container["label"] = container_label.strip()
            if container:
                data["container"] = container
        if target_kind in HARDWARE_OBJECT_KINDS and submitted_hardware:
            allowed_hardware_fields = {
                str(field["key"])
                for field in schema_field_payload(ui_schema)
                if str(field["key"]).startswith("hardware_")
            }
            _apply_hardware_fields(
                data,
                model=hardware_model if "hardware_model" in allowed_hardware_fields else None,
                cpu_vendor=(
                    hardware_cpu_vendor
                    if "hardware_cpu_vendor" in allowed_hardware_fields
                    else None
                ),
                cpu_name=(
                    hardware_cpu_name if "hardware_cpu_name" in allowed_hardware_fields else None
                ),
                cpu_cores=(
                    hardware_cpu_cores
                    if "hardware_cpu_cores" in allowed_hardware_fields
                    else None
                ),
                memory=hardware_memory if "hardware_memory" in allowed_hardware_fields else None,
                gpu=hardware_gpu if "hardware_gpu" in allowed_hardware_fields else None,
                storage=hardware_storage if "hardware_storage" in allowed_hardware_fields else None,
            )
        _reject_secret_shaped_form_data(data)
        payload = CatalogObjectIn(
            id=object_id,
            kind=target_kind,
            label=primary_value or label or existing_object.label,
            status=status or existing_object.status or "active",
            summary=existing_object.summary if summary is None else summary or None,
            data=data,
        )
        upsert_object(session, payload)
    except (json.JSONDecodeError, ValidationError, ValueError) as exc:
        catalog_object = get_object(session, object_id)
        if catalog_object is None:
            raise HTTPException(status_code=404, detail="Catalog object not found") from exc
        relationships = list_relationships_for_object(session, catalog_object)
        all_objects = _sort_for_browse(list_objects(session))
        object_map = {f"{obj.kind}:{obj.id}": obj for obj in all_objects}
        object_data = catalog_object.data
        ui_schema = get_ui_schema(catalog_object.kind)
        network = _network_summary(object_data)
        hardware = _hardware_summary(object_data)
        hardware_fields = _hardware_schema_fields(ui_schema, hardware)
        ports = _list_of_mappings(object_data.get("ports"))
        endpoints = _list_of_mappings(object_data.get("endpoints"))
        relationship_groups = _group_relationships(
            catalog_object,
            relationships,
            object_map,
        )
        access_methods = _display_access_methods(
            catalog_object,
            relationship_groups,
            object_map,
        )
        return templates.TemplateResponse(
            request,
            "object_detail.html",
            context={
                "title": f"{catalog_object.label} - Blockwart",
                "object": catalog_object,
                "relationships": relationships,
                "relationship_groups": relationship_groups,
                "relationship_targets": [obj for obj in all_objects if obj.id != catalog_object.id],
                "relation_types": RELATION_TYPES,
                "comment": str(object_data.get("comment") or ""),
                "audit_events": list_audit_events_for_object(session, catalog_object.id),
                "ui_schema": ui_schema,
                "schema_fields_by_key": _fields_by_key(schema_field_payload(ui_schema)),
                "primary_name_value": _primary_name_value(catalog_object),
                "network": network,
                "hardware": hardware,
                "hardware_fields": hardware_fields,
                "supports_hardware": catalog_object.kind in HARDWARE_OBJECT_KINDS,
                "container": _container_summary(object_data),
                "ports": ports,
                "endpoints": endpoints,
                "network_address_rows": _padded_mappings(
                    network["addresses"],
                    max(1, len(network["addresses"])),
                ),
                "port_rows": _padded_mappings(ports, max(1, len(ports))),
                "endpoint_rows": _endpoint_edit_rows(endpoints),
                "endpoint_types": ENDPOINT_TYPES,
                "can_edit_network_addresses": catalog_object.kind in NETWORK_ADDRESS_EDIT_KINDS,
                "can_edit_network_ports": catalog_object.kind in NETWORK_PORT_EDIT_KINDS,
                "can_edit_network_endpoints": catalog_object.kind in NETWORK_ENDPOINT_EDIT_KINDS,
                "access_methods": access_methods,
                "access_method_rows": _access_method_rows(catalog_object, access_methods),
                "credential_references": [],
                "data_json": SAFE_DATA_JSON_FALLBACK,
                "object_kinds": OBJECT_KINDS,
                "object_statuses": OBJECT_STATUSES_UI,
                "error": _safe_error_message(exc),
                "edit_section": "hardware" if submitted_hardware else "overview",
            },
            status_code=422,
        )
    return RedirectResponse(url=f"/objects/{payload.id}", status_code=303)


@router.post("/objects/{object_id}/network", response_class=HTMLResponse)
async def update_network(
    request: Request,
    object_id: str,
    session: Annotated[Session, Depends(get_session)],
):
    existing_object = get_object(session, object_id)
    if existing_object is None:
        raise HTTPException(status_code=404, detail="Catalog object not found")
    form = await request.form()
    data = _editable_data_copy(existing_object.data)
    network = dict(data.get("network") if isinstance(data.get("network"), Mapping) else {})
    if existing_object.kind in NETWORK_ADDRESS_EDIT_KINDS:
        network["addresses"] = [
            {
                **address,
                "ip": ip,
                "interface": interface,
                "scope": scope,
            }
            for address, ip, interface, scope in zip(
                _padded_mappings(network.get("addresses"), len(form.getlist("address_ip"))),
                form.getlist("address_ip"),
                form.getlist("address_interface"),
                form.getlist("address_scope"),
                strict=False,
            )
            if str(ip).strip()
        ]
        data["network"] = network
    if existing_object.kind in NETWORK_PORT_EDIT_KINDS:
        data["ports"] = [
            {
                **port,
                "port": int(port_value),
                "protocol": protocol or "tcp",
                "purpose": purpose,
                "exposure": exposure,
            }
            for port, port_value, protocol, purpose, exposure in zip(
                _padded_mappings(data.get("ports"), len(form.getlist("port_value"))),
                form.getlist("port_value"),
                form.getlist("port_protocol"),
                form.getlist("port_purpose"),
                form.getlist("port_exposure"),
                strict=False,
            )
            if str(port_value).strip()
        ]
    if existing_object.kind in NETWORK_ENDPOINT_EDIT_KINDS:
        try:
            data["endpoints"] = [
                _endpoint_payload(endpoint, endpoint_type, url, port_value)
                for endpoint, endpoint_type, url, port_value in zip(
                    _padded_mappings(data.get("endpoints"), len(form.getlist("endpoint_type"))),
                    form.getlist("endpoint_type"),
                    form.getlist("endpoint_url"),
                    form.getlist("endpoint_port"),
                    strict=False,
                )
                if str(endpoint_type).strip() or str(url).strip() or str(port_value).strip()
            ]
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
    _reject_secret_shaped_form_data(data)
    upsert_object(
        session,
        CatalogObjectIn(
            id=existing_object.id,
            kind=existing_object.kind,
            label=existing_object.label,
            status=existing_object.status,
            summary=existing_object.summary,
            data=data,
        ),
    )
    return RedirectResponse(url=f"/objects/{object_id}", status_code=303)


@router.post("/objects/{object_id}/access", response_class=HTMLResponse)
async def update_access(
    request: Request,
    object_id: str,
    session: Annotated[Session, Depends(get_session)],
):
    if get_object(session, object_id) is None:
        raise HTTPException(status_code=404, detail="Catalog object not found")
    form = await request.form()
    refs = [str(value) for value in form.getlist("method_ref")]
    indexes = [str(value) for value in form.getlist("method_index")]
    types = [str(value) for value in form.getlist("method_type")]
    endpoints = [str(value) for value in form.getlist("method_endpoint")]
    auth_modes = [str(value) for value in form.getlist("method_auth_mode")]
    changed_objects: dict[str, CatalogObjectOut] = {}
    changed_data: dict[str, dict[str, Any]] = {}
    for ref, index_text, method_type, endpoint, auth_mode in zip(
        refs,
        indexes,
        types,
        endpoints,
        auth_modes,
        strict=False,
    ):
        if ":" not in ref:
            continue
        kind, target_id = ref.split(":", 1)
        target = changed_objects.get(ref) or get_object(session, target_id)
        if target is None or target.kind != kind:
            continue
        changed_objects[ref] = target
        data = changed_data.setdefault(ref, _editable_data_copy(target.data))
        methods = data.get("access_methods")
        if not isinstance(methods, list):
            methods = []
            data["access_methods"] = methods
        try:
            index = int(index_text)
        except ValueError:
            continue
        if index < 0:
            continue
        while len(methods) <= index:
            methods.append({})
        if not isinstance(methods[index], dict):
            methods[index] = {}
        if not method_type.strip() and not endpoint.strip() and not auth_mode.strip():
            continue
        methods[index] = {
            **methods[index],
            "type": method_type,
            "endpoint": endpoint,
            "auth_mode": auth_mode,
        }
    for ref, data in changed_data.items():
        _reject_secret_shaped_form_data(data)
        target = changed_objects[ref]
        upsert_object(
            session,
            CatalogObjectIn(
                id=target.id,
                kind=target.kind,
                label=target.label,
                status=target.status,
                summary=target.summary,
                data=data,
            ),
        )
    return RedirectResponse(url=f"/objects/{object_id}", status_code=303)


def _empty_form() -> dict[str, str]:
    return {
        "id": "",
        "kind": "system",
        "label": "",
        "primary_name": "",
        "labels": "",
        "platform": "",
        "hostname": "",
        "status": "active",
        "summary": "",
        "data_json": SAFE_DATA_JSON_FALLBACK,
        "hosted_on_system_id": "",
        "relation_target_ref": "",
        "relation_type": "hosts",
    }


def _split_label_values(raw_labels: str) -> list[str]:
    labels: list[str] = []
    seen: set[str] = set()
    for value in re.split(r"[,;\n]+", raw_labels):
        label = value.strip()
        if not label or label.casefold() in seen:
            continue
        seen.add(label.casefold())
        labels.append(label)
    return labels


def _require_existing_ref(session: Session, ref: str) -> None:
    if ":" not in ref:
        raise HTTPException(status_code=422, detail="Invalid object reference")
    kind, object_id = ref.split(":", 1)
    target = get_object(session, object_id)
    if target is None or target.kind != kind:
        raise HTTPException(status_code=422, detail="Relationship target does not exist")


def _reject_secret_shaped_form_data(data: object) -> None:
    violations = find_secret_violations(data)
    if violations:
        raise ValueError("; ".join(violations))


def _safe_error_message(exc: Exception) -> str:
    if isinstance(exc, json.JSONDecodeError):
        return f"data_json is not valid JSON: {exc.msg}"
    if isinstance(exc, ValueError):
        return str(exc)
    return "Invalid catalog object payload."


def _primary_name_value(catalog_object: CatalogObjectOut) -> str:
    schema = get_ui_schema(catalog_object.kind)
    if schema.primary_name_storage == "network_hostname":
        network = _network_summary(catalog_object.data)
        if network["hostnames"]:
            return str(network["hostnames"][0])
    return catalog_object.label


def _apply_primary_name(data: dict[str, Any], schema: Any, value: str) -> None:
    if schema.primary_name_storage != "network_hostname":
        return
    network = dict(data.get("network") if isinstance(data.get("network"), Mapping) else {})
    existing_hostnames = network.get("hostnames")
    hostname_values = (
        [str(hostname) for hostname in existing_hostnames]
        if isinstance(existing_hostnames, list)
        else []
    )
    network["hostnames"] = [value, *hostname_values[1:]] if value else hostname_values[1:]
    if network["hostnames"] or network.get("addresses") or network.get("mac_addresses"):
        data["network"] = network
    else:
        data.pop("network", None)


def _access_method_rows(
    catalog_object: CatalogObjectOut,
    access_methods: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if access_methods:
        return access_methods
    return [
        {
            "type": "",
            "endpoint": "",
            "auth_mode": "",
            "source_kind": catalog_object.kind,
            "source_label": catalog_object.label,
            "source_ref": f"{catalog_object.kind}:{catalog_object.id}",
            "index": 0,
        }
    ]


def _sort_for_browse(objects: list[CatalogObjectOut]) -> list[CatalogObjectOut]:
    return sorted(
        objects,
        key=lambda obj: (
            UI_KIND_PRIORITY.get(obj.kind, len(UI_KIND_PRIORITY)),
            obj.label.casefold(),
            obj.id.casefold(),
        ),
    )


def _visible_objects(objects: list[CatalogObjectOut]) -> list[CatalogObjectOut]:
    return _sort_for_browse([obj for obj in objects if obj.kind in OBJECT_KINDS])


def _index_relationship_cards(
    session: Session,
    objects: list[CatalogObjectOut],
    object_map: dict[str, CatalogObjectOut],
) -> dict[str, dict[str, Any]]:
    cards: dict[str, dict[str, Any]] = {}
    all_relationships = _all_relationships(session)
    for catalog_object in objects:
        relationships = list_relationships_for_object(session, catalog_object)
        grouped = _group_relationships(catalog_object, relationships, object_map)
        cards[catalog_object.id] = {
            "relationships": _relationship_display_cards(catalog_object, grouped, object_map),
            "topology": _relationship_topology(catalog_object, all_relationships, object_map),
        }
    return cards


def _all_relationships(session: Session) -> list[dict[str, str]]:
    rows = session.scalars(
        select(Relationship).order_by(
            Relationship.relation_type,
            Relationship.from_ref,
            Relationship.to_ref,
        )
    ).all()
    return [
        {
            "from_ref": row.from_ref,
            "relation_type": row.relation_type,
            "to_ref": row.to_ref,
        }
        for row in rows
    ]


def _relationship_topology(
    catalog_object: CatalogObjectOut,
    relationships: list[dict[str, str]],
    object_map: dict[str, CatalogObjectOut],
) -> dict[str, Any]:
    current_ref = f"{catalog_object.kind}:{catalog_object.id}"
    systems_by_host: dict[str, list[str]] = {}
    hosts_by_system: dict[str, list[str]] = {}
    services_by_system: dict[str, list[str]] = {}
    systems_by_service: dict[str, list[str]] = {}

    for relationship in relationships:
        from_ref = relationship["from_ref"]
        to_ref = relationship["to_ref"]
        relation_type = relationship["relation_type"]
        from_object = object_map.get(from_ref)
        to_object = object_map.get(to_ref)
        from_kind = from_object.kind if from_object else from_ref.split(":", 1)[0]
        to_kind = to_object.kind if to_object else to_ref.split(":", 1)[0]

        if relation_type == "hosts" and from_kind in {"host", "system"} and to_kind == "system":
            if from_ref != to_ref:
                _append_unique_ref(systems_by_host, from_ref, to_ref)
                _append_unique_ref(hosts_by_system, to_ref, from_ref)
        if (
            relation_type in {"hosts", "provides"}
            and from_kind == "system"
            and to_kind == "service"
        ):
            _append_unique_ref(services_by_system, from_ref, to_ref)
            _append_unique_ref(systems_by_service, to_ref, from_ref)

    for ref, obj in object_map.items():
        if obj.kind != "service":
            continue
        system_ref = obj.data.get("system_id")
        if isinstance(system_ref, str) and system_ref.startswith("system:"):
            _append_unique_ref(services_by_system, system_ref, ref)
            _append_unique_ref(systems_by_service, ref, system_ref)

    if catalog_object.kind == "service":
        system_refs = systems_by_service.get(current_ref, [])
        host_refs = _unique_refs(
            host_ref
            for system_ref in system_refs
            for host_ref in hosts_by_system.get(system_ref, [])
        )
        return {
            "chains": [
                {
                    "hosts": _relationship_nodes(host_refs, object_map),
                    "systems": _relationship_nodes(system_refs, object_map),
                    "services": [_relationship_node(current_ref, catalog_object)],
                }
            ]
        }

    if catalog_object.kind in {"host", "system"} and systems_by_host.get(current_ref):
        system_refs = systems_by_host[current_ref]
        service_refs = _unique_refs(
            service_ref
            for system_ref in system_refs
            for service_ref in services_by_system.get(system_ref, [])
        )
        return {
            "chains": [
                {
                    "hosts": [_relationship_node(current_ref, catalog_object)],
                    "systems": _relationship_nodes(system_refs, object_map),
                    "services": _relationship_nodes(service_refs, object_map),
                }
            ]
        }

    if catalog_object.kind == "system":
        host_refs = hosts_by_system.get(current_ref, [])
        service_refs = services_by_system.get(current_ref, [])
        return {
            "chains": [
                {
                    "hosts": _relationship_nodes(host_refs, object_map),
                    "systems": [_relationship_node(current_ref, catalog_object)],
                    "services": _relationship_nodes(service_refs, object_map),
                }
            ]
        }

    return {"chains": []}


def _append_unique_ref(target: dict[str, list[str]], key: str, value: str) -> None:
    values = target.setdefault(key, [])
    if value not in values:
        values.append(value)


def _unique_refs(values: Any) -> list[str]:
    seen: set[str] = set()
    unique: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        unique.append(value)
    return unique


def _relationship_nodes(
    refs: list[str],
    object_map: dict[str, CatalogObjectOut],
) -> list[dict[str, Any]]:
    return [_relationship_node(ref, object_map.get(ref)) for ref in refs]


def _relationship_display_sort_key(card: dict[str, Any]) -> tuple[int, str, str]:
    left_kind = card["left"]["kind"]
    right_kind = card["right"]["kind"]
    is_system_service = left_kind == "system" and right_kind == "service"
    return (0 if is_system_service else 1, card["left"]["label"], card["right"]["label"])


def _relationship_display_cards(
    catalog_object: CatalogObjectOut,
    grouped: dict[str, list[dict[str, str]]],
    object_map: dict[str, CatalogObjectOut],
) -> list[dict[str, Any]]:
    cards: list[dict[str, Any]] = []
    current_ref = f"{catalog_object.kind}:{catalog_object.id}"
    for relationship in [
        relationship
        for direction in ("outbound", "inbound")
        for relationship in grouped.get(direction, [])
    ]:
        from_ref = relationship["from_ref"]
        to_ref = relationship["to_ref"]
        from_object = object_map.get(from_ref)
        to_object = object_map.get(to_ref)
        left_ref = from_ref
        right_ref = to_ref
        left_ref, right_ref = _system_service_refs(
            from_ref,
            to_ref,
            from_object,
            to_object,
        )
        left_object = object_map.get(left_ref)
        right_object = object_map.get(right_ref)
        cards.append(
            {
                **relationship,
                "left": _relationship_node(left_ref, left_object),
                "right": _relationship_node(right_ref, right_object),
                "current_side": "left" if left_ref == current_ref else "right",
            }
        )
    return sorted(cards, key=_relationship_display_sort_key)


def _system_service_refs(
    from_ref: str,
    to_ref: str,
    from_object: CatalogObjectOut | None,
    to_object: CatalogObjectOut | None,
) -> tuple[str, str]:
    if from_object is not None and to_object is not None:
        if from_object.kind == "system" and to_object.kind == "service":
            return from_ref, to_ref
        if from_object.kind == "service" and to_object.kind == "system":
            return to_ref, from_ref
    if from_ref.startswith("system:") and to_ref.startswith("service:"):
        return from_ref, to_ref
    if from_ref.startswith("service:") and to_ref.startswith("system:"):
        return to_ref, from_ref
    return from_ref, to_ref


def _relationship_node(
    ref: str,
    catalog_object: CatalogObjectOut | None,
) -> dict[str, Any]:
    kind = catalog_object.kind if catalog_object else ref.split(":", 1)[0]
    return {
        "ref": ref,
        "id": catalog_object.id if catalog_object else _object_id_from_ref(ref),
        "kind": kind,
        "label": _primary_name_value(catalog_object) if catalog_object else ref,
        "status": catalog_object.status if catalog_object else "",
        "data": catalog_object.data if catalog_object else {},
        "ports": _relationship_node_ports(catalog_object),
    }


def _group_relationships(
    catalog_object: CatalogObjectOut,
    relationships: list[dict[str, str]],
    object_map: dict[str, CatalogObjectOut],
) -> dict[str, list[dict[str, str]]]:
    current_ref = f"{catalog_object.kind}:{catalog_object.id}"
    grouped: dict[str, list[dict[str, str]]] = {}
    for relationship in relationships:
        direction = "outbound" if relationship["from_ref"] == current_ref else "inbound"
        other_ref = (
            relationship["to_ref"]
            if direction == "outbound"
            else relationship["from_ref"]
        )
        other_object = object_map.get(other_ref)
        grouped.setdefault(direction, []).append(
            {
                **relationship,
                "other_ref": other_ref,
                "other_id": _object_id_from_ref(other_ref),
                "other_kind": other_object.kind if other_object else other_ref.split(":", 1)[0],
                "other_label": _primary_name_value(other_object) if other_object else other_ref,
                "other_status": other_object.status if other_object else "",
                "other_data": other_object.data if other_object else {},
            }
        )
    return grouped


def _relationship_node_ports(catalog_object: CatalogObjectOut | None) -> list[dict[str, str]]:
    if catalog_object is None:
        return []
    if catalog_object.kind == "system":
        return _relationship_system_ports(catalog_object)
    if catalog_object.kind == "service":
        return _relationship_service_ports(catalog_object, None)
    return []


def _relationship_system_ports(catalog_object: CatalogObjectOut) -> list[dict[str, str]]:
    if catalog_object.kind == "service":
        return _relationship_service_ports(catalog_object, None)
    return []


def _relationship_service_ports(
    catalog_object: CatalogObjectOut,
    other_object: CatalogObjectOut | None,
) -> list[dict[str, str]]:
    service = catalog_object if catalog_object.kind == "service" else other_object
    if service is None or service.kind != "service":
        return []
    ports: list[dict[str, str]] = []
    for endpoint in _list_of_mappings(service.data.get("endpoints")):
        port = endpoint.get("port")
        if port is None:
            continue
        protocol = str(endpoint.get("protocol") or "tcp")
        ports.append({"label": "service", "value": f"{port}/{protocol}"})
    return ports


def _display_access_methods(
    catalog_object: CatalogObjectOut,
    relationship_groups: dict[str, list[dict[str, str]]],
    object_map: dict[str, CatalogObjectOut],
) -> list[dict[str, Any]]:
    methods = _access_methods(
        catalog_object.data,
        source_kind=catalog_object.kind,
        source_label=catalog_object.label,
        source_ref=f"{catalog_object.kind}:{catalog_object.id}",
    )
    if catalog_object.kind != "system":
        return methods
    for relationship in relationship_groups.get("outbound", []):
        if relationship.get("relation_type") != "hosts":
            continue
        service = object_map.get(relationship.get("to_ref", ""))
        if service is None or service.kind != "service":
            continue
        methods.extend(
            _access_methods(
                service.data,
                source_kind="service",
                source_label=service.label,
                source_ref=f"service:{service.id}",
            )
        )
    return methods


def _object_id_from_ref(value: str) -> str:
    if ":" not in value:
        return value
    return value.split(":", 1)[1]


def _network_summary(data: Mapping[str, Any]) -> dict[str, list[Mapping[str, Any]] | list[str]]:
    network = data.get("network")
    if not isinstance(network, Mapping):
        return {"hostnames": [], "addresses": [], "mac_addresses": []}
    hostnames = network.get("hostnames")
    hostname_values = (
        [str(hostname) for hostname in hostnames]
        if isinstance(hostnames, list)
        else []
    )
    return {
        "hostnames": hostname_values,
        "addresses": _list_of_mappings(network.get("addresses")),
        "mac_addresses": _list_of_mappings(network.get("mac_addresses")),
    }


def _container_summary(data: Mapping[str, Any]) -> Mapping[str, Any] | None:
    container = data.get("container")
    return container if isinstance(container, Mapping) else None


def _hardware_summary(data: Mapping[str, Any]) -> dict[str, str]:
    hardware = data.get("hardware")
    if not isinstance(hardware, Mapping):
        return {
            "model": "",
            "cpu_vendor": "",
            "cpu_name": "",
            "cpu_cores": "",
            "memory": "",
            "gpu": "",
            "storage": "",
        }
    cpu = hardware.get("cpu")
    cpu_data = cpu if isinstance(cpu, Mapping) else {}
    return {
        "model": str(hardware.get("model") or ""),
        "cpu_vendor": str(cpu_data.get("vendor") or ""),
        "cpu_name": str(cpu_data.get("name") or ""),
        "cpu_cores": str(cpu_data.get("cores") or ""),
        "memory": str(hardware.get("memory") or ""),
        "gpu": str(hardware.get("gpu") or ""),
        "storage": str(hardware.get("storage") or ""),
    }


def _hardware_schema_fields(ui_schema: Any, hardware: Mapping[str, str]) -> list[dict[str, str]]:
    hardware_values = {
        "hardware_model": hardware.get("model", ""),
        "hardware_cpu_vendor": hardware.get("cpu_vendor", ""),
        "hardware_cpu_name": hardware.get("cpu_name", ""),
        "hardware_cpu_cores": hardware.get("cpu_cores", ""),
        "hardware_memory": hardware.get("memory", ""),
        "hardware_gpu": hardware.get("gpu", ""),
        "hardware_storage": hardware.get("storage", ""),
    }
    return [
        {
            "key": str(field["key"]),
            "label": str(field["label"]),
            "placeholder": str(field["placeholder"] or ""),
            "value": hardware_values.get(str(field["key"]), ""),
        }
        for field in schema_field_payload(ui_schema)
        if str(field["key"]).startswith("hardware_")
    ]


def _apply_hardware_fields(
    data: dict[str, Any],
    *,
    model: str | None,
    cpu_vendor: str | None,
    cpu_name: str | None,
    cpu_cores: str | None,
    memory: str | None,
    gpu: str | None,
    storage: str | None,
) -> None:
    existing_hardware = data.get("hardware")
    hardware = dict(existing_hardware if isinstance(existing_hardware, Mapping) else {})
    for key, value in {
        "model": model,
        "memory": memory,
        "gpu": gpu,
        "storage": storage,
    }.items():
        if value is None:
            continue
        clean_value = value.strip()
        if clean_value:
            hardware[key] = clean_value
        else:
            hardware.pop(key, None)
    cpu = dict(hardware.get("cpu") if isinstance(hardware.get("cpu"), Mapping) else {})
    for key, value in {
        "vendor": cpu_vendor,
        "name": cpu_name,
        "cores": cpu_cores,
    }.items():
        if value is None:
            continue
        clean_value = value.strip()
        if clean_value:
            cpu[key] = clean_value
        else:
            cpu.pop(key, None)
    if cpu:
        hardware["cpu"] = cpu
    else:
        hardware.pop("cpu", None)
    if hardware:
        data["hardware"] = hardware
    else:
        data.pop("hardware", None)


def _access_methods(
    data: Mapping[str, Any],
    *,
    source_kind: str,
    source_label: str,
    source_ref: str,
) -> list[dict[str, Any]]:
    methods = _list_of_mappings(data.get("access_methods"))
    return [
        {
            "type": str(method.get("type") or "access"),
            "endpoint": str(method.get("endpoint") or ""),
            "auth_mode": str(method.get("auth_mode") or "unknown"),
            "source_kind": source_kind,
            "source_label": source_label,
            "source_ref": source_ref,
            "index": index,
        }
        for index, method in enumerate(methods)
    ]


def _editable_data_copy(data: Mapping[str, Any]) -> dict[str, Any]:
    return json.loads(json.dumps(data))


def _endpoint_edit_rows(endpoints: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    rows = _padded_mappings(endpoints, max(1, len(endpoints)))
    for row in rows:
        row["type"] = _normalize_endpoint_type(
            row.get("type") or row.get("name") or row.get("label")
        )
    return rows


def _endpoint_payload(
    endpoint: Mapping[str, Any],
    endpoint_type: object,
    url: object,
    port_value: object,
) -> dict[str, Any]:
    payload = dict(endpoint)
    payload.pop("name", None)
    payload.pop("label", None)
    normalized_type = _normalize_endpoint_type(endpoint_type)
    if not normalized_type:
        allowed = ", ".join(ENDPOINT_TYPES)
        raise ValueError(f"endpoint type must be one of: {allowed}")
    payload["type"] = normalized_type
    payload["url"] = str(url).strip()
    payload["port"] = int(port_value) if str(port_value).strip() else ""
    return payload


def _normalize_endpoint_type(value: object) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    compact = re.sub(r"[^a-z0-9]+", "", raw.lower())
    aliases = {
        "web": "Web",
        "webui": "Web",
        "ui": "Web",
        "rest": "REST API",
        "restapi": "REST API",
        "api": "REST API",
        "apibase": "REST API",
        "managementapi": "REST API",
        "lanmanagementapi": "REST API",
        "publicmanagementapi": "REST API",
        "mcp": "MCP",
        "hec": "HEC",
        "ssh": "SSH",
    }
    return aliases.get(compact, raw if raw in ENDPOINT_TYPES else "")


def _split_multivalue(value: str) -> list[str]:
    return [item.strip() for item in value.replace("\n", ",").split(",") if item.strip()]


def _padded_mappings(value: Any, count: int) -> list[dict[str, Any]]:
    items = [dict(item) for item in _list_of_mappings(value)]
    while len(items) < count:
        items.append({})
    return items[:count]


def _fields_by_key(fields: list[Mapping[str, Any]]) -> dict[str, Mapping[str, Any]]:
    return {str(field["key"]): field for field in fields}


def _schema_field_order_from_form(form: Any, field_keys: list[str]) -> list[str]:
    order_pairs: list[tuple[int, int, str]] = []
    for fallback_index, key in enumerate(field_keys, start=1):
        raw_order = str(form.get(f"field_order_{key}") or fallback_index)
        try:
            order = int(raw_order)
        except ValueError as exc:
            raise ValueError(f"{key}.order must be a number") from exc
        order_pairs.append((order, fallback_index, key))
    return [key for _, _, key in sorted(order_pairs)]


def _schema_fields_from_form(
    form: Any,
    field_keys: list[str],
) -> dict[str, dict[str, str | bool]]:
    fields: dict[str, dict[str, str | bool]] = {}
    for key in field_keys:
        label = str(form.get(f"field_label_{key}") or "").strip()
        if not label:
            raise ValueError(f"{key}.label must not be empty")
        fields[key] = {
            "label": label,
            "placeholder": str(form.get(f"field_placeholder_{key}") or "").strip(),
            "required": form.get(f"field_required_{key}") == "1",
            "visible_in_detail": form.get(f"field_visible_in_detail_{key}") == "1",
        }
    return fields


def _without_credential_references(value: Any) -> Any:
    if isinstance(value, Mapping):
        cleaned: dict[str, Any] = {}
        for key, child in value.items():
            if key == "credential_references":
                continue
            cleaned[key] = _without_credential_references(child)
        return cleaned
    if isinstance(value, list):
        return [
            cleaned_child
            for item in value
            if not _is_credential_ref(item)
            for cleaned_child in [_without_credential_references(item)]
        ]
    if _is_credential_ref(value):
        return ""
    return value


def _credential_references(data: Mapping[str, Any]) -> list[dict[str, str]]:
    return [
        {"ref": ref, "id": _object_id_from_ref(ref)}
        for ref in sorted(_collect_credential_references(data))
    ]


def _collect_credential_references(value: Any) -> set[str]:
    references: set[str] = set()
    if isinstance(value, Mapping):
        for child in value.values():
            if _is_credential_ref(child):
                references.add(child)
            references.update(_collect_credential_references(child))
    elif isinstance(value, list):
        for child in value:
            if _is_credential_ref(child):
                references.add(child)
            references.update(_collect_credential_references(child))
    return references


def _is_credential_ref(value: Any) -> bool:
    return isinstance(value, str) and value.startswith("credential_reference:")


def _list_of_mappings(value: Any) -> list[Mapping[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, Mapping)]
