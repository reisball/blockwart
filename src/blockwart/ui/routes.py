import json
from collections import Counter
from collections.abc import Mapping
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.domain.security import find_secret_violations
from blockwart.schemas.catalog import (
    OBJECT_STATUSES,
    PUBLIC_OBJECT_KINDS,
    CatalogObjectIn,
    CatalogObjectOut,
)
from blockwart.services.catalog import (
    create_relationship,
    get_object,
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
UI_KIND_PRIORITY = {kind: index for index, kind in enumerate(OBJECT_KINDS)}
SAFE_DATA_JSON_FALLBACK = "{\n  \"schema_version\": 1\n}"


@router.get("/", response_class=HTMLResponse)
def index(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    q: str = "",
    kind: str = "",
    create: str = "",
):
    normalized_kind = kind if kind in OBJECT_KINDS else ""
    objects = _visible_objects(
        search_objects(session, query=q.strip() or None, kind=normalized_kind or None)
    )
    systems = _sort_for_browse(search_objects(session, kind="system"))
    relation_targets = _visible_objects(list_objects(session))
    object_counts = Counter(obj.kind for obj in _visible_objects(search_objects(session)))
    total_objects = sum(object_counts.values())
    return templates.TemplateResponse(
        request,
        "index.html",
        context={
            "title": "Blockwart",
            "objects": objects,
            "q": q,
            "kind": normalized_kind,
            "object_kinds": OBJECT_KINDS,
            "object_statuses": OBJECT_STATUSES_UI,
            "object_counts": object_counts,
            "total_objects": total_objects,
            "error": None,
            "form": _empty_form(),
            "systems": systems,
            "relation_targets": relation_targets,
            "relation_types": RELATION_TYPES,
            "show_create_form": create == "1",
        },
    )


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
            "source_references": _source_references(object_data),
            "network": _network_summary(object_data),
            "container": _container_summary(object_data),
            "ports": _list_of_mappings(object_data.get("ports")),
            "endpoints": _list_of_mappings(object_data.get("endpoints")),
            "access_methods": _display_access_methods(
                catalog_object,
                relationship_groups,
                object_map,
            ),
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
    label: Annotated[str, Form()],
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
        "label": label,
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
            label=label,
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
        object_counts = Counter(obj.kind for obj in objects)
        return templates.TemplateResponse(
            request,
            "index.html",
            context={
                "title": "Blockwart",
                "objects": objects,
                "q": "",
                "kind": "",
                "object_kinds": OBJECT_KINDS,
                "object_statuses": OBJECT_STATUSES_UI,
                "object_counts": object_counts,
                "total_objects": sum(object_counts.values()),
                "error": _safe_error_message(exc),
                "form": form,
                "systems": _sort_for_browse(search_objects(session, kind="system")),
                "relation_targets": _visible_objects(list_objects(session)),
                "relation_types": RELATION_TYPES,
                "show_create_form": True,
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


@router.post("/objects/{object_id}", response_class=HTMLResponse)
def update_object(
    request: Request,
    object_id: str,
    session: Annotated[Session, Depends(get_session)],
    label: Annotated[str, Form()],
    kind: Annotated[str | None, Form()] = None,
    status: Annotated[str, Form()] = "active",
    summary: Annotated[str, Form()] = "",
    hostname: Annotated[str | None, Form()] = None,
    container_id: Annotated[str | None, Form()] = None,
    container_label: Annotated[str | None, Form()] = None,
    data_json: Annotated[str | None, Form()] = None,
):
    try:
        existing_object = get_object(session, object_id)
        if existing_object is None:
            raise HTTPException(status_code=404, detail="Catalog object not found")
        data = _editable_data_copy(
            existing_object.data if data_json is None else json.loads(data_json or "{}")
        )
        if hostname is not None:
            network = dict(data.get("network") if isinstance(data.get("network"), Mapping) else {})
            existing_hostnames = network.get("hostnames")
            hostname_values = (
                [str(value) for value in existing_hostnames]
                if isinstance(existing_hostnames, list)
                else []
            )
            primary_hostname = hostname.strip()
            network["hostnames"] = (
                [primary_hostname, *hostname_values[1:]]
                if primary_hostname
                else hostname_values[1:]
            )
            data["network"] = network
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
        _reject_secret_shaped_form_data(data)
        payload = CatalogObjectIn(
            id=object_id,
            kind=kind or existing_object.kind,
            label=label,
            status=status or "active",
            summary=summary or None,
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
        return templates.TemplateResponse(
            request,
            "object_detail.html",
            context={
                "title": f"{catalog_object.label} - Blockwart",
                "object": catalog_object,
                "relationships": relationships,
                "relationship_groups": _group_relationships(
                    catalog_object,
                    relationships,
                    object_map,
                ),
                "relationship_targets": [obj for obj in all_objects if obj.id != catalog_object.id],
                "relation_types": RELATION_TYPES,
                "source_references": _source_references(object_data),
                "network": _network_summary(object_data),
                "container": _container_summary(object_data),
                "ports": _list_of_mappings(object_data.get("ports")),
                "endpoints": _list_of_mappings(object_data.get("endpoints")),
                "access_methods": _display_access_methods(
                    catalog_object,
                    _group_relationships(
                        catalog_object,
                        relationships,
                        object_map,
                    ),
                    object_map,
                ),
                "credential_references": [],
                "data_json": SAFE_DATA_JSON_FALLBACK,
                "object_kinds": OBJECT_KINDS,
                "object_statuses": OBJECT_STATUSES_UI,
                "error": _safe_error_message(exc),
                "edit_section": "overview",
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
    data["endpoints"] = [
        {
            **endpoint,
            "name": name,
            "url": url,
            "port": int(port_value) if str(port_value).strip() else "",
        }
        for endpoint, name, url, port_value in zip(
            _padded_mappings(data.get("endpoints"), len(form.getlist("endpoint_name"))),
            form.getlist("endpoint_name"),
            form.getlist("endpoint_url"),
            form.getlist("endpoint_port"),
            strict=False,
        )
        if str(name).strip() or str(url).strip() or str(port_value).strip()
    ]
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
            continue
        try:
            index = int(index_text)
        except ValueError:
            continue
        if index < 0 or index >= len(methods) or not isinstance(methods[index], dict):
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
        "status": "active",
        "summary": "",
        "data_json": SAFE_DATA_JSON_FALLBACK,
        "hosted_on_system_id": "",
        "relation_target_ref": "",
        "relation_type": "hosts",
    }


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
                "other_label": other_object.label if other_object else other_ref,
                "service_ports": _relationship_service_ports(catalog_object, other_object),
            }
        )
    return grouped


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


def _source_references(data: Mapping[str, Any]) -> list[dict[str, str]]:
    references = _list_of_mappings(data.get("source_references"))
    return [
        {
            "label": str(reference.get("label") or reference.get("uri") or "reference"),
            "uri": str(reference.get("uri") or ""),
        }
        for reference in references
    ]


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


def _split_multivalue(value: str) -> list[str]:
    return [item.strip() for item in value.replace("\n", ",").split(",") if item.strip()]


def _padded_mappings(value: Any, count: int) -> list[dict[str, Any]]:
    items = [dict(item) for item in _list_of_mappings(value)]
    while len(items) < count:
        items.append({})
    return items[:count]


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
