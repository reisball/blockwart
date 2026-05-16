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
from blockwart.schemas.catalog import CatalogObjectIn, CatalogObjectOut
from blockwart.services.catalog import (
    get_object,
    list_relationships_for_object,
    search_objects,
    upsert_object,
)

templates = Jinja2Templates(directory="src/blockwart/ui/templates")
router = APIRouter(tags=["ui"])

OBJECT_KINDS = ("system", "service", "credential_reference", "runbook", "decision", "project")
UI_KIND_PRIORITY = {kind: index for index, kind in enumerate(OBJECT_KINDS)}
SAFE_DATA_JSON_FALLBACK = "{\n  \"schema_version\": 1\n}"


@router.get("/", response_class=HTMLResponse)
def index(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    q: str = "",
    kind: str = "",
):
    normalized_kind = kind if kind in OBJECT_KINDS else ""
    objects = _sort_for_browse(
        search_objects(session, query=q.strip() or None, kind=normalized_kind or None)
    )
    object_counts = Counter(obj.kind for obj in search_objects(session))
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
            "object_counts": object_counts,
            "total_objects": total_objects,
            "error": None,
            "form": _empty_form(),
        },
    )


@router.get("/objects/{object_id}", response_class=HTMLResponse)
def object_detail(
    request: Request,
    object_id: str,
    session: Annotated[Session, Depends(get_session)],
):
    catalog_object = get_object(session, object_id)
    if catalog_object is None:
        raise HTTPException(status_code=404, detail="Catalog object not found")
    relationships = list_relationships_for_object(session, catalog_object)
    relationship_groups = _group_relationships(catalog_object, relationships)
    object_data = catalog_object.data
    return templates.TemplateResponse(
        request,
        "object_detail.html",
        context={
            "title": f"{catalog_object.label} - Blockwart",
            "object": catalog_object,
            "relationships": relationships,
            "relationship_groups": relationship_groups,
            "source_references": _source_references(object_data),
            "network": _network_summary(object_data),
            "ports": _list_of_mappings(object_data.get("ports")),
            "endpoints": _list_of_mappings(object_data.get("endpoints")),
            "access_methods": _access_methods(object_data),
            "credential_references": _credential_references(object_data),
            "data_json": json.dumps(catalog_object.data, indent=2, sort_keys=True),
            "object_kinds": OBJECT_KINDS,
            "error": None,
        },
    )


@router.post("/objects", response_class=HTMLResponse)
def save_object(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    object_id: Annotated[str, Form()],
    kind: Annotated[str, Form()],
    label: Annotated[str, Form()],
    status: Annotated[str, Form()] = "unknown",
    summary: Annotated[str, Form()] = "",
    data_json: Annotated[str, Form()] = "{}",
):
    form = {
        "id": object_id,
        "kind": kind,
        "label": label,
        "status": status,
        "summary": summary,
        "data_json": data_json,
    }
    try:
        data = json.loads(data_json or "{}")
        _reject_secret_shaped_form_data(data)
        payload = CatalogObjectIn(
            id=object_id,
            kind=kind,
            label=label,
            status=status or "unknown",
            summary=summary or None,
            data=data,
        )
        upsert_object(session, payload)
    except (json.JSONDecodeError, ValidationError, ValueError) as exc:
        form["data_json"] = SAFE_DATA_JSON_FALLBACK
        objects = search_objects(session)
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
                "object_counts": object_counts,
                "total_objects": sum(object_counts.values()),
                "error": _safe_error_message(exc),
                "form": form,
            },
            status_code=422,
        )
    return RedirectResponse(url=f"/objects/{payload.id}", status_code=303)


@router.post("/objects/{object_id}", response_class=HTMLResponse)
def update_object(
    request: Request,
    object_id: str,
    session: Annotated[Session, Depends(get_session)],
    label: Annotated[str, Form()],
    status: Annotated[str, Form()] = "unknown",
    summary: Annotated[str, Form()] = "",
    data_json: Annotated[str, Form()] = "{}",
):
    try:
        existing_object = get_object(session, object_id)
        if existing_object is None:
            raise HTTPException(status_code=404, detail="Catalog object not found")
        data = json.loads(data_json or "{}")
        _reject_secret_shaped_form_data(data)
        payload = CatalogObjectIn(
            id=object_id,
            kind=existing_object.kind,
            label=label,
            status=status or "unknown",
            summary=summary or None,
            data=data,
        )
        upsert_object(session, payload)
    except (json.JSONDecodeError, ValidationError, ValueError) as exc:
        catalog_object = get_object(session, object_id)
        if catalog_object is None:
            raise HTTPException(status_code=404, detail="Catalog object not found") from exc
        relationships = list_relationships_for_object(session, catalog_object)
        object_data = catalog_object.data
        return templates.TemplateResponse(
            request,
            "object_detail.html",
            context={
                "title": f"{catalog_object.label} - Blockwart",
                "object": catalog_object,
                "relationships": relationships,
                "relationship_groups": _group_relationships(catalog_object, relationships),
                "source_references": _source_references(object_data),
                "network": _network_summary(object_data),
                "ports": _list_of_mappings(object_data.get("ports")),
                "endpoints": _list_of_mappings(object_data.get("endpoints")),
                "access_methods": _access_methods(object_data),
                "credential_references": _credential_references(object_data),
                "data_json": SAFE_DATA_JSON_FALLBACK,
                "object_kinds": OBJECT_KINDS,
                "error": _safe_error_message(exc),
            },
            status_code=422,
        )
    return RedirectResponse(url=f"/objects/{payload.id}", status_code=303)


def _empty_form() -> dict[str, str]:
    return {
        "id": "",
        "kind": "system",
        "label": "",
        "status": "active",
        "summary": "",
        "data_json": SAFE_DATA_JSON_FALLBACK,
    }


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


def _group_relationships(
    catalog_object: CatalogObjectOut,
    relationships: list[dict[str, str]],
) -> dict[str, list[dict[str, str]]]:
    current_ref = f"{catalog_object.kind}:{catalog_object.id}"
    grouped: dict[str, list[dict[str, str]]] = {}
    for relationship in relationships:
        direction = "outbound" if relationship["from_ref"] == current_ref else "inbound"
        grouped.setdefault(direction, []).append(
            {
                **relationship,
                "other_ref": (
                    relationship["to_ref"]
                    if direction == "outbound"
                    else relationship["from_ref"]
                ),
                "other_id": _object_id_from_ref(
                    relationship["to_ref"]
                    if direction == "outbound"
                    else relationship["from_ref"]
                ),
            }
        )
    return grouped


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


def _access_methods(data: Mapping[str, Any]) -> list[dict[str, Any]]:
    methods = _list_of_mappings(data.get("access_methods"))
    return [
        {
            "type": str(method.get("type") or "access"),
            "endpoint": str(method.get("endpoint") or ""),
            "auth_mode": str(method.get("auth_mode") or "unknown"),
            "credential_references": [
                ref for ref in method.get("credential_references", []) if _is_credential_ref(ref)
            ]
            if isinstance(method.get("credential_references"), list)
            else [],
        }
        for method in methods
    ]


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
