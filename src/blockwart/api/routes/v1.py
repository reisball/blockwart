import json
from collections.abc import Mapping
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.models import CatalogObject, Relationship
from blockwart.schemas.catalog import (
    PUBLIC_OBJECT_KINDS,
    CatalogObjectIn,
    CatalogObjectOut,
    ObjectKind,
    ObjectStatus,
)
from blockwart.services.agent import REDACTED
from blockwart.services.catalog import (
    get_object,
    list_objects,
    upsert_object,
)

router = APIRouter(prefix="/v1", tags=["api-v1"])


class CatalogObjectPatch(BaseModel):
    label: str | None = None
    status: ObjectStatus | None = None
    summary: str | None = None
    data: dict[str, Any] | None = None


class CommentsIn(BaseModel):
    comment: str
    actor: str = "api"


class EndpointsIn(BaseModel):
    endpoints: list[dict[str, Any]] = Field(default_factory=list)


class AccessMethodsIn(BaseModel):
    access_methods: list[dict[str, Any]] = Field(default_factory=list)


class InterfacesIn(BaseModel):
    interfaces: list[dict[str, Any]] = Field(default_factory=list)


class RelationshipIn(BaseModel):
    host_ref: str | None = None
    system_ref: str | None = None


@router.get("/objects", response_model=list[CatalogObjectOut])
def list_v1_objects(
    session: Annotated[Session, Depends(get_session)],
    q: Annotated[str | None, Query(description="Search term")] = None,
    kind: ObjectKind | None = None,
    status: ObjectStatus | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
) -> list[CatalogObjectOut]:
    objects = list_objects(session)
    if kind:
        objects = [obj for obj in objects if obj.kind == kind]
    if q:
        term = q.casefold()
        objects = [
            obj
            for obj in objects
            if term in obj.id.casefold()
            or term in obj.label.casefold()
            or term in (obj.summary or "").casefold()
        ]
    if status:
        objects = [obj for obj in objects if obj.status == status]
    return [_api_object(obj) for obj in objects[:limit]]


@router.post("/objects", response_model=CatalogObjectOut, status_code=status.HTTP_201_CREATED)
def create_v1_object(
    payload: CatalogObjectIn,
    session: Annotated[Session, Depends(get_session)],
) -> CatalogObjectOut:
    _reject_public_ports(payload)
    if session.get(CatalogObject, payload.id) is not None:
        raise HTTPException(status_code=409, detail="Catalog object already exists")
    return _api_object(upsert_object(session, payload))


@router.get("/objects/{object_id}", response_model=CatalogObjectOut)
def get_v1_object(
    object_id: str,
    session: Annotated[Session, Depends(get_session)],
) -> CatalogObjectOut:
    return _api_object(_get_object_or_404(session, object_id))


@router.patch("/objects/{object_id}", response_model=CatalogObjectOut)
def patch_v1_object(
    object_id: str,
    payload: CatalogObjectPatch,
    session: Annotated[Session, Depends(get_session)],
) -> CatalogObjectOut:
    current = _get_object_or_404(session, object_id)
    data = payload.data if payload.data is not None else dict(current.data)
    if payload.data is not None:
        _reject_inherited_service_fields(current.kind, data)
    if current.kind in PUBLIC_OBJECT_KINDS and payload.data is None:
        data.pop("ports", None)
    updated = _catalog_input(
        current,
        label=payload.label if payload.label is not None else current.label,
        status=payload.status if payload.status is not None else current.status,
        summary=payload.summary if payload.summary is not None else current.summary,
        data=data,
    )
    if payload.data is not None:
        _reject_public_ports(updated)
    return _api_object(upsert_object(session, updated))


@router.get("/objects/{object_id}/comments")
def get_v1_comments(
    object_id: str,
    session: Annotated[Session, Depends(get_session)],
) -> list[dict[str, str | None]]:
    current = _get_object_or_404(session, object_id)
    return _comments_from_data(current.data)


@router.post(
    "/objects/{object_id}/comments",
    response_model=CatalogObjectOut,
    status_code=status.HTTP_201_CREATED,
)
def post_v1_comment(
    object_id: str,
    payload: CommentsIn,
    session: Annotated[Session, Depends(get_session)],
) -> CatalogObjectOut:
    comment = payload.comment.strip()
    if not comment:
        raise HTTPException(status_code=422, detail="comment must not be empty")
    current = _get_object_or_404(session, object_id)
    data = dict(current.data)
    comments = _comments_from_data(data)
    comments = [
        item
        for item in comments
        if not (item["actor"] == "legacy" and item["created_at"] is None)
    ]
    comments.append({"text": comment, "actor": payload.actor.strip() or "api", "created_at": None})
    data["comments"] = comments
    return _api_object(_replace_data(session, current, data))


@router.put("/objects/{object_id}/endpoints", response_model=CatalogObjectOut)
def put_v1_endpoints(
    object_id: str,
    payload: EndpointsIn,
    session: Annotated[Session, Depends(get_session)],
) -> CatalogObjectOut:
    current = _get_object_or_404(session, object_id)
    if current.kind not in PUBLIC_OBJECT_KINDS:
        raise HTTPException(
            status_code=422,
            detail="endpoints are only supported on public objects",
        )
    data = dict(current.data)
    data["endpoints"] = payload.endpoints
    return _api_object(_replace_data(session, current, data))


@router.put("/objects/{object_id}/ports")
def put_v1_ports(object_id: str, session: Annotated[Session, Depends(get_session)]) -> None:
    _get_object_or_404(session, object_id)
    raise HTTPException(
        status_code=422,
        detail="Standalone ports are no longer writable; use /api/v1/objects/{id}/endpoints",
    )


@router.put("/objects/{object_id}/access-methods", response_model=CatalogObjectOut)
def put_v1_access_methods(
    object_id: str,
    payload: AccessMethodsIn,
    session: Annotated[Session, Depends(get_session)],
) -> CatalogObjectOut:
    current = _get_object_or_404(session, object_id)
    data = dict(current.data)
    data["access_methods"] = payload.access_methods
    return _api_object(_replace_data(session, current, data))


@router.put("/objects/{object_id}/interfaces", response_model=CatalogObjectOut)
def put_v1_interfaces(
    object_id: str,
    payload: InterfacesIn,
    session: Annotated[Session, Depends(get_session)],
) -> CatalogObjectOut:
    current = _get_object_or_404(session, object_id)
    if current.kind == "service":
        raise HTTPException(status_code=422, detail="services inherit interfaces from systems")
    data = dict(current.data)
    network = dict(data.get("network") or {})
    network["addresses"] = payload.interfaces
    data["network"] = network
    return _api_object(_replace_data(session, current, data))


@router.put("/objects/{object_id}/relationships", response_model=CatalogObjectOut)
def put_v1_relationships(
    object_id: str,
    payload: RelationshipIn,
    session: Annotated[Session, Depends(get_session)],
) -> CatalogObjectOut:
    current = _get_object_or_404(session, object_id)
    data = dict(current.data)
    if current.kind == "system":
        ref = payload.host_ref
        if not ref or not ref.startswith(("host:", "system:")):
            raise HTTPException(status_code=422, detail="system relationships require host_ref")
        _ensure_reference_exists(session, ref)
        data["host_ref"] = ref
    elif current.kind == "service":
        ref = payload.system_ref
        if not ref or not ref.startswith("system:"):
            raise HTTPException(status_code=422, detail="service relationships require system_ref")
        _ensure_reference_exists(session, ref)
        data["system_id"] = ref
    else:
        raise HTTPException(
            status_code=422,
            detail="relationships are only writable for systems/services",
        )
    return _api_object(_replace_data(session, current, data))


@router.get("/objects/{object_id}/agent-view")
def get_v1_agent_view(
    object_id: str,
    session: Annotated[Session, Depends(get_session)],
) -> dict[str, Any]:
    current = _get_object_or_404(session, object_id)
    typed = _parse_typed_object_id(object_id)
    if typed and typed[0] != current.kind:
        raise HTTPException(status_code=404, detail="Catalog object not found")
    return _agent_view(session, current)


def _get_object_or_404(session: Session, object_id: str) -> CatalogObjectOut:
    parsed = _parse_typed_object_id(object_id)
    raw_id = parsed[1] if parsed else object_id
    catalog_object = get_object(session, raw_id)
    if catalog_object is None:
        raise HTTPException(status_code=404, detail="Catalog object not found")
    if parsed and parsed[0] != catalog_object.kind:
        raise HTTPException(status_code=404, detail="Catalog object not found")
    return catalog_object


def _replace_data(
    session: Session,
    current: CatalogObjectOut,
    data: dict[str, Any],
) -> CatalogObjectOut:
    if current.kind in PUBLIC_OBJECT_KINDS:
        data.pop("ports", None)
    updated = _catalog_input(current, data=data)
    return upsert_object(session, updated)


def _catalog_input(
    current: CatalogObjectOut,
    *,
    label: str | None = None,
    status: ObjectStatus | None = None,
    summary: str | None = None,
    data: dict[str, Any],
) -> CatalogObjectIn:
    try:
        return CatalogObjectIn(
            id=current.id,
            kind=current.kind,
            label=label if label is not None else current.label,
            status=status if status is not None else current.status,
            summary=summary if summary is not None else current.summary,
            data=data,
        )
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


def _reject_public_ports(payload: CatalogObjectIn) -> None:
    if payload.kind in PUBLIC_OBJECT_KINDS and "ports" in payload.data:
        raise HTTPException(
            status_code=422,
            detail="data.ports is not supported for public objects; use data.endpoints",
        )


def _reject_inherited_service_fields(kind: str, data: Mapping[str, Any]) -> None:
    if kind != "service":
        return
    inherited_fields = {"hostname", "interfaces", "network", "ports"}
    present = sorted(inherited_fields & set(data))
    if present:
        raise HTTPException(
            status_code=422,
            detail=f"service data may not own inherited fields: {', '.join(present)}",
        )


def _api_object(obj: CatalogObjectOut) -> CatalogObjectOut:
    if obj.kind not in PUBLIC_OBJECT_KINDS or "ports" not in obj.data:
        return obj
    data = dict(obj.data)
    data.pop("ports", None)
    return CatalogObjectOut(
        id=obj.id,
        kind=obj.kind,
        label=obj.label,
        status=obj.status,
        summary=obj.summary,
        data=data,
        created_at=obj.created_at,
        updated_at=obj.updated_at,
        last_changed=obj.last_changed,
    )


def _comments_from_data(data: Mapping[str, Any]) -> list[dict[str, str | None]]:
    comments: list[dict[str, str | None]] = []
    legacy = data.get("comment")
    if isinstance(legacy, str) and legacy.strip():
        comments.append({"text": legacy, "actor": "legacy", "created_at": None})
    for item in data.get("comments") or []:
        if isinstance(item, Mapping) and isinstance(item.get("text"), str):
            comments.append(
                {
                    "text": item["text"],
                    "actor": str(item.get("actor") or "api"),
                    "created_at": item.get("created_at")
                    if isinstance(item.get("created_at"), str)
                    else None,
                }
            )
    return comments


def _parse_typed_object_id(value: str) -> tuple[str, str] | None:
    if ":" not in value:
        return None
    kind, raw_id = value.split(":", 1)
    return kind, raw_id


def _ensure_reference_exists(session: Session, ref: str) -> None:
    parsed = _parse_typed_object_id(ref)
    if parsed is None:
        raise HTTPException(status_code=422, detail="reference must use kind:id")
    if session.get(CatalogObject, parsed[1]) is None:
        raise HTTPException(status_code=404, detail="Referenced object not found")


def _agent_view(session: Session, current: CatalogObjectOut) -> dict[str, Any]:
    system = _resolve_system(session, current)
    host = _resolve_host(session, current, system)
    data = _sanitize(json.loads(json.dumps(current.data)))
    endpoints = _list_mappings(data.get("endpoints"))
    network = data.get("network") if isinstance(data.get("network"), Mapping) else {}
    resolved: dict[str, Any] = {}
    if system is not None and current.kind == "service":
        system_data = _sanitize(json.loads(json.dumps(system.data)))
        system_network = system_data.get("network")
        if isinstance(system_network, Mapping):
            hostnames = system_network.get("hostnames")
            if isinstance(hostnames, list) and hostnames:
                resolved["hostname"] = hostnames[0]
            resolved["network"] = system_network
        if system_data.get("platform"):
            resolved["platform"] = system_data["platform"]
    return {
        "identity": _summary(current),
        "hierarchy": {
            "host": _summary(host) if host else None,
            "system": _summary(system) if system else None,
            "service": _summary(current) if current.kind == "service" else None,
        },
        "data": data,
        "resolved": resolved,
        "network": {
            "addresses": list(network.get("addresses") or [])
            if isinstance(network, Mapping)
            else [],
            "endpoints": endpoints,
        },
        "endpoints": endpoints,
        "access_methods": _list_mappings(data.get("access_methods")),
        "credential_references": sorted(_collect_credential_references(data)),
        "relationships": _relationships(session, current),
        "links": _links(current, system, host),
    }


def _resolve_system(
    session: Session,
    current: CatalogObjectOut,
) -> CatalogObjectOut | None:
    if current.kind == "system":
        return current
    if current.kind != "service":
        return None
    ref = current.data.get("system_id") or current.data.get("system_ref")
    if isinstance(ref, str) and ref.startswith("system:"):
        return get_object(session, ref.split(":", 1)[1])
    relationship = session.scalar(
        select(Relationship).where(
            Relationship.relation_type == "provides",
            Relationship.to_ref == f"service:{current.id}",
        )
    )
    if relationship is None:
        return None
    return get_object(session, relationship.from_ref.split(":", 1)[1])


def _resolve_host(
    session: Session,
    current: CatalogObjectOut,
    system: CatalogObjectOut | None,
) -> CatalogObjectOut | None:
    if current.kind == "host":
        return current
    if system is None:
        return None
    ref = system.data.get("host_ref")
    if isinstance(ref, str) and ref.startswith("host:"):
        return get_object(session, ref.split(":", 1)[1])
    relationship = session.scalar(
        select(Relationship).where(
            Relationship.relation_type == "hosts",
            Relationship.to_ref == f"system:{system.id}",
        )
    )
    if relationship is None:
        return None
    return get_object(session, relationship.from_ref.split(":", 1)[1])


def _summary(obj: CatalogObjectOut | None) -> dict[str, Any] | None:
    if obj is None:
        return None
    return {
        "ref": f"{obj.kind}:{obj.id}",
        "id": obj.id,
        "kind": obj.kind,
        "label": obj.label,
        "status": obj.status,
        "summary": obj.summary,
    }


def _relationships(session: Session, current: CatalogObjectOut) -> list[dict[str, str]]:
    ref = f"{current.kind}:{current.id}"
    rows = session.scalars(
        select(Relationship)
        .where((Relationship.from_ref == ref) | (Relationship.to_ref == ref))
        .order_by(Relationship.relation_type, Relationship.from_ref, Relationship.to_ref)
    ).all()
    return [
        {"from_ref": row.from_ref, "relation_type": row.relation_type, "to_ref": row.to_ref}
        for row in rows
    ]


def _links(
    current: CatalogObjectOut,
    system: CatalogObjectOut | None,
    host: CatalogObjectOut | None,
) -> dict[str, str]:
    links = {
        "self": f"/api/v1/objects/{current.id}",
        "agent_view": f"/api/v1/objects/{current.id}/agent-view",
        "endpoints": f"/api/v1/objects/{current.id}/endpoints",
    }
    if system is not None and system.id != current.id:
        links["system"] = f"/api/v1/objects/{system.id}/agent-view"
    if host is not None and host.id != current.id:
        links["host"] = f"/api/v1/objects/{host.id}/agent-view"
    return links


def _list_mappings(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [dict(item) for item in value if isinstance(item, Mapping)]


def _sanitize(value: Any) -> Any:
    if isinstance(value, Mapping):
        safe = {}
        for key, child in value.items():
            key_text = str(key)
            if key_text.lower() in {"password", "token", "secret", "api_key", "apikey"}:
                safe[key_text] = REDACTED
            else:
                safe[key_text] = _sanitize(child)
        return safe
    if isinstance(value, list):
        return [_sanitize(item) for item in value]
    return value


def _collect_credential_references(value: Any) -> set[str]:
    refs: set[str] = set()
    if isinstance(value, Mapping):
        for child in value.values():
            if isinstance(child, str) and child.startswith("credential_reference:"):
                refs.add(child)
            refs.update(_collect_credential_references(child))
    elif isinstance(value, list):
        for child in value:
            if isinstance(child, str) and child.startswith("credential_reference:"):
                refs.add(child)
            refs.update(_collect_credential_references(child))
    return refs
