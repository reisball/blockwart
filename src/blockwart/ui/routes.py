import json
from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.domain.security import find_secret_violations
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services.catalog import (
    get_object,
    list_relationships_for_object,
    search_objects,
    upsert_object,
)

templates = Jinja2Templates(directory="src/blockwart/ui/templates")
router = APIRouter(tags=["ui"])

OBJECT_KINDS = ("system", "service", "credential_reference", "runbook", "decision", "project")
SAFE_DATA_JSON_FALLBACK = "{\n  \"schema_version\": 1\n}"


@router.get("/", response_class=HTMLResponse)
def index(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    q: str = "",
    kind: str = "",
):
    normalized_kind = kind if kind in OBJECT_KINDS else ""
    objects = search_objects(session, query=q.strip() or None, kind=normalized_kind or None)
    return templates.TemplateResponse(
        request,
        "index.html",
        context={
            "title": "Blockwart",
            "objects": objects,
            "q": q,
            "kind": normalized_kind,
            "object_kinds": OBJECT_KINDS,
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
    return templates.TemplateResponse(
        request,
        "object_detail.html",
        context={
            "title": f"{catalog_object.label} - Blockwart",
            "object": catalog_object,
            "relationships": relationships,
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
        return templates.TemplateResponse(
            request,
            "index.html",
            context={
                "title": "Blockwart",
                "objects": objects,
                "q": "",
                "kind": "",
                "object_kinds": OBJECT_KINDS,
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
        return templates.TemplateResponse(
            request,
            "object_detail.html",
            context={
                "title": f"{catalog_object.label} - Blockwart",
                "object": catalog_object,
                "relationships": relationships,
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
