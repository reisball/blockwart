from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from blockwart.ui.admin_auth import (
    ADMIN_COOKIE_NAME,
    admin_is_configured,
    admin_token_matches,
    can_write,
    create_admin_session,
    settings_for_request,
)

templates = Jinja2Templates(directory=Path(__file__).resolve().parent / "templates")
router = APIRouter(prefix="/admin", tags=["ui"], include_in_schema=False)


@router.get("", response_class=HTMLResponse)
def admin_page(request: Request) -> HTMLResponse:
    return _admin_response(request)


@router.post("/unlock", response_class=HTMLResponse)
def unlock_admin(
    request: Request,
    admin_token: Annotated[str, Form()],
):
    settings = settings_for_request(request)
    if not admin_token_matches(settings, admin_token):
        return _admin_response(request, error="Admin-Freigabe fehlgeschlagen.", status_code=403)
    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(
        key=ADMIN_COOKIE_NAME,
        value=create_admin_session(settings),
        max_age=settings.admin_session_ttl_seconds,
        httponly=True,
        secure=settings.admin_cookie_secure,
        samesite="strict",
        path="/",
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@router.post("/lock")
def lock_admin(request: Request) -> RedirectResponse:
    settings = settings_for_request(request)
    response = RedirectResponse(url="/", status_code=303)
    response.delete_cookie(
        key=ADMIN_COOKIE_NAME,
        path="/",
        httponly=True,
        secure=settings.admin_cookie_secure,
        samesite="strict",
    )
    response.headers["Cache-Control"] = "no-store"
    return response


def _admin_response(
    request: Request,
    *,
    error: str | None = None,
    status_code: int = 200,
) -> HTMLResponse:
    response = templates.TemplateResponse(
        request,
        "admin.html",
        context={
            "title": "Admin-Freigabe - Blockwart",
            "admin_configured": admin_is_configured(request),
            "can_write": can_write(request),
            "error": error,
        },
        status_code=status_code,
    )
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response
