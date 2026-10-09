"""UI surface for the shared access-request workflow (Issue #100).

The UI uses the exact same service commands as the REST API and MCP: same
policy checks, same idempotency, same audit events. Nothing here can approve
or decide anything the current policy does not authorize.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import (
    APIRouter,
    Depends,
    Form,
    HTTPException,
    Request,
)
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.domain.access_requests import AccessRequestDuration
from blockwart.services.access_request_notices import notice_routing_from_settings
from blockwart.services.access_requests import (
    cancel_access_request as cancel_access_request_command,
)
from blockwart.services.access_requests import (
    create_access_request as create_access_request_command,
)
from blockwart.services.access_requests import (
    decide_access_request as decide_access_request_command,
)
from blockwart.services.access_requests import (
    list_my_access_requests,
    list_pending_access_requests,
)
from blockwart.services.commands import CommandError
from blockwart.ui.i18n import translation_context
from blockwart.ui.paths import TEMPLATE_DIR
from blockwart.ui.security import (
    AUTH_CSRF_COOKIE_NAME,
    read_access_from_request,
    require_browser_read_access,
    require_browser_write_csrf,
)
from blockwart.ui.write_commands import (
    execute_ui_command,
    execute_ui_read_only_command,
    ui_write_context,
)

templates = Jinja2Templates(directory=TEMPLATE_DIR)
# Every route authenticates the browser session first: the page and the three
# writes all act as the signed-in principal, never as an anonymous caller.
router = APIRouter(
    tags=["ui"],
    include_in_schema=False,
    dependencies=[Depends(require_browser_read_access)],
)


_ERROR_CODES = {403: "denied", 404: "not_found", 409: "conflict", 422: "invalid"}
_NOTICE_CODES = frozenset({"created", "exists", "cancelled", "approved", "denied"})
_ERROR_KEYS = frozenset({"denied", "not_found", "conflict", "invalid", "failed"})


def _error_redirect(exc: Exception) -> RedirectResponse:
    # Only a stable code travels in the URL; the page renders the localized
    # text, so a crafted link can never inject a message into the page.
    status_code = getattr(exc, "status_code", None)
    code = _ERROR_CODES.get(status_code, "failed") if isinstance(status_code, int) else "failed"
    return RedirectResponse(url=f"/access-requests?error={code}", status_code=303)


def _page_context(request: Request, session: Session) -> dict[str, Any]:
    access = read_access_from_request(request)
    context = ui_write_context(request, access)
    # The page is a GET: it reads the effective state and never writes.
    pending = execute_ui_read_only_command(
        session,
        context,
        lambda: list_pending_access_requests(session, context),
    )
    mine = execute_ui_read_only_command(
        session,
        context,
        lambda: list_my_access_requests(session, context),
    )
    translated = translation_context(request)
    return {
        "title": translated["t"]("access_requests.title"),
        "pending_requests": pending,
        "my_requests": mine,
        "durations": ("temporary", "permanent"),
        "csrf_token": request.cookies.get(AUTH_CSRF_COOKIE_NAME, ""),
        **translated,
    }


@router.get("/access-requests", response_class=HTMLResponse)
def access_requests_page(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    error: str | None = None,
    notice: str | None = None,
):
    context = _page_context(request, session)
    translate = context["t"]
    if error in _ERROR_KEYS:
        context["form_error"] = translate(f"access_requests.error.{error}")
    if notice in _NOTICE_CODES:
        context["notice"] = translate(f"access_requests.notice.{notice}")
    return templates.TemplateResponse(request, "access_requests.html", context=context)


@router.post(
    "/access-requests",
    response_class=RedirectResponse,
    dependencies=[Depends(require_browser_write_csrf)],
)
def create_access_request_from_ui(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    object_id: Annotated[str, Form(max_length=128)],
    duration: Annotated[str, Form(max_length=16)],
    ttl_seconds: Annotated[str | None, Form(max_length=10)] = None,
    reason: Annotated[str | None, Form(max_length=500)] = None,
):
    access = read_access_from_request(request)
    context = ui_write_context(request, access)
    try:
        resolved_duration = AccessRequestDuration(duration)
    except ValueError:
        return _error_redirect(HTTPException(422, "Unsupported duration."))
    parsed_ttl: int | None = None
    if duration == AccessRequestDuration.TEMPORARY:
        try:
            parsed_ttl = int(ttl_seconds) if ttl_seconds else None
        except ValueError:
            return _error_redirect(
                HTTPException(422, "ttl_seconds must be an integer number of seconds.")
            )
    try:
        result = execute_ui_command(
            session,
            context,
            lambda: create_access_request_command(
                session,
                context,
                object_id=object_id.strip(),
                duration=resolved_duration,
                ttl_seconds=parsed_ttl,
                reason=reason,
                routing=notice_routing_from_settings(request.app.state.settings),
            ),
        )
    except HTTPException as exc:
        return _error_redirect(exc)
    except CommandError as exc:
        return _error_redirect(exc)
    notice = "created" if result.changed else "exists"
    return RedirectResponse(url=f"/access-requests?notice={notice}", status_code=303)


@router.post(
    "/access-requests/{request_id}/cancellation",
    response_class=RedirectResponse,
    dependencies=[Depends(require_browser_write_csrf)],
)
def cancel_access_request_from_ui(
    request: Request,
    request_id: str,
    session: Annotated[Session, Depends(get_session)],
):
    access = read_access_from_request(request)
    context = ui_write_context(request, access)
    try:
        execute_ui_command(
            session,
            context,
            lambda: cancel_access_request_command(
                session,
                context,
                request_id=request_id,
            ),
        )
    except HTTPException as exc:
        return _error_redirect(exc)
    except CommandError as exc:
        return _error_redirect(exc)
    return RedirectResponse(url="/access-requests?notice=cancelled", status_code=303)


@router.post(
    "/access-requests/{request_id}/decision",
    response_class=RedirectResponse,
    dependencies=[Depends(require_browser_write_csrf)],
)
def decide_access_request_from_ui(
    request: Request,
    request_id: str,
    session: Annotated[Session, Depends(get_session)],
    decision: Annotated[str, Form(max_length=8)],
    ttl_seconds: Annotated[str | None, Form(max_length=10)] = None,
):
    if decision not in {"approve", "deny"}:
        return _error_redirect(HTTPException(422, "Unsupported decision."))
    try:
        parsed_ttl = int(ttl_seconds) if ttl_seconds else None
    except ValueError:
        return _error_redirect(
            HTTPException(422, "ttl_seconds must be an integer number of seconds.")
        )
    access = read_access_from_request(request)
    context = ui_write_context(request, access)
    try:
        execute_ui_command(
            session,
            context,
            lambda: decide_access_request_command(
                session,
                context,
                request_id=request_id,
                approve=decision == "approve",
                approved_ttl_seconds=parsed_ttl,
            ),
        )
    except HTTPException as exc:
        return _error_redirect(exc)
    except CommandError as exc:
        return _error_redirect(exc)
    outcome = "approved" if decision == "approve" else "denied"
    return RedirectResponse(url=f"/access-requests?notice={outcome}", status_code=303)
