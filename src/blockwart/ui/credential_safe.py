"""Server-rendered explicit safe actions. No secret fetching on GET."""
import html
import json
from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import ValidationError
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.services.credential_safe import SafeAction, operate
from blockwart.ui.security import (
    read_access_from_request,
    require_browser_read_access,
    require_browser_write_csrf,
)
from blockwart.ui.write_commands import execute_ui_command, ui_write_context

router = APIRouter(dependencies=[Depends(require_browser_read_access)], include_in_schema=False)


@router.post("/objects/{object_id}/safe", response_class=HTMLResponse,
             dependencies=[Depends(require_browser_write_csrf)])
def safe_action(request: Request, object_id: str,
                session: Annotated[Session, Depends(get_session)],
                action: Annotated[str, Form()],
                fields_json: Annotated[str, Form()] = "",
                preset: Annotated[str, Form()] = "other",
                version: Annotated[str, Form()] = "",
                cas: Annotated[str, Form()] = ""):
    context = ui_write_context(request, read_access_from_request(request))
    try:
        payload = SafeAction(action=action, preset=preset,
                             fields=json.loads(fields_json) if fields_json else None,
                             version=int(version) if version else None,
                             cas=int(cas) if cas else None)
    except (ValueError, ValidationError):
        raise HTTPException(422, "Invalid safe action") from None
    result = execute_ui_command(session, context, lambda: operate(
        session, context, request.app.state.settings, object_id, payload,
    ))
    # Escaped values only in this explicit response; never echo submitted fields on error.
    return HTMLResponse("<!doctype html><meta charset=utf-8><title>Credential safe</title>"
                        "<pre>" + html.escape(json.dumps(result, ensure_ascii=False, indent=2))
                        + "</pre><a href='/objects/" + html.escape(object_id, quote=True)
                        + "'>Back</a>")
