"""Explicit POST-only secret transport; normal catalog endpoints never reveal values."""
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.api.errors import API_ERROR_RESPONSES
from blockwart.api.security import require_api_read_access
from blockwart.api.write_commands import api_write_context, execute_api_command
from blockwart.services.credential_safe import SafeAction, operate
from blockwart.services.read_access import ReadAccess

router = APIRouter(responses=API_ERROR_RESPONSES)


@router.post("/v1/objects/{object_id}/safe")
def safe_action(request: Request, object_id: str, payload: SafeAction,
                session: Annotated[Session, Depends(get_session)],
                access: Annotated[ReadAccess, Depends(require_api_read_access)]) -> dict:
    context = api_write_context(request, access)
    return execute_api_command(session, context, lambda: operate(
        session, context, request.app.state.settings, object_id, payload,
    ), owns_transactions=True)
