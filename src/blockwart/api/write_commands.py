from __future__ import annotations

from collections.abc import Callable

from fastapi import HTTPException, Request
from sqlalchemy.orm import Session

from blockwart.db.session import transaction
from blockwart.domain.decisions import DecisionIntegrityError
from blockwart.domain.placement import PlacementError
from blockwart.domain.relationships import RelationshipIntegrityError
from blockwart.services.commands import (
    CommandAuthorizationDenied,
    CommandConflict,
    CommandNotFound,
    CommandPreconditionFailed,
    CommandPreconditionRequired,
    IdempotencyConflict,
    WriteContext,
    record_command_denial,
)
from blockwart.services.read_access import ReadAccess


def api_write_context(request: Request, access: ReadAccess) -> WriteContext:
    channel = (
        "mcp"
        if request.headers.get("X-Blockwart-Channel", "").casefold() == "mcp"
        else "api"
    )
    return WriteContext.from_read_access(
        access,
        channel=channel,
        request_id=getattr(request.state, "correlation_id", None),
    )


def execute_api_command[T](
    session: Session,
    context: WriteContext,
    command: Callable[[], T],
) -> T:
    try:
        with transaction(session):
            return command()
    except CommandAuthorizationDenied as exc:
        with transaction(session):
            record_command_denial(session, context, exc)
        raise HTTPException(status_code=403, detail="Object permission denied") from exc
    except CommandNotFound as exc:
        raise HTTPException(status_code=404, detail="Resource not found") from exc
    except CommandPreconditionRequired as exc:
        raise HTTPException(status_code=428, detail=str(exc)) from exc
    except CommandPreconditionFailed as exc:
        raise HTTPException(status_code=412, detail=str(exc)) from exc
    except IdempotencyConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except (
        CommandConflict,
        DecisionIntegrityError,
        PlacementError,
        RelationshipIntegrityError,
    ) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
