from __future__ import annotations

from collections.abc import Callable

from fastapi import HTTPException, Request
from sqlalchemy.orm import Session

from blockwart.api.errors import request_correlation_id
from blockwart.db.session import transaction
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


def ui_write_context(request: Request, access: ReadAccess) -> WriteContext:
    return WriteContext.from_read_access(
        access,
        channel="ui",
        request_id=request_correlation_id(request),
    )


def execute_ui_command[T](
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
    except (IdempotencyConflict, CommandConflict) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except (PlacementError, RelationshipIntegrityError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
