from __future__ import annotations

from collections.abc import Callable

from fastapi import HTTPException, Request
from sqlalchemy.orm import Session

from blockwart.db.session import read_only_transaction, transaction
from blockwart.domain.decisions import DecisionIntegrityError
from blockwart.domain.placement import PlacementError
from blockwart.domain.relationships import RelationshipIntegrityError
from blockwart.domain.runbooks import RunbookIntegrityError
from blockwart.services.commands import (
    CommandAuthorizationDenied,
    CommandConflict,
    CommandError,
    CommandNotFound,
    CommandPreconditionFailed,
    CommandPreconditionRequired,
    WriteContext,
    record_command_denial,
)
from blockwart.services.read_access import ReadAccess

# The command errors and the domain integrity errors a write may surface all
# map onto the same safe REST envelope, so both executors share one mapping.
_MAPPED_COMMAND_ERRORS = (
    CommandError,
    DecisionIntegrityError,
    PlacementError,
    RelationshipIntegrityError,
    RunbookIntegrityError,
)


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
    except _MAPPED_COMMAND_ERRORS as exc:
        raise _command_http_error(session, context, exc, record_denial=True) from exc


def execute_api_read_only_command[T](
    session: Session,
    context: WriteContext,
    command: Callable[[], T],
) -> T:
    """Run one authorized but read-only object command with the write contract.

    The command itself is never committed, so it can create no object,
    revision, timestamp, audit, security, comment, grant, idempotency,
    relationship, or sequence state.
    """
    try:
        with read_only_transaction(session):
            return command()
    except _MAPPED_COMMAND_ERRORS as exc:
        raise _command_http_error(session, context, exc, record_denial=False) from exc


def _command_http_error(
    session: Session,
    context: WriteContext,
    exc: Exception,
    *,
    record_denial: bool,
) -> HTTPException:
    """Map one command error onto the shared safe REST envelope."""
    if isinstance(exc, CommandAuthorizationDenied):
        if record_denial:
            with transaction(session):
                record_command_denial(session, context, exc)
        return HTTPException(status_code=403, detail="Object permission denied")
    if isinstance(exc, CommandNotFound):
        return HTTPException(status_code=404, detail="Resource not found")
    if isinstance(exc, CommandPreconditionRequired):
        return HTTPException(status_code=428, detail=str(exc))
    if isinstance(exc, CommandPreconditionFailed):
        return HTTPException(status_code=412, detail=str(exc))
    if isinstance(
        exc,
        CommandConflict
        | DecisionIntegrityError
        | PlacementError
        | RelationshipIntegrityError
        | RunbookIntegrityError,
    ):
        return HTTPException(status_code=409, detail=str(exc))
    raise exc
