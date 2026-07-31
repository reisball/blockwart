import logging
import re
from http import HTTPStatus
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.exception_handlers import (
    http_exception_handler,
    request_validation_exception_handler,
)
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, PlainTextResponse
from sqlalchemy.exc import SQLAlchemyError
from starlette.exceptions import HTTPException as StarletteHTTPException

from blockwart.db.session import DatabaseTransactionError
from blockwart.schemas.errors import ApiErrorResponse

CORRELATION_ID_HEADER = "X-Correlation-ID"
API_ERROR_RESPONSES = {
    400: {"model": ApiErrorResponse, "description": "Invalid request"},
    401: {"model": ApiErrorResponse, "description": "Authentication required"},
    403: {"model": ApiErrorResponse, "description": "Permission denied"},
    500: {"model": ApiErrorResponse, "description": "Internal server error"},
    404: {"model": ApiErrorResponse, "description": "Resource not found"},
    409: {"model": ApiErrorResponse, "description": "Conflict"},
    412: {"model": ApiErrorResponse, "description": "Precondition failed"},
    422: {"model": ApiErrorResponse, "description": "Request validation failed"},
    428: {"model": ApiErrorResponse, "description": "Precondition required"},
    503: {"model": ApiErrorResponse, "description": "Service unavailable"},
}

_CORRELATION_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
logger = logging.getLogger(__name__)


def install_api_error_contract(app: FastAPI) -> None:
    @app.middleware("http")
    async def api_error_middleware(request: Request, call_next):
        if not _is_api_request(request):
            return await call_next(request)

        correlation_id = _correlation_id(request)
        try:
            response = await call_next(request)
        except SQLAlchemyError:
            _log_request_failure(
                code="db_unavailable",
                channel="api",
                correlation_id=correlation_id,
            )
            response = _error_response(
                status_code=503,
                code="db_unavailable",
                message="Database is unavailable.",
                correlation_id=correlation_id,
            )
        except Exception:
            _log_request_failure(
                code="internal_error",
                channel="api",
                correlation_id=correlation_id,
            )
            response = _error_response(
                status_code=500,
                code="internal_error",
                message="Request processing failed.",
                correlation_id=correlation_id,
            )
        return response

    @app.exception_handler(RequestValidationError)
    async def api_validation_error_handler(
        request: Request,
        exc: RequestValidationError,
    ):
        if not _is_api_request(request):
            return await request_validation_exception_handler(request, exc)
        details = [
            {
                "location": ".".join(str(part) for part in error.get("loc", ())),
                "message": "Invalid value.",
                "type": str(error.get("type", "validation_error")),
            }
            for error in exc.errors()
        ]
        return _error_response(
            status_code=422,
            code="validation_error",
            message="Request validation failed.",
            correlation_id=_correlation_id(request),
            details=details,
        )
    @app.exception_handler(StarletteHTTPException)
    async def api_http_error_handler(
        request: Request,
        exc: StarletteHTTPException,
    ):
        if not _is_api_request(request):
            return await http_exception_handler(request, exc)
        code = {
            400: "invalid_request",
            401: "unauthorized",
            403: "forbidden",
            404: "not_found",
            405: "method_not_allowed",
            409: "conflict",
            412: "precondition_failed",
            428: "precondition_required",
            503: "service_unavailable",
        }.get(exc.status_code, "http_error")
        try:
            default_message = HTTPStatus(exc.status_code).phrase
        except ValueError:
            default_message = "HTTP request failed."
        message = exc.detail if isinstance(exc.detail, str) else default_message
        return _error_response(
            status_code=exc.status_code,
            code=code,
            message=message,
            correlation_id=_correlation_id(request),
            headers=exc.headers,
        )

    @app.exception_handler(DatabaseTransactionError)
    async def database_transaction_error_handler(
        request: Request,
        _exc: DatabaseTransactionError,
    ) -> JSONResponse:
        if not _is_api_request(request):
            _log_request_failure(
                code="db_unavailable",
                channel="ui",
                correlation_id=_correlation_id(request),
            )
            return JSONResponse(
                status_code=503,
                content={"detail": "Database transaction failed"},
            )
        correlation_id = _correlation_id(request)
        _log_request_failure(code="db_unavailable", channel="api", correlation_id=correlation_id)
        return _error_response(
            status_code=503,
            code="db_unavailable",
            message="Database is unavailable.",
            correlation_id=correlation_id,
        )


def install_request_context(app: FastAPI) -> None:
    @app.middleware("http")
    async def request_context_middleware(request: Request, call_next):
        correlation_id = _correlation_id(request)
        request.state.correlation_id = correlation_id
        try:
            response = await call_next(request)
        except SQLAlchemyError:
            _log_request_failure(
                code="db_unavailable",
                channel="api" if _is_api_request(request) else "ui",
                correlation_id=correlation_id,
            )
            response = PlainTextResponse("Request processing failed.", status_code=503)
        except Exception:
            _log_request_failure(
                code="internal_error",
                channel="api" if _is_api_request(request) else "ui",
                correlation_id=correlation_id,
            )
            response = PlainTextResponse("Request processing failed.", status_code=500)
        response.headers[CORRELATION_ID_HEADER] = correlation_id
        return response


def request_correlation_id(request: Request) -> str:
    return _correlation_id(request)


def _log_request_failure(*, code: str, channel: str, correlation_id: str) -> None:
    logger.error(
        "request_failure operation=http_request code=%s channel=%s correlation_id=%s",
        code,
        channel,
        correlation_id,
    )


def _is_api_request(request: Request) -> bool:
    return request.url.path == "/api" or request.url.path.startswith("/api/")


def _correlation_id(request: Request) -> str:
    existing = getattr(request.state, "correlation_id", None)
    if isinstance(existing, str):
        return existing
    supplied = request.headers.get(CORRELATION_ID_HEADER)
    if supplied and _CORRELATION_ID_PATTERN.fullmatch(supplied):
        return supplied
    return str(uuid4())


def _error_response(
    *,
    status_code: int,
    code: str,
    message: str,
    correlation_id: str,
    details: list[dict[str, str]] | None = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    error: dict[str, object] = {
        "code": code,
        "message": message,
        "correlation_id": correlation_id,
    }
    if details:
        error["details"] = details
    return JSONResponse(
        status_code=status_code,
        content={"error": error},
        headers=headers,
    )
