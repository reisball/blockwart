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
from blockwart.domain.search import (
    AGENT_SEARCH_LIMIT_MAX,
    CONTEXT_LIMIT_MAX,
    SEARCH_LIMIT_MAX,
    SEARCH_LIMIT_MIN,
)
from blockwart.domain.validation_errors import (
    detail_from_validation_error,
    order_public_details,
    search_limit_detail,
    violation_for_validation_type,
)
from blockwart.schemas.errors import ApiErrorResponse
from blockwart.schemas.v1 import MAX_BATCH_REQUEST_BODY_BYTES

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
_BATCH_OBJECT_CONTEXTS_PATH = "/api/v1/object-contexts"
# The closed set of search resources whose rejected page size publishes the
# narrowly scoped field-accurate detail, with the exact range each route
# declares. No other parameter and no other resource is enriched, so the global
# validation contract keeps publishing exactly the canonical detail fields.
_SEARCH_LIMIT_RANGES: dict[str, tuple[int, int]] = {
    "/api/v1/objects": (SEARCH_LIMIT_MIN, SEARCH_LIMIT_MAX),
    "/api/v1/context": (SEARCH_LIMIT_MIN, CONTEXT_LIMIT_MAX),
    "/api/agent/search": (SEARCH_LIMIT_MIN, AGENT_SEARCH_LIMIT_MAX),
    "/api/agent/context": (SEARCH_LIMIT_MIN, CONTEXT_LIMIT_MAX),
}
_SEARCH_LIMIT_LOCATION = ("query", "limit")
logger = logging.getLogger(__name__)


def install_batch_request_bound(app: FastAPI) -> None:
    """Install an endpoint-local receive-time body bound for the batch route.

    Uses a raw ASGI middleware (not ``BaseHTTPMiddleware``) so the ASGI
    ``receive`` callable itself is wrapped — the inner app reads the body
    through the counting wrapper, not through a framework-cached request object.
    A ``Content-Length`` header that honestly declares an oversized body is
    rejected without reading any bytes; an absent, misleading, or
    chunked/streamed body is bounded while receiving. The middleware runs
    inside the API error contract so the 413 response preserves the stable
    error envelope and correlation ID.
    """
    app.add_middleware(_BatchRequestBodyBoundMiddleware)


class _BatchRequestBodyBoundMiddleware:
    """Raw ASGI middleware: bounds the receive stream for the batch endpoint.

    Reads the request body with a byte cap before the inner app starts. If the
    body fits, a replay ``receive`` returns the cached body so FastAPI/Pydantic
    parsing proceeds normally. If the body exceeds the cap, a stable 413
    response is sent without invoking the route. A ``Content-Length`` header
    that honestly declares an oversized body is rejected without reading any
    bytes; an absent, misleading, or chunked/streamed body is bounded while
    receiving.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if (
            scope.get("type") != "http"
            or scope.get("method") != "POST"
            or scope.get("path") != _BATCH_OBJECT_CONTEXTS_PATH
        ):
            await self.app(scope, receive, send)
            return

        content_length = None
        for key, value in scope.get("headers", []):
            if key == b"content-length":
                try:
                    content_length = int(value)
                except ValueError:
                    content_length = None
                break

        if content_length is not None and content_length > MAX_BATCH_REQUEST_BODY_BYTES:
            await _send_batch_too_large(scope, send)
            return

        chunks: list[bytes] = []
        total = 0
        too_large = False
        while True:
            message = await receive()
            if message["type"] == "http.request":
                body = message.get("body", b"")
                total += len(body)
                if total > MAX_BATCH_REQUEST_BODY_BYTES:
                    too_large = True
                    break
                chunks.append(body)
                if not message.get("more_body", False):
                    break
            else:
                break

        if too_large:
            await _send_batch_too_large(scope, send)
            return

        cached_body = b"".join(chunks)
        body_sent = False
        original_receive = receive

        async def replay_receive():
            nonlocal body_sent
            if not body_sent:
                body_sent = True
                return {
                    "type": "http.request",
                    "body": cached_body,
                    "more_body": False,
                }
            return await original_receive()

        await self.app(scope, replay_receive, send)


async def _send_batch_too_large(scope, send):
    correlation_id = _correlation_id_from_scope(scope)
    response = _error_response(
        status_code=413,
        code="payload_too_large",
        message="Batch request payload exceeds the maximum allowed size.",
        correlation_id=correlation_id,
    )

    async def _empty_receive():
        return {"type": "http.disconnect"}

    await response(scope, _empty_receive, send)


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
        # Every detail is projected from the canonical domain violation
        # contract: the rejected value, its Pydantic context, the boundary
        # validation type, and the raw exception text stay internal. A detail
        # carries only the published fields (code, location, message, path,
        # rule), matching the schema projection's violation contract exactly.
        details = order_public_details(
            _api_validation_detail(request, error) for error in exc.errors()
        )
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
            413: "payload_too_large",
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


def _api_validation_detail(
    request: Request,
    error: dict[str, object],
) -> dict[str, str | int | None]:
    """Project one rejected request value onto its published detail.

    A rejected search page size additionally publishes the field name, the
    server-declared allowed range, and the received value re-derived as a
    bounded integer. Every other rejection keeps the unchanged canonical
    detail, so no other input is echoed.
    """
    bounds = _SEARCH_LIMIT_RANGES.get(request.url.path)
    if bounds is not None and tuple(error.get("loc", ())) == _SEARCH_LIMIT_LOCATION:
        minimum, maximum = bounds
        return search_limit_detail(
            location=".".join(_SEARCH_LIMIT_LOCATION),
            code=violation_for_validation_type(error.get("type")),
            received=error.get("input"),
            minimum=minimum,
            maximum=maximum,
        )
    return detail_from_validation_error(error)


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


def _correlation_id_from_scope(scope) -> str:
    """Extract the correlation ID from a raw ASGI scope."""
    state = scope.get("state") or {}
    existing = state.get("correlation_id")
    if isinstance(existing, str):
        return existing
    for key, value in scope.get("headers", []):
        if key == b"x-correlation-id":
            decoded = value.decode("utf-8", errors="replace")
            if _CORRELATION_ID_PATTERN.fullmatch(decoded):
                return decoded
            break
    return str(uuid4())


def _error_response(
    *,
    status_code: int,
    code: str,
    message: str,
    correlation_id: str,
    details: list[dict[str, str | int | None]] | None = None,
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
