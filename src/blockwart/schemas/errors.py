from pydantic import BaseModel


class ApiErrorDetail(BaseModel):
    """One rejected field of a failed request.

    The fields mirror the published `violation_policy` of the schema
    projection exactly: `code` is a published violation type from
    `blockwart.domain.object_schema`, `path` the canonical catalog data path
    when the domain schema rejected the value, `rule` the published schema
    rule when a postcondition rejected it, `location` the rejected path inside
    the request, and `message` the published description of the violation.
    No rejected value, boundary validation type, Pydantic context, or
    exception text is ever part of a detail.
    """

    location: str
    message: str
    code: str
    path: str | None = None
    rule: str | None = None


class ApiError(BaseModel):
    code: str
    message: str
    correlation_id: str
    details: list[ApiErrorDetail] | None = None


class ApiErrorResponse(BaseModel):
    error: ApiError
