from pydantic import BaseModel


class ApiErrorDetail(BaseModel):
    location: str
    message: str
    type: str


class ApiError(BaseModel):
    code: str
    message: str
    correlation_id: str
    details: list[ApiErrorDetail] | None = None


class ApiErrorResponse(BaseModel):
    error: ApiError
