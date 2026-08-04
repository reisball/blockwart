from typing import Literal

from pydantic import BaseModel, Field


class CommentCreateIn(BaseModel):
    body: str = Field(min_length=1, max_length=4000)


class CommentOut(BaseModel):
    id: str
    object_id: str
    author_principal_id: str | None = None
    author_login: str | None = None
    author_display_name: str | None = None
    author_principal_type: str | None = None
    origin: Literal["ui", "api", "mcp", "legacy"]
    format: Literal["markdown", "plain_text"]
    body: str
    created_at: str


class CommentPageOut(BaseModel):
    items: list[CommentOut]
    next_cursor: str | None = None
    total: int | None = None
    sort: Literal["created_at"] = "created_at"
    direction: Literal["desc"] = "desc"


class CommentCommandOut(BaseModel):
    comment: CommentOut
    revision: int = Field(ge=1)
    etag: str
    replayed: bool = False
