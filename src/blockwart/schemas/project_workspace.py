"""One closed contract shared by UI, REST and MCP project records."""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, field_validator, model_validator

from blockwart.domain.object_schema import is_safe_external_http_url
from blockwart.domain.provenance import parse_rfc3339_utc
from blockwart.domain.security import find_secret_violations
from blockwart.domain.timestamps import format_rfc3339_utc
from blockwart.schemas.catalog import CatalogObjectIn

RecordKind = Literal["item", "page", "access"]
ItemStatus = Literal["open", "in_progress", "blocked", "done"]
ItemType = Literal["task", "question", "blocker"]


class RecordBase(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    title: str = Field(min_length=1, max_length=255)

    @model_validator(mode="after")
    def safe_metadata(self):
        if find_secret_violations(self.model_dump(mode="json")):
            raise ValueError("Secret-shaped content is not allowed; use a credential reference")
        return self


class ProjectItemIn(RecordBase):
    kind: Literal["item"] = "item"
    description: str = Field(default="", max_length=4000)
    item_type: ItemType = "task"
    status: ItemStatus = "open"
    assignee: str = Field(default="", max_length=255)
    due_at: str | None = None
    parent_id: str | None = Field(default=None, min_length=1, max_length=36)
    issue_url: str | None = Field(default=None, max_length=2048)
    related_objects: list[str] = Field(default_factory=list, max_length=50)

    @field_validator("due_at")
    @classmethod
    def timestamp(cls, value):
        return normalized_time(value)

    @field_validator("issue_url")
    @classmethod
    def safe_url(cls, value):
        return validated_url(value)


class ProjectPageIn(RecordBase):
    kind: Literal["page"] = "page"
    body: str = Field(default="", max_length=4000)
    review_after: str | None = None
    related_objects: list[str] = Field(default_factory=list, max_length=50)

    @field_validator("review_after")
    @classmethod
    def timestamp(cls, value):
        return normalized_time(value)


class ProjectAccessIn(RecordBase):
    kind: Literal["access"] = "access"
    url: str | None = Field(default=None, max_length=2048)
    purpose: str = Field(default="", max_length=2000)
    account: str = Field(default="", max_length=255)
    credential_reference: str | None = Field(default=None, max_length=192)
    new_credential_reference: CatalogObjectIn | None = Field(default=None, exclude=True)

    @field_validator("url")
    @classmethod
    def safe_url(cls, value):
        return validated_url(value)

    @model_validator(mode="after")
    def one_reference(self):
        if self.credential_reference and self.new_credential_reference:
            raise ValueError("Choose an existing or a new reference, not both")
        if (
            self.new_credential_reference
            and self.new_credential_reference.kind != "credential_reference"
        ):
            raise ValueError("Only credential_reference metadata can be created here")
        return self


ProjectRecordIn = Annotated[
    ProjectItemIn | ProjectPageIn | ProjectAccessIn, Field(discriminator="kind")
]
RECORD_ADAPTER = TypeAdapter(ProjectRecordIn)


class ProjectRecordOut(BaseModel):
    id: str
    kind: RecordKind
    data: dict
    version: int
    created_at: str
    updated_at: str
    completed_at: str | None = None
    overdue: bool = False


class ProjectRecordPageOut(BaseModel):
    items: list[ProjectRecordOut]
    next_cursor: str | None = None
    total: int


class ProjectRecordCommandOut(BaseModel):
    record: ProjectRecordOut
    revision: int
    etag: str
    replayed: bool = False


class ProjectRecordVersionOut(BaseModel):
    version: int
    data: dict
    author_id: str
    author_label: str
    origin: str
    created_at: str
    completed_at: str | None = None


class ProjectHistoryPageOut(BaseModel):
    items: list[ProjectRecordVersionOut]
    next_cursor: str | None = None
    total: int


class ProjectSearchHitOut(BaseModel):
    kind: str
    id: str
    title: str
    text: str


class ProjectSearchPageOut(BaseModel):
    items: list[ProjectSearchHitOut]
    next_cursor: str | None = None
    total: int


def normalized_time(value):
    if value is None:
        return None
    return format_rfc3339_utc(parse_rfc3339_utc(value))


def validated_url(value):
    if value is not None and not is_safe_external_http_url(value):
        raise ValueError("A safe HTTP(S) URL without credentials is required")
    return value
