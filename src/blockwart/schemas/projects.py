"""Dedicated Project workspace and chronology boundary models."""

from typing import Literal

from pydantic import BaseModel, Field

from blockwart.domain.auth import Permission
from blockwart.domain.projects import ProjectCategory, ProjectStatus

ProjectChronologyKind = Literal[
    "intent",
    "implementation",
    "result",
    "decision",
    "milestone",
    "blocker",
    "note",
]
ProjectOverviewSort = Literal["last_activity", "label", "id"]


class ProjectChronologyCreateIn(BaseModel):
    kind: ProjectChronologyKind
    body: str = Field(min_length=1, max_length=4000)


class ProjectChronologyEntryOut(BaseModel):
    id: str
    object_id: str
    kind: ProjectChronologyKind
    author_principal_id: str | None = None
    author_login: str | None = None
    author_display_name: str | None = None
    author_principal_type: str | None = None
    origin: Literal["ui", "api", "mcp", "legacy"]
    format: Literal["markdown", "plain_text"]
    body: str
    created_at: str


class ProjectChronologyPageOut(BaseModel):
    items: list[ProjectChronologyEntryOut]
    next_cursor: str | None = None
    total: int | None = None
    sort: Literal["created_at"] = "created_at"
    direction: Literal["desc"] = "desc"


class ProjectChronologyCommandOut(BaseModel):
    entry: ProjectChronologyEntryOut
    revision: int = Field(ge=1)
    etag: str
    replayed: bool = False


class ProjectOverviewItemOut(BaseModel):
    visibility: Literal["detail"] = "detail"
    capabilities: list[Permission] = Field(default_factory=list)
    ref: str
    id: str
    label: str
    revision: int = Field(ge=1)
    category: ProjectCategory | None = None
    project_status: ProjectStatus | None = None
    current_summary: str | None = None
    next_action: str | None = None
    last_professional_activity: ProjectChronologyEntryOut | None = None


class ProjectOverviewPageOut(BaseModel):
    items: list[ProjectOverviewItemOut]
    next_cursor: str | None = None
    total: int | None = None
    sort: ProjectOverviewSort
    direction: Literal["asc", "desc"]
