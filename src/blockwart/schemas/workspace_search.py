"""Dedicated cross-project workspace search; separate from catalog ranking."""

from typing import Literal

from pydantic import BaseModel, Field

WorkspaceSearchKind = Literal["item", "page", "chronology"]


class WorkspaceSearchHitOut(BaseModel):
    project_id: str
    project_label: str
    kind: WorkspaceSearchKind
    id: str
    title: str
    excerpt: str = Field(max_length=300)
    url: str


class WorkspaceSearchPageOut(BaseModel):
    items: list[WorkspaceSearchHitOut]
    next_cursor: str | None = None
    total: int
