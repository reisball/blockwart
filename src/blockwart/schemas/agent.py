from typing import Any

from pydantic import BaseModel, Field

from blockwart.schemas.catalog import ObjectKind


class AgentCatalogObjectSummary(BaseModel):
    ref: str
    id: str
    kind: ObjectKind
    label: str
    status: str
    summary: str | None = None


class AgentRelationshipOut(BaseModel):
    from_ref: str
    relation_type: str
    to_ref: str


class AgentCatalogObjectContext(AgentCatalogObjectSummary):
    data: dict[str, Any] = Field(default_factory=dict)
    relationships: list[AgentRelationshipOut] = Field(default_factory=list)
    credential_references: list[str] = Field(default_factory=list)


class AgentSearchOut(BaseModel):
    query: str | None = None
    kind: ObjectKind | None = None
    count: int
    results: list[AgentCatalogObjectSummary]


class AgentContextOut(BaseModel):
    query: str | None = None
    kind: ObjectKind | None = None
    count: int
    objects: list[AgentCatalogObjectContext]
