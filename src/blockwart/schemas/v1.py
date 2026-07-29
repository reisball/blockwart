from typing import Any, Literal

from pydantic import BaseModel, Field

from blockwart.schemas.agent import (
    AgentCatalogObjectContext,
    AgentCatalogObjectSummary,
)
from blockwart.schemas.catalog import ObjectKind

ObjectSortField = Literal["id", "label", "kind", "updated_at"]
SortDirection = Literal["asc", "desc"]


class V1ObjectPageOut(BaseModel):
    items: list[AgentCatalogObjectSummary]
    next_cursor: str | None = None
    total: int | None = None
    sort: ObjectSortField
    direction: SortDirection


class V1ContextPageOut(BaseModel):
    items: list[AgentCatalogObjectContext]
    next_cursor: str | None = None
    total: int | None = None
    sort: ObjectSortField
    direction: SortDirection


class V1RelationshipOut(BaseModel):
    from_ref: str
    relation_type: str
    to_ref: str


class V1RelationshipPageOut(BaseModel):
    items: list[V1RelationshipOut]
    next_cursor: str | None = None
    total: int | None = None
    sort: Literal["relation_type"] = "relation_type"
    direction: SortDirection


class V1AuditEventOut(BaseModel):
    id: int
    action: str
    actor: str
    summary: str
    details: dict[str, Any] = Field(default_factory=dict)
    created_at: str


class V1AuditPageOut(BaseModel):
    items: list[V1AuditEventOut]
    next_cursor: str | None = None
    total: int | None = None
    sort: Literal["created_at"] = "created_at"
    direction: SortDirection


class V1TopologyPortOut(BaseModel):
    label: str
    value: str


class V1TopologyNodeOut(BaseModel):
    ref: str
    id: str
    kind: ObjectKind
    label: str
    status: str
    data: dict[str, Any] = Field(default_factory=dict)
    ports: list[V1TopologyPortOut] = Field(default_factory=list)


class V1TopologyChainOut(BaseModel):
    hosts: list[V1TopologyNodeOut] = Field(default_factory=list)
    systems: list[V1TopologyNodeOut] = Field(default_factory=list)
    services: list[V1TopologyNodeOut] = Field(default_factory=list)


class V1TopologyOut(BaseModel):
    object_ref: str
    chains: list[V1TopologyChainOut] = Field(default_factory=list)
