from typing import Any, Literal

from pydantic import BaseModel, Field

from blockwart.domain.auth import Permission
from blockwart.schemas.agent import (
    AgentCatalogContextRead,
    AgentCatalogObjectRead,
)
from blockwart.schemas.catalog import CatalogObjectOut, ObjectKind

ObjectSortField = Literal["id", "label", "kind", "updated_at"]
SortDirection = Literal["asc", "desc"]


class V1ObjectPageOut(BaseModel):
    items: list[AgentCatalogObjectRead]
    next_cursor: str | None = None
    total: int | None = None
    sort: ObjectSortField
    direction: SortDirection


class V1ContextPageOut(BaseModel):
    items: list[AgentCatalogContextRead]
    next_cursor: str | None = None
    total: int | None = None
    sort: ObjectSortField
    direction: SortDirection


class V1RelationshipOut(BaseModel):
    from_ref: str
    relation_type: str
    to_ref: str


class V1ObjectCommandOut(BaseModel):
    catalog_object: CatalogObjectOut
    etag: str
    changed: bool
    replayed: bool = False


class V1DeleteCommandOut(BaseModel):
    object_id: str
    deleted_revision: int
    changed: bool = True


class V1RelationshipCommandIn(BaseModel):
    from_ref: str = Field(min_length=3, max_length=192)
    relation_type: str = Field(min_length=1, max_length=96)
    to_ref: str = Field(min_length=3, max_length=192)


class V1RelationshipCommandOut(V1RelationshipCommandIn):
    object_id: str
    revision: int = Field(ge=1)
    etag: str
    changed: bool


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
    visibility: Literal["detail"] = "detail"
    capabilities: list[Permission] = Field(default_factory=list)
    ref: str
    id: str
    kind: ObjectKind
    label: str
    status: str
    data: dict[str, Any] = Field(default_factory=dict)
    ports: list[V1TopologyPortOut] = Field(default_factory=list)


class V1TopologyStubNodeOut(BaseModel):
    visibility: Literal["stub"] = "stub"
    capabilities: list[Permission] = Field(default_factory=list)
    ref: str
    id: str
    kind: ObjectKind
    label: str


V1TopologyReadNodeOut = V1TopologyNodeOut | V1TopologyStubNodeOut


class V1TopologyChainOut(BaseModel):
    hosts: list[V1TopologyReadNodeOut] = Field(default_factory=list)
    systems: list[V1TopologyReadNodeOut] = Field(default_factory=list)
    services: list[V1TopologyReadNodeOut] = Field(default_factory=list)


class V1TopologyOut(BaseModel):
    object_ref: str
    chains: list[V1TopologyChainOut] = Field(default_factory=list)
