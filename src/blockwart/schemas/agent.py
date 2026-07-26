from typing import Any

from pydantic import BaseModel, Field

from blockwart.domain.asset_state import AssetHealth, AssetLifecycle
from blockwart.domain.placement import PlacementState
from blockwart.schemas.catalog import ObjectKind


class AgentEndpoint(BaseModel):
    id: str
    type: str
    label: str | None = None
    url: str | None = None
    host: str | None = None
    port: int | None = None
    path: str | None = None
    protocol: str
    transport: str
    exposure: str
    health_url: str | None = None


class AgentAssetNode(BaseModel):
    ref: str
    id: str
    kind: ObjectKind
    label: str
    status: str


class AgentCatalogObjectSummary(BaseModel):
    ref: str
    id: str
    kind: ObjectKind
    label: str
    status: str
    summary: str | None = None
    parent: AgentAssetNode | None = None
    ips: list[str] = Field(default_factory=list)
    hostnames: list[str] = Field(default_factory=list)
    primary_endpoint: AgentEndpoint | None = None
    lifecycle: AssetLifecycle | None = None
    health: AssetHealth | None = None
    placement_state: PlacementState | None = None


class AgentRelationshipOut(BaseModel):
    from_ref: str
    relation_type: str
    to_ref: str


class AgentCatalogObjectContext(AgentCatalogObjectSummary):
    data: dict[str, Any] = Field(default_factory=dict)
    relationships: list[AgentRelationshipOut] = Field(default_factory=list)
    parent_path: list[AgentAssetNode] = Field(default_factory=list)
    children: list[AgentAssetNode] = Field(default_factory=list)
    endpoints: list[AgentEndpoint] = Field(default_factory=list)
    source_references: list[dict[str, Any]] = Field(default_factory=list)
    updated_at: str | None = None
    dependencies: dict[str, list[str]] = Field(default_factory=dict)
    credential_references: list[str] = Field(default_factory=list)


class AgentSearchOut(BaseModel):
    query: str | None = None
    kind: ObjectKind | None = None
    filters: dict[str, str | int] = Field(default_factory=dict)
    count: int
    results: list[AgentCatalogObjectSummary]


class AgentContextOut(BaseModel):
    query: str | None = None
    kind: ObjectKind | None = None
    filters: dict[str, str | int] = Field(default_factory=dict)
    count: int
    objects: list[AgentCatalogObjectContext]
