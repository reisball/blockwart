from typing import Any, Literal

from pydantic import BaseModel, Field

from blockwart.domain.asset_state import AssetHealth, AssetLifecycle
from blockwart.domain.auth import Permission
from blockwart.domain.placement import PlacementState
from blockwart.domain.provenance import CatalogProvenanceOut
from blockwart.schemas.catalog import CatalogRecordDiagnostic, ObjectKind


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
    visibility: Literal["detail"] = "detail"
    capabilities: list[Permission] = Field(default_factory=list)
    ref: str
    id: str
    kind: ObjectKind
    label: str
    status: str


class AgentAssetStubNode(BaseModel):
    visibility: Literal["stub"] = "stub"
    capabilities: list[Permission] = Field(default_factory=list)
    ref: str
    id: str
    kind: ObjectKind
    label: str


AgentAssetReadNode = AgentAssetNode | AgentAssetStubNode


class AgentCatalogObjectSummary(BaseModel):
    visibility: Literal["detail"] = "detail"
    capabilities: list[Permission] = Field(default_factory=list)
    ref: str
    id: str
    kind: ObjectKind
    label: str
    status: str
    summary: str | None = None
    parent: AgentAssetReadNode | None = None
    ips: list[str] = Field(default_factory=list)
    hostnames: list[str] = Field(default_factory=list)
    primary_endpoint: AgentEndpoint | None = None
    lifecycle: AssetLifecycle | None = None
    health: AssetHealth | None = None
    placement_state: PlacementState | None = None
    record_state: Literal["valid", "corrupt"] = "valid"
    diagnostics: list[CatalogRecordDiagnostic] = Field(default_factory=list)
    provenance: CatalogProvenanceOut


class AgentRelationshipOut(BaseModel):
    from_ref: str
    relation_type: str
    to_ref: str


class AgentCatalogObjectContext(AgentCatalogObjectSummary):
    data: dict[str, Any] = Field(default_factory=dict)
    relationships: list[AgentRelationshipOut] = Field(default_factory=list)
    parent_path: list[AgentAssetReadNode] = Field(default_factory=list)
    children: list[AgentAssetReadNode] = Field(default_factory=list)
    endpoints: list[AgentEndpoint] = Field(default_factory=list)
    source_references: list[dict[str, Any]] = Field(default_factory=list)
    updated_at: str | None = None
    dependencies: dict[str, list[str]] = Field(default_factory=dict)
    credential_references: list[str] = Field(default_factory=list)


class AgentCatalogObjectStub(BaseModel):
    visibility: Literal["stub"] = "stub"
    capabilities: list[Permission] = Field(default_factory=list)
    ref: str
    id: str
    kind: ObjectKind
    label: str
    parent: AgentAssetReadNode | None = None
    parent_path: list[AgentAssetReadNode] = Field(default_factory=list)
    placement_state: PlacementState | None = None


AgentCatalogObjectRead = AgentCatalogObjectSummary | AgentCatalogObjectStub
AgentCatalogContextRead = AgentCatalogObjectContext | AgentCatalogObjectStub


class AgentSearchOut(BaseModel):
    query: str | None = None
    kind: ObjectKind | None = None
    filters: dict[str, str | int | bool] = Field(default_factory=dict)
    count: int
    results: list[AgentCatalogObjectRead]


class AgentContextOut(BaseModel):
    query: str | None = None
    kind: ObjectKind | None = None
    filters: dict[str, str | int | bool] = Field(default_factory=dict)
    count: int
    objects: list[AgentCatalogContextRead]
