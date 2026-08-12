from typing import Any, Literal

from pydantic import BaseModel, Field

from blockwart.domain.asset_state import AssetHealth, AssetLifecycle
from blockwart.domain.auth import Permission
from blockwart.domain.decisions import DecisionStatus
from blockwart.domain.placement import PlacementState
from blockwart.domain.projects import ProjectCategory, ProjectStatus
from blockwart.domain.provenance import CatalogProvenanceOut
from blockwart.schemas.catalog import CatalogRecordDiagnostic, ObjectKind
from blockwart.schemas.comments import CommentOut


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
    revision: int = Field(ge=1)
    summary: str | None = None
    parent: AgentAssetReadNode | None = None
    ips: list[str] = Field(default_factory=list)
    hostnames: list[str] = Field(default_factory=list)
    primary_endpoint: AgentEndpoint | None = None
    lifecycle: AssetLifecycle | None = None
    health: AssetHealth | None = None
    decision_status: DecisionStatus | None = None
    applies_to: list[str] = Field(default_factory=list)
    project_category: ProjectCategory | None = None
    project_status: ProjectStatus | None = None
    related_assets: list[str] = Field(default_factory=list)
    placement_state: PlacementState | None = None
    record_state: Literal["valid", "corrupt"] = "valid"
    diagnostics: list[CatalogRecordDiagnostic] = Field(default_factory=list)
    provenance: CatalogProvenanceOut


class AgentRelationshipOut(BaseModel):
    from_ref: str
    relation_type: str
    to_ref: str


class AgentCatalogObjectContext(AgentCatalogObjectSummary):
    etag: str
    data: dict[str, Any] = Field(default_factory=dict)
    relationships: list[AgentRelationshipOut] = Field(default_factory=list)
    parent_path: list[AgentAssetReadNode] = Field(default_factory=list)
    children: list[AgentAssetReadNode] = Field(default_factory=list)
    endpoints: list[AgentEndpoint] = Field(default_factory=list)
    source_references: list[dict[str, Any]] = Field(default_factory=list)
    updated_at: str | None = None
    dependencies: dict[str, list[str]] = Field(default_factory=dict)
    credential_references: list[str] = Field(default_factory=list)
    recent_comments: list[CommentOut] = Field(default_factory=list)


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


# A concealed placeholder carries only the requested id and a marker. It is
# returned by the known-id batch surface for objects the caller cannot discover
# and for ids that do not exist; the two cases must stay indistinguishable, so
# no kind, label, ref, capability, etag, comment, relationship, or other
# detail-only field is ever attached.
class AgentCatalogConcealed(BaseModel):
    visibility: Literal["concealed"] = "concealed"
    id: str


AgentCatalogObjectRead = AgentCatalogObjectSummary | AgentCatalogObjectStub
AgentCatalogContextRead = AgentCatalogObjectContext | AgentCatalogObjectStub
# The batch item union adds the concealed marker. Single-object reads keep
# returning 404 for concealed ids, so AgentCatalogContextRead stays unchanged.
AgentCatalogBatchItem = (
    AgentCatalogObjectContext | AgentCatalogObjectStub | AgentCatalogConcealed
)


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


class AgentObjectContextBatchOut(BaseModel):
    count: int
    objects: list[AgentCatalogBatchItem]
