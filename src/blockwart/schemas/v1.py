from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_serializer

from blockwart.domain.auth import GrantScope, Permission, Role
from blockwart.schemas.agent import (
    AgentCatalogContextRead,
    AgentCatalogObjectRead,
)
from blockwart.schemas.catalog import CatalogObjectIn, CatalogObjectOut, ObjectKind

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


class V1RelationshipMetadata(BaseModel):
    """Canonical optional metadata for link-shaped relationships.

    Unset fields are omitted so empty metadata serializes as ``{}``.
    """

    model_config = ConfigDict(extra="forbid")

    source_interface: str | None = Field(default=None, min_length=1, max_length=128)
    target_interface_or_port: str | None = Field(default=None, min_length=1, max_length=128)
    link_kind: (
        Literal[
            "ethernet",
            "wifi",
            "mesh",
            "zigbee",
            "bluetooth",
            "usb",
            "serial",
            "gpio",
            "power",
            "virtual",
            "other",
        ]
        | None
    ) = None
    primary: bool | None = None
    note: str | None = Field(default=None, min_length=1, max_length=512)
    mode: (
        Literal[
            "access",
            "trunk",
            "routed",
            "bridged",
            "mesh",
            "other",
        ]
        | None
    ) = None

    @model_serializer(mode="wrap")
    def _serialize_without_nulls(self, handler) -> dict[str, Any]:
        return {key: value for key, value in handler(self).items() if value is not None}


class V1RelationshipOut(BaseModel):
    from_ref: str
    relation_type: str
    to_ref: str
    metadata: V1RelationshipMetadata = Field(default_factory=V1RelationshipMetadata)


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
    metadata: V1RelationshipMetadata = Field(
        default_factory=V1RelationshipMetadata,
    )


class V1AttachedDeviceCreateIn(BaseModel):
    device: CatalogObjectIn
    metadata: V1RelationshipMetadata = Field(
        default_factory=V1RelationshipMetadata,
    )


class V1RelationshipCommandOut(BaseModel):
    from_ref: str
    relation_type: str
    to_ref: str
    metadata: V1RelationshipMetadata = Field(default_factory=V1RelationshipMetadata)
    object_id: str
    revision: int = Field(ge=1)
    etag: str
    changed: bool


class V1DeviceGraphNodeBaseOut(BaseModel):
    ref: str
    id: str
    kind: ObjectKind
    label: str
    capabilities: list[Permission] = Field(default_factory=list)


class V1DeviceGraphStubNodeOut(V1DeviceGraphNodeBaseOut):
    visibility: Literal["stub"] = "stub"


class V1DeviceGraphDetailNodeOut(V1DeviceGraphNodeBaseOut):
    visibility: Literal["detail"] = "detail"
    status: str
    data: dict[str, Any] = Field(default_factory=dict)
    manufacturer: str | None = None
    model: str | None = None
    category: str | None = None


class V1DeviceGraphEdgeOut(BaseModel):
    from_ref: str
    relation_type: Literal["attached_to"]
    to_ref: str
    metadata: V1RelationshipMetadata = Field(default_factory=V1RelationshipMetadata)


V1DeviceGraphNodeOut = Annotated[
    V1DeviceGraphDetailNodeOut | V1DeviceGraphStubNodeOut,
    Field(discriminator="visibility"),
]


class V1DeviceGraphOut(BaseModel):
    object_ref: str
    nodes: list[V1DeviceGraphNodeOut] = Field(default_factory=list)
    edges: list[V1DeviceGraphEdgeOut] = Field(default_factory=list)
    upstream_path: list[str] = Field(default_factory=list)
    downstream_refs: list[str] = Field(default_factory=list)


class V1NetworkTopologyNodeBaseOut(BaseModel):
    ref: str
    id: str
    kind: ObjectKind
    label: str
    capabilities: list[Permission] = Field(default_factory=list)


class V1NetworkTopologyStubNodeOut(V1NetworkTopologyNodeBaseOut):
    visibility: Literal["stub"] = "stub"


class V1NetworkTopologyDetailNodeOut(V1NetworkTopologyNodeBaseOut):
    visibility: Literal["detail"] = "detail"
    status: str
    data: dict[str, Any] = Field(default_factory=dict)
    category: str | None = None
    manufacturer: str | None = None
    model: str | None = None
    location: str | None = None


V1NetworkTopologyNodeOut = Annotated[
    V1NetworkTopologyDetailNodeOut | V1NetworkTopologyStubNodeOut,
    Field(discriminator="visibility"),
]


class V1NetworkTopologyEdgeOut(BaseModel):
    from_ref: str
    relation_type: Literal["hosts", "attached_to", "uplinks_to"]
    to_ref: str
    metadata: V1RelationshipMetadata = Field(default_factory=V1RelationshipMetadata)


class V1NetworkTopologyPathOut(BaseModel):
    refs: list[str] = Field(default_factory=list)
    status: Literal["complete", "incomplete"]


class V1NetworkTopologyOut(BaseModel):
    object_ref: str
    nodes: list[V1NetworkTopologyNodeOut] = Field(default_factory=list)
    edges: list[V1NetworkTopologyEdgeOut] = Field(default_factory=list)
    paths: list[V1NetworkTopologyPathOut] = Field(default_factory=list)
    resolution: Literal["direct", "inherited"] | None = None
    resolution_source: Literal["host", "system", "placement_host", "network"] | None = None
    resolution_source_ref: str | None = None
    placement_path: list[str] = Field(default_factory=list)
    status: Literal["complete", "incomplete", "unconnected"]
    truncated: bool = False


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


class V1PrincipalSummaryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    login: str
    display_name: str
    principal_type: Literal["human", "service_account"]
    active: bool


class V1DirectGrantOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    principal: V1PrincipalSummaryOut
    role: Role
    scope: GrantScope
    created_at: str
    updated_at: str


class V1EffectiveGrantSourceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    grant_id: int
    anchor_object_id: str
    anchor_object_kind: str
    anchor_object_label: str
    role: Role
    scope: GrantScope
    direct: bool


class V1EffectivePrincipalAccessOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    principal: V1PrincipalSummaryOut
    permissions: list[Permission]
    sources: list[V1EffectiveGrantSourceOut]


class V1ObjectAccessOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    object_id: str
    revision: int = Field(ge=1)
    etag: str
    direct_grants: list[V1DirectGrantOut]
    effective_access: list[V1EffectivePrincipalAccessOut]


class V1PrincipalSearchOut(BaseModel):
    items: list[V1PrincipalSummaryOut]


class V1ScopePreviewObjectOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    kind: str
    label: str
    direct: bool


class V1GrantScopePreviewOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    object_id: str
    scope: GrantScope
    affected_objects: list[V1ScopePreviewObjectOut]


class V1GrantCreateIn(BaseModel):
    principal_id: str = Field(min_length=1, max_length=36)
    role: Role
    scope: GrantScope


class V1GrantUpdateIn(BaseModel):
    role: Role
    scope: GrantScope


class V1GrantCommandOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    object_id: str
    revision: int = Field(ge=1)
    etag: str
    changed: bool
    grant: V1DirectGrantOut | None = None
    revoked_grant_id: int | None = None
