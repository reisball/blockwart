from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from blockwart.domain.asset_state import AssetHealth, AssetLifecycle
from blockwart.domain.auth import Permission
from blockwart.domain.decisions import DecisionStatus
from blockwart.domain.monitoring import (
    MonitoringDiagnostic,
    MonitoringErrorCode,
    MonitoringFreshness,
    MonitoringProvider,
    MonitoringState,
    MonitoringTargetSource,
)
from blockwart.domain.placement import PlacementState
from blockwart.domain.projects import ProjectCategory, ProjectStatus
from blockwart.domain.provenance import CatalogProvenanceOut
from blockwart.domain.read_projection import (
    READ_PROJECTION_VERSION,
    ProjectionProfile,
)
from blockwart.domain.runbooks import RunbookRisk, RunbookStatus
from blockwart.domain.search import SEARCH_SNIPPET_MAX_LENGTH
from blockwart.schemas.catalog import CatalogRecordDiagnostic, ObjectKind
from blockwart.schemas.comments import CommentOut
from blockwart.schemas.projects import ProjectChronologyEntryOut


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


class AgentMonitoringTarget(BaseModel):
    """The one deterministically resolved probe target of a service."""

    url: str
    scheme: str
    host: str
    port: int
    path: str
    source: MonitoringTargetSource
    endpoint_id: str


class AgentServiceMonitoring(BaseModel):
    """The provider-neutral monitoring projection shared by every surface.

    It carries no vendor-specific payload, so adding a provider cannot change
    this contract. ``state`` is the value a client may act on; ``observed_state``
    is the last stored result even when it has gone stale.
    """

    enabled: bool
    provider: MonitoringProvider | None
    interval_seconds: int | None
    interval_overridden: bool
    target: AgentMonitoringTarget | None = None
    diagnostic: MonitoringDiagnostic | None = None
    state: MonitoringState
    observed_state: MonitoringState
    freshness: MonitoringFreshness
    http_status: int | None = None
    latency_ms: int | None = None
    error_code: MonitoringErrorCode | None = None
    last_checked_at: str | None = None
    last_success_at: str | None = None
    next_due_at: str | None = None
    effective_health: AssetHealth | None = None


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
    # Closed so a projected read can never be silently validated as a full
    # one, which would drop its capability-set key or its reference fields.
    model_config = ConfigDict(extra="forbid")

    visibility: Literal["detail"] = "detail"
    capabilities: list[Permission] = Field(default_factory=list)
    ref: str
    id: str
    kind: ObjectKind
    label: str
    status: str
    revision: int = Field(ge=1)
    summary: str | None = None
    # One bounded, safe orientation line for a detailed result. It is the
    # top-level summary, or the canonical knowledge field of the kind when no
    # summary exists. A discover-only stub never carries it.
    search_snippet: str | None = Field(
        default=None,
        max_length=SEARCH_SNIPPET_MAX_LENGTH,
    )
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
    runbook_status: RunbookStatus | None = None
    runbook_risk: RunbookRisk | None = None
    runbook_applies_to: list[str] = Field(default_factory=list)
    placement_state: PlacementState | None = None
    record_state: Literal["valid", "corrupt"] = "valid"
    diagnostics: list[CatalogRecordDiagnostic] = Field(default_factory=list)
    provenance: CatalogProvenanceOut
    # Present only for readable service objects. A discover-only stub never
    # carries it, so monitoring cannot become an existence or state hint.
    monitoring: AgentServiceMonitoring | None = None


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
    # Project-only professional chronology. Non-Project contexts keep this
    # absent/null; discover-only stubs never carry it.
    recent_project_chronology: list[ProjectChronologyEntryOut] | None = None


class AgentCatalogObjectStub(BaseModel):
    model_config = ConfigDict(extra="forbid")

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
    model_config = ConfigDict(extra="forbid")

    visibility: Literal["concealed"] = "concealed"
    id: str


def _omit_empty_projected_value(value: Any) -> bool:
    """Keep an unselected projected section out of the wire contract."""
    return value is None or value == [] or value == {}


class _ProjectedRead(BaseModel):
    """One read model whose serialized keys are the resolved projection.

    Only the keys the resolved projection actually set are serialized, so an
    unselected section costs nothing at all rather than one null placeholder.
    A key that is absent from a projected read therefore means exactly what a
    null value means in the full contract: the read carries no such value.
    """

    model_config = ConfigDict(extra="forbid")


class AgentProjectedObject(_ProjectedRead):
    """One readable object under a non-default read projection.

    Identity and state are always present, so a projected object publishes the
    same id, ref, kind, revision, visibility decision, and effective
    permissions as the full contract. The effective permissions are published
    once per distinct permission set in the response-level `capability_sets`
    table, which `capability_set` keys into. A full read never carries that
    key and a projected read never carries an inline capability list, so the
    two contracts can never be confused for one another.
    """

    visibility: Literal["detail"] = "detail"
    capability_set: str
    ref: str
    id: str
    kind: ObjectKind
    label: str
    status: str
    revision: int = Field(ge=1)
    # The canonical reference of the one visible placement parent. It is
    # present under exactly the visibility decision that gives the full
    # contract its nested `parent` node.
    parent_ref: str | None = Field(default=None, exclude_if=_omit_empty_projected_value)
    lifecycle: AssetLifecycle | None = Field(default=None, exclude_if=_omit_empty_projected_value)
    health: AssetHealth | None = Field(default=None, exclude_if=_omit_empty_projected_value)
    placement_state: PlacementState | None = Field(
        default=None, exclude_if=_omit_empty_projected_value
    )
    # knowledge: only the canonical short fields of this object's own kind
    decision_status: DecisionStatus | None = Field(
        default=None, exclude_if=_omit_empty_projected_value
    )
    applies_to: list[str] | None = Field(default=None, exclude_if=_omit_empty_projected_value)
    project_category: ProjectCategory | None = Field(
        default=None, exclude_if=_omit_empty_projected_value
    )
    project_status: ProjectStatus | None = Field(
        default=None, exclude_if=_omit_empty_projected_value
    )
    related_assets: list[str] | None = Field(default=None, exclude_if=_omit_empty_projected_value)
    runbook_status: RunbookStatus | None = Field(
        default=None, exclude_if=_omit_empty_projected_value
    )
    runbook_risk: RunbookRisk | None = Field(default=None, exclude_if=_omit_empty_projected_value)
    runbook_applies_to: list[str] | None = Field(
        default=None, exclude_if=_omit_empty_projected_value
    )
    # orientation
    summary: str | None = Field(default=None, exclude_if=_omit_empty_projected_value)
    search_snippet: str | None = Field(
        default=None,
        max_length=SEARCH_SNIPPET_MAX_LENGTH,
        exclude_if=_omit_empty_projected_value,
    )
    # network
    ips: list[str] | None = Field(default=None, exclude_if=_omit_empty_projected_value)
    hostnames: list[str] | None = Field(default=None, exclude_if=_omit_empty_projected_value)
    primary_endpoint: AgentEndpoint | None = Field(
        default=None, exclude_if=_omit_empty_projected_value
    )
    endpoints: list[AgentEndpoint] | None = Field(
        default=None, exclude_if=_omit_empty_projected_value
    )
    # integrity
    record_state: Literal["valid", "corrupt"] | None = Field(
        default=None, exclude_if=_omit_empty_projected_value
    )
    diagnostics: list[CatalogRecordDiagnostic] | None = Field(
        default=None, exclude_if=_omit_empty_projected_value
    )
    provenance: CatalogProvenanceOut | None = Field(
        default=None, exclude_if=_omit_empty_projected_value
    )
    # monitoring
    monitoring: AgentServiceMonitoring | None = Field(
        default=None, exclude_if=_omit_empty_projected_value
    )
    # detail
    etag: str | None = Field(default=None, exclude_if=_omit_empty_projected_value)
    data: dict[str, Any] | None = Field(default=None, exclude_if=_omit_empty_projected_value)
    relationships: list[AgentRelationshipOut] | None = Field(
        default=None, exclude_if=_omit_empty_projected_value
    )
    parent_path_refs: list[str] | None = Field(default=None, exclude_if=_omit_empty_projected_value)
    children_refs: list[str] | None = Field(default=None, exclude_if=_omit_empty_projected_value)
    source_references: list[dict[str, Any]] | None = Field(
        default=None, exclude_if=_omit_empty_projected_value
    )
    updated_at: str | None = Field(default=None, exclude_if=_omit_empty_projected_value)
    dependencies: dict[str, list[str]] | None = Field(
        default=None, exclude_if=_omit_empty_projected_value
    )
    credential_references: list[str] | None = Field(
        default=None, exclude_if=_omit_empty_projected_value
    )
    # activity
    recent_comments: list[CommentOut] | None = Field(
        default=None, exclude_if=_omit_empty_projected_value
    )
    recent_project_chronology: list[ProjectChronologyEntryOut] | None = Field(
        default=None, exclude_if=_omit_empty_projected_value
    )


class AgentProjectedStub(_ProjectedRead):
    """One discover-only object under a non-default read projection.

    A projected stub publishes strictly the subset of what the full stub
    already publishes, so a projection can never turn discover-only knowledge
    into readable knowledge.
    """

    visibility: Literal["stub"] = "stub"
    capability_set: str
    ref: str
    id: str
    kind: ObjectKind
    label: str
    parent_ref: str | None = Field(default=None, exclude_if=_omit_empty_projected_value)
    placement_state: PlacementState | None = Field(
        default=None, exclude_if=_omit_empty_projected_value
    )
    parent_path_refs: list[str] | None = Field(default=None, exclude_if=_omit_empty_projected_value)


class ReadProjectionOut(BaseModel):
    """The echoed, versioned description of one resolved projected read."""

    model_config = ConfigDict(extra="forbid")

    version: int = READ_PROJECTION_VERSION
    profile: ProjectionProfile
    sections: list[str] = Field(default_factory=list)


AgentProjectedRead = Annotated[
    AgentProjectedObject | AgentProjectedStub,
    Field(discriminator="visibility"),
]
AgentProjectedBatchItem = Annotated[
    AgentProjectedObject | AgentProjectedStub | AgentCatalogConcealed,
    Field(discriminator="visibility"),
]


AgentCatalogObjectRead = AgentCatalogObjectSummary | AgentCatalogObjectStub
AgentCatalogContextRead = AgentCatalogObjectContext | AgentCatalogObjectStub
# The batch item union adds the concealed marker. Single-object reads keep
# returning 404 for concealed ids, so AgentCatalogContextRead stays unchanged.
AgentCatalogBatchItem = AgentCatalogObjectContext | AgentCatalogObjectStub | AgentCatalogConcealed


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
