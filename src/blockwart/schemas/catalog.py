from typing import Any, ClassVar, Literal

from pydantic import BaseModel, Field, model_validator

from blockwart.domain.asset_state import AssetHealth, AssetLifecycle, is_asset_kind
from blockwart.domain.auth import Permission
from blockwart.domain.interfaces import normalize_interface_data
from blockwart.domain.object_schema import normalize_object_data, validate_object_data
from blockwart.domain.placement import PlacementState, validate_placement_metadata
from blockwart.domain.provenance import (
    CatalogProvenance,
    CatalogProvenanceOut,
    manual_provenance,
)
from blockwart.domain.security import find_acl_data_violations, find_secret_violations

ObjectKind = Literal[
    "host",
    "system",
    "network",
    "device",
    "service",
    "credential_reference",
    "runbook",
    "decision",
    "project",
]
PublicObjectKind = Literal["host", "system", "network", "device", "service"]
ObjectStatus = Literal["active", "inactive", "deleted"]
PUBLIC_OBJECT_KINDS: tuple[PublicObjectKind, ...] = (
    "host",
    "system",
    "network",
    "device",
    "service",
)
OBJECT_STATUSES: tuple[ObjectStatus, ...] = ("active", "inactive", "deleted")

ENDPOINT_TYPE_OPTIONS = ("Web", "REST API", "MCP", "HEC", "SSH")
ENDPOINT_TYPES = set(ENDPOINT_TYPE_OPTIONS)


class CatalogObjectIn(BaseModel):
    reject_acl_data: ClassVar[bool] = True
    allow_legacy_network_without_category: ClassVar[bool] = False
    allow_legacy_decision_without_status: ClassVar[bool] = False
    allow_legacy_decision_data: ClassVar[bool] = False
    allow_legacy_project_without_category: ClassVar[bool] = False
    allow_legacy_project_data: ClassVar[bool] = False
    allow_legacy_runbook_without_status: ClassVar[bool] = False
    allow_legacy_runbook_data: ClassVar[bool] = False

    id: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]*[a-z0-9]$|^[a-z0-9]$")
    kind: ObjectKind
    label: str
    status: ObjectStatus = "active"
    lifecycle: AssetLifecycle | None = None
    health: AssetHealth | None = None
    summary: str | None = None
    data: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Kind-specific catalog data. The top-level x-blockwart-object-schema "
            "OpenAPI extension is generated from the same domain registry that "
            "validates writes."
        ),
    )
    provenance: CatalogProvenance = Field(default_factory=manual_provenance)

    @model_validator(mode="after")
    def reject_secret_values(self) -> "CatalogObjectIn":
        violations = find_secret_violations(self.model_dump())
        if violations:
            raise ValueError("; ".join(violations))
        if self.reject_acl_data:
            acl_violations = find_acl_data_violations(self.data)
            if acl_violations:
                raise ValueError("; ".join(acl_violations))
        return self

    @model_validator(mode="after")
    def validate_catalog_data(self) -> "CatalogObjectIn":
        if not is_asset_kind(self.kind) and (
            self.lifecycle is not None or self.health is not None
        ):
            raise ValueError("lifecycle and health are only valid for asset kinds")
        if not self.allow_legacy_network_without_category:
            self.data = normalize_object_data(self.kind, self.data)
        validate_object_data(
            self.kind,
            self.data,
            allow_legacy_network_without_category=(
                self.allow_legacy_network_without_category
            ),
            allow_legacy_decision_without_status=(
                self.allow_legacy_decision_without_status
            ),
            allow_legacy_decision_data=self.allow_legacy_decision_data,
            allow_legacy_project_without_category=(
                self.allow_legacy_project_without_category
            ),
            allow_legacy_project_data=self.allow_legacy_project_data,
            allow_legacy_runbook_without_status=(
                self.allow_legacy_runbook_without_status
            ),
            allow_legacy_runbook_data=self.allow_legacy_runbook_data,
        )
        normalize_interface_data(
            self.data,
            kind=self.kind,
            object_id=self.id,
        )
        validate_placement_metadata(self.data, kind=self.kind)
        return self


class CatalogAssetNode(BaseModel):
    visibility: Literal["detail"] = "detail"
    capabilities: list[Permission] = Field(default_factory=list)
    ref: str
    id: str
    kind: ObjectKind
    label: str
    status: str


class CatalogAssetStubNode(BaseModel):
    visibility: Literal["stub"] = "stub"
    capabilities: list[Permission] = Field(default_factory=list)
    ref: str
    id: str
    kind: ObjectKind
    label: str


CatalogAssetReadNode = CatalogAssetNode | CatalogAssetStubNode


class CatalogRecordDiagnostic(BaseModel):
    code: Literal["corrupt_record"]
    object_id: str
    message: str


class CatalogObjectOut(CatalogObjectIn):
    # Legacy records remain readable while all mutation/import inputs reject
    # ACL-shaped catalog data.
    reject_acl_data: ClassVar[bool] = False
    allow_legacy_network_without_category: ClassVar[bool] = True
    allow_legacy_decision_without_status: ClassVar[bool] = True
    allow_legacy_decision_data: ClassVar[bool] = True
    allow_legacy_project_without_category: ClassVar[bool] = True
    allow_legacy_project_data: ClassVar[bool] = True
    allow_legacy_runbook_without_status: ClassVar[bool] = True
    allow_legacy_runbook_data: ClassVar[bool] = True

    visibility: Literal["detail"] = "detail"
    capabilities: list[Permission] = Field(default_factory=list)
    provenance: CatalogProvenanceOut
    revision: int = Field(ge=1)
    created_at: str | None = None
    updated_at: str | None = None
    last_changed: str | None = None
    parent_path: list[CatalogAssetReadNode] = Field(default_factory=list)
    placement_state: PlacementState | None = None
    record_state: Literal["valid", "corrupt"] = "valid"
    diagnostics: list[CatalogRecordDiagnostic] = Field(default_factory=list)


class CatalogObjectStubOut(BaseModel):
    visibility: Literal["stub"] = "stub"
    capabilities: list[Permission] = Field(default_factory=list)
    id: str
    kind: ObjectKind
    label: str
    parent_path: list[CatalogAssetReadNode] = Field(default_factory=list)
    placement_state: PlacementState | None = None


CatalogObjectReadOut = CatalogObjectOut | CatalogObjectStubOut


class HealthOut(BaseModel):
    ok: bool
    status: Literal["alive"]
    service: str
    version: str
    build_revision: str


class ReadinessOut(BaseModel):
    ok: bool
    status: Literal["ready", "not_ready"]
    service: str
    version: str
    build_revision: str
    checks: dict[str, Literal["ok", "error", "unknown", "not_applicable"]]
    revision: str | None = None
    error_code: str | None = None
