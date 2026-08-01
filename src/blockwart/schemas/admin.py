from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from blockwart.domain.auth import (
    GrantScope,
    Permission,
    PlatformRole,
    PrincipalType,
    Role,
)

SERVICE_TOKEN_MIN_TTL_SECONDS = 300
SERVICE_TOKEN_MAX_TTL_SECONDS = 31_536_000


class PrincipalAdminSummaryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    principal_type: PrincipalType
    login: str
    display_name: str
    active: bool
    platform_role: PlatformRole | None = None
    revision: int = Field(ge=1)
    etag: str
    created_at: str
    updated_at: str
    last_used_at: str | None = None


class PrincipalAdminListOut(BaseModel):
    items: list[PrincipalAdminSummaryOut]
    next_cursor: str | None = None


class DirectPrincipalGrantOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    grant_id: int
    object_id: str
    object_kind: str
    object_label: str
    object_revision: int = Field(ge=1)
    object_etag: str
    role: Role
    scope: GrantScope
    created_at: str
    updated_at: str


class PrincipalGrantSourceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    grant_id: int
    anchor_object_id: str
    anchor_object_kind: str
    anchor_object_label: str
    role: Role
    scope: GrantScope
    direct: bool


class EffectivePrincipalGrantOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    object_id: str
    object_kind: str
    object_label: str
    permissions: list[Permission]
    sources: list[PrincipalGrantSourceOut]


class PrincipalTokenOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    token_prefix: str
    active: bool
    expires_at: str | None = None
    revoked_at: str | None = None
    rotated_at: str | None = None
    created_at: str
    last_used_at: str | None = None


class PrincipalAdminDetailOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    principal: PrincipalAdminSummaryOut
    direct_grants: list[DirectPrincipalGrantOut]
    effective_access: list[EffectivePrincipalGrantOut]
    service_tokens: list[PrincipalTokenOut]


class PrincipalCreateIn(BaseModel):
    principal_type: PrincipalType
    login: str = Field(min_length=3, max_length=128)
    display_name: str = Field(min_length=1, max_length=255)
    password: str | None = Field(default=None, min_length=12, max_length=1024)
    platform_role: PlatformRole | None = None


class PrincipalUpdateIn(BaseModel):
    display_name: str = Field(min_length=1, max_length=255)
    active: bool
    platform_role: PlatformRole | None


class PrincipalGrantCreateIn(BaseModel):
    object_id: str = Field(min_length=1, max_length=128)
    role: Role
    scope: GrantScope


class PrincipalGrantUpdateIn(PrincipalGrantCreateIn):
    pass


class PrincipalMutationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    principal: PrincipalAdminSummaryOut
    changed: bool


class PasswordResetIn(BaseModel):
    new_password: str = Field(min_length=12, max_length=1024)
    current_admin_password: str | None = Field(default=None, min_length=1, max_length=1024)


class ServiceTokenIssueIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    expires_in_seconds: int | None = Field(
        default=None,
        ge=SERVICE_TOKEN_MIN_TTL_SECONDS,
        le=SERVICE_TOKEN_MAX_TTL_SECONDS,
    )
    current_admin_password: str | None = Field(default=None, min_length=1, max_length=1024)


class ServiceTokenRevokeIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)


class PrincipalCredentialOut(BaseModel):
    principal: PrincipalAdminSummaryOut
    changed: bool
    token: str | None = None
    token_name: str | None = None
    token_expires_at: str | None = None
    disclosure: Literal["none", "one_time"] = "none"
