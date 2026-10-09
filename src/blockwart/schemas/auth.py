from typing import Literal

from pydantic import BaseModel, Field

from blockwart.domain.auth import GrantScope, PlatformRole, PrincipalType, Role


class PrincipalOut(BaseModel):
    id: str
    principal_type: PrincipalType
    login: str
    display_name: str
    platform_role: PlatformRole | None = None
    revision: int = Field(ge=1)


class OwnDirectGrantOut(BaseModel):
    target_kind: Literal["catalog_object", "project"]
    target_id: str
    role: Role
    scope: GrantScope


class OwnDirectGrantListOut(BaseModel):
    items: list[OwnDirectGrantOut]
    next_cursor: str | None = None
