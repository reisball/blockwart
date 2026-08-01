from pydantic import BaseModel, Field

from blockwart.domain.auth import PlatformRole, PrincipalType


class PrincipalOut(BaseModel):
    id: str
    principal_type: PrincipalType
    login: str
    display_name: str
    platform_role: PlatformRole | None = None
    revision: int = Field(ge=1)
