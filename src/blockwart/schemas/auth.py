from pydantic import BaseModel

from blockwart.domain.auth import PrincipalType


class PrincipalOut(BaseModel):
    id: str
    principal_type: PrincipalType
    login: str
    display_name: str
