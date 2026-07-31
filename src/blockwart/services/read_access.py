from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.orm import Session

from blockwart.domain.auth import Permission, PrincipalContext
from blockwart.services.policy import PolicySnapshot, policy_for_principal


@dataclass(frozen=True, slots=True)
class ReadAccess:
    principal: PrincipalContext
    policy: PolicySnapshot

    @property
    def cursor_scope(self) -> str:
        return f"{self.principal.id}:{self.policy.fingerprint()}"

    def capabilities_for(self, object_id: str) -> list[Permission]:
        permissions = self.policy.permissions_for(object_id)
        return [
            permission
            for permission in Permission
            if permission in permissions
        ]


def read_access_for_principal(
    session: Session,
    principal: PrincipalContext,
) -> ReadAccess:
    return ReadAccess(
        principal=principal,
        policy=policy_for_principal(session, principal.id),
    )
