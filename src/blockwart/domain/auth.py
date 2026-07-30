from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType


class PrincipalType(StrEnum):
    HUMAN = "human"
    SERVICE_ACCOUNT = "service_account"


class Permission(StrEnum):
    DISCOVER = "discover"
    READ = "read"
    WRITE = "write"
    CREATE_CHILD = "create_child"
    MANAGE_ACCESS = "manage_access"
    DELETE = "delete"


class Role(StrEnum):
    DISCOVERER = "discoverer"
    VIEWER = "viewer"
    EDITOR = "editor"
    CREATOR = "creator"
    ACCESS_MANAGER = "access_manager"
    OWNER = "owner"


class GrantScope(StrEnum):
    SELF = "self"
    SUBTREE = "subtree"


class ObjectVisibility(StrEnum):
    NONE = "none"
    STUB = "stub"
    DETAIL = "detail"


ROLE_PERMISSIONS = MappingProxyType(
    {
        Role.DISCOVERER: frozenset({Permission.DISCOVER}),
        Role.VIEWER: frozenset({Permission.DISCOVER, Permission.READ}),
        Role.EDITOR: frozenset(
            {
                Permission.DISCOVER,
                Permission.READ,
                Permission.WRITE,
            }
        ),
        Role.CREATOR: frozenset(
            {
                Permission.DISCOVER,
                Permission.READ,
                Permission.CREATE_CHILD,
            }
        ),
        Role.ACCESS_MANAGER: frozenset(
            {
                Permission.DISCOVER,
                Permission.READ,
                Permission.MANAGE_ACCESS,
            }
        ),
        Role.OWNER: frozenset(Permission),
    }
)


@dataclass(frozen=True)
class PrincipalContext:
    id: str
    principal_type: PrincipalType
    login: str
    display_name: str


def permissions_for_role(role: Role | str) -> frozenset[Permission]:
    return ROLE_PERMISSIONS[Role(role)]


def roles_for_permission(permission: Permission | str) -> frozenset[Role]:
    resolved = Permission(permission)
    return frozenset(
        role
        for role, permissions in ROLE_PERMISSIONS.items()
        if resolved in permissions
    )
