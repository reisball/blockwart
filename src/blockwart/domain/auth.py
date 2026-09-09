from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType


class PrincipalType(StrEnum):
    HUMAN = "human"
    SERVICE_ACCOUNT = "service_account"


class PlatformRole(StrEnum):
    ADMIN = "admin"


class CatalogRole(StrEnum):
    """Global catalog authority, independent of the platform-admin axis."""

    CATALOG_OWNER = "catalog_owner"
    CATALOG_VIEWER = "catalog_viewer"


class Permission(StrEnum):
    DISCOVER = "discover"
    READ = "read"
    WRITE = "write"
    # Changing only the common top-level label is its own capability, so it can
    # be delegated without the general write authority over an object document.
    RENAME = "rename"
    CREATE_CHILD = "create_child"
    MANAGE_ACCESS = "manage_access"
    DELETE = "delete"


class Role(StrEnum):
    DISCOVERER = "discoverer"
    VIEWER = "viewer"
    RENAMER = "renamer"
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
        Role.RENAMER: frozenset(
            {
                Permission.DISCOVER,
                Permission.READ,
                Permission.RENAME,
            }
        ),
        Role.EDITOR: frozenset(
            {
                Permission.DISCOVER,
                Permission.READ,
                Permission.WRITE,
                Permission.RENAME,
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

CATALOG_ROLE_PERMISSIONS = MappingProxyType(
    {
        CatalogRole.CATALOG_OWNER: frozenset(Permission),
        CatalogRole.CATALOG_VIEWER: frozenset(
            {
                Permission.DISCOVER,
                Permission.READ,
            }
        ),
    }
)


@dataclass(frozen=True)
class PrincipalContext:
    id: str
    principal_type: PrincipalType
    login: str
    display_name: str
    platform_role: PlatformRole | None = None
    revision: int = 1
    service_token_audience: str | None = field(default=None, compare=False)
    catalog_role: CatalogRole | None = None

    @property
    def is_admin(self) -> bool:
        return self.platform_role == PlatformRole.ADMIN

    @property
    def is_catalog_owner(self) -> bool:
        return self.catalog_role == CatalogRole.CATALOG_OWNER

    @property
    def is_catalog_viewer(self) -> bool:
        return self.catalog_role == CatalogRole.CATALOG_VIEWER


def permissions_for_role(role: Role | str) -> frozenset[Permission]:
    return ROLE_PERMISSIONS[Role(role)]


def permissions_for_catalog_role(role: CatalogRole | str) -> frozenset[Permission]:
    return CATALOG_ROLE_PERMISSIONS[CatalogRole(role)]


def roles_for_permission(permission: Permission | str) -> frozenset[Role]:
    resolved = Permission(permission)
    return frozenset(
        role
        for role, permissions in ROLE_PERMISSIONS.items()
        if resolved in permissions
    )
