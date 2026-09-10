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
    # Creating a top-level root is the one catalog write that has no parent
    # object to carry a grant, so delegating it needs its own catalog-level
    # authority. This role delegates exactly that, for exactly one kind, and
    # carries no catalog-wide object permission of any sort.
    PROJECT_CREATOR = "project_creator"


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
        # The project creator holds no catalog-wide object permission. Its only
        # authority is root creation for its own kind, and the Owner/self grant
        # written on each root it creates is an ordinary object grant.
        CatalogRole.PROJECT_CREATOR: frozenset(),
    }
)

ROOT_PROJECT_KIND = "project"

# Which object kinds a catalog role may create as a disconnected top-level
# root. ``None`` means every kind the object schema accepts; the concrete kind
# vocabulary lives in the schema layer, so it is resolved at that boundary
# instead of being copied here.
CATALOG_ROLE_ROOT_KINDS = MappingProxyType(
    {
        CatalogRole.CATALOG_OWNER: None,
        CatalogRole.CATALOG_VIEWER: frozenset(),
        CatalogRole.PROJECT_CREATOR: frozenset({ROOT_PROJECT_KIND}),
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

    @property
    def is_project_creator(self) -> bool:
        return self.catalog_role == CatalogRole.PROJECT_CREATOR

    def may_create_root_kind(self, kind: str) -> bool:
        """Answer the projection question only; commands re-resolve from the DB."""
        return catalog_role_creates_root_kind(self.catalog_role, kind)


def permissions_for_role(role: Role | str) -> frozenset[Permission]:
    return ROLE_PERMISSIONS[Role(role)]


def permissions_for_catalog_role(role: CatalogRole | str) -> frozenset[Permission]:
    return CATALOG_ROLE_PERMISSIONS[CatalogRole(role)]


def root_kinds_for_catalog_role(role: CatalogRole | str) -> frozenset[str] | None:
    """Return the creatable root kinds, or ``None`` for every existing kind."""
    return CATALOG_ROLE_ROOT_KINDS[CatalogRole(role)]


def catalog_role_creates_root_kind(
    role: CatalogRole | str | None,
    kind: str,
) -> bool:
    """Whether ``role`` alone authorizes creating a root of ``kind``.

    No catalog role at all creates no root, and neither an object grant nor the
    platform-admin axis can substitute: a root has no parent object to carry a
    grant, and identity administration is a separate axis. A stored value this
    vocabulary does not recognize is never an authority either, so a raw write
    that defeats the database check constraint still fails closed here rather
    than raising out of an authorization gate.
    """
    if role is None:
        return False
    try:
        resolved = CatalogRole(role)
    except ValueError:
        return False
    allowed = CATALOG_ROLE_ROOT_KINDS[resolved]
    return allowed is None or kind in allowed


def roles_for_permission(permission: Permission | str) -> frozenset[Role]:
    resolved = Permission(permission)
    return frozenset(
        role
        for role, permissions in ROLE_PERMISSIONS.items()
        if resolved in permissions
    )
