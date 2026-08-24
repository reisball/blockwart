"""The versioned, closed read-projection contract shared by every agent read.

An agent read may cost far more context than the decision it supports. This
module publishes the *only* way a caller may make an authorized read smaller:
one closed server-defined profile plus one closed server-defined field mask.
There is no client-supplied field expression, no path selector, and no way to
name a stored field, so a projection can never widen a read, reach past an
authorization decision, or turn a concealed object into a distinguishable one.

A projection changes which *published sections* of an already authorized read
model are serialized. It never changes:

- which objects are returned, in which order, or under which cursor;
- the visibility decision made for an object (detail, stub, or concealed);
- the identity, revision, or effective permissions of a returned object;
- the concealment contract, under which a concealed and a missing id stay
  indistinguishable.

The `identity` and `state` sections are therefore not selectable: they carry
exactly those invariants and are always serialized.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Literal, get_args

from blockwart.domain.auth import Permission

# Bump this deliberately when the meaning of a profile or section changes.
# Adding a new selectable section is additive and does not require a bump.
READ_PROJECTION_VERSION = 1

ProjectionProfile = Literal["compact", "context", "full"]
ProjectionSection = Literal[
    "knowledge",
    "orientation",
    "network",
    "integrity",
    "monitoring",
    "detail",
    "activity",
]
ProjectionSurface = Literal["summary", "context"]

PROJECTION_PROFILES: tuple[str, ...] = get_args(ProjectionProfile)
# The closed field mask. `identity` and `state` are deliberately absent: they
# are always serialized, so a mask can never hide an identity, a revision, a
# visibility decision, or an effective permission.
PROJECTION_SECTIONS: tuple[str, ...] = get_args(ProjectionSection)
CORE_SECTIONS: tuple[str, ...] = ("identity", "state")
DEFAULT_PROJECTION_PROFILE = "full"

# What each profile may serialize. A mask can only narrow this further.
_PROFILE_SECTIONS: dict[str, frozenset[str]] = {
    "compact": frozenset({"knowledge", "orientation"}),
    "context": frozenset(
        {"knowledge", "orientation", "network", "integrity", "monitoring", "detail"}
    ),
    "full": frozenset(PROJECTION_SECTIONS),
}
# What each read surface can serve at all. A search summary has no detail or
# activity data, so those sections are not silently promised there.
_SURFACE_SECTIONS: dict[str, frozenset[str]] = {
    "summary": frozenset({"knowledge", "orientation", "network", "integrity", "monitoring"}),
    "context": frozenset(PROJECTION_SECTIONS),
}
# The one section an agent may switch on or off independently of its profile.
# `list_comments` stays the complete authorized comment history; this section
# only carries the bounded newest-first preview a context read may embed.
ACTIVITY_SECTION = "activity"

PROJECTION_DESCRIPTION = (
    "Closed server-defined read profile. compact keeps identity, state, and the "
    "type-aware short fields; context adds network, integrity, monitoring, and "
    "the detail document; full is the unchanged complete contract."
)
FIELDS_DESCRIPTION = (
    "Closed server-defined field mask. It can only narrow the chosen profile; "
    "identity and state are always returned, so identities, revisions, "
    "visibility decisions, and effective permissions never depend on it."
)
RECENT_COMMENTS_DESCRIPTION = (
    "Explicitly include or exclude the bounded newest-first comment preview. "
    "Omit it to keep the profile default; list_comments remains the complete "
    "authorized comment history either way."
)


class ReadProjectionError(ValueError):
    """One rejected projection request. It never echoes the rejected value."""


@dataclass(frozen=True, slots=True)
class ReadProjection:
    """One resolved projection: the closed set of sections a read serializes."""

    profile: str
    surface: str
    sections: frozenset[str]

    def includes(self, section: str) -> bool:
        return section in self.sections

    @property
    def is_default(self) -> bool:
        """Whether this read is byte-for-byte the historical full contract.

        Asking for `full` without a mask resolves to the default, so an
        explicit default request stays indistinguishable from no request at
        all and no existing client sees a changed response.
        """
        return (
            self.profile == DEFAULT_PROJECTION_PROFILE
            and self.sections == _PROFILE_SECTIONS[DEFAULT_PROJECTION_PROFILE]
            & _SURFACE_SECTIONS[self.surface]
        )

    @property
    def deduplicates_capabilities(self) -> bool:
        """Whether a page envelope publishes one shared capability-set table.

        Only a non-default projection does. Deduplication never merges
        different effective rights: each distinct permission set keeps its own
        stable key.
        """
        return not self.is_default

    def descriptor(self) -> dict[str, Any]:
        """Return the echoed, versioned description of this resolved read."""
        return {
            "version": READ_PROJECTION_VERSION,
            "profile": self.profile,
            "sections": [*CORE_SECTIONS, *sorted(self.sections)],
        }


def resolve_read_projection(
    *,
    surface: str,
    profile: str | None = None,
    fields: list[str] | tuple[str, ...] | None = None,
    include_recent_comments: bool | None = None,
) -> ReadProjection:
    """Resolve one closed profile and field mask for one read surface.

    `fields` may only narrow: the result is the intersection of the profile,
    the surface, and the mask. `include_recent_comments` is the one explicit
    override, so a batch or discovery read never has to carry a comment
    preview it did not ask for.
    """
    if surface not in _SURFACE_SECTIONS:
        raise ReadProjectionError("unknown read projection surface")
    resolved_profile = DEFAULT_PROJECTION_PROFILE if profile is None else profile
    if resolved_profile not in _PROFILE_SECTIONS:
        raise ReadProjectionError("unknown read projection profile")

    sections = _PROFILE_SECTIONS[resolved_profile] & _SURFACE_SECTIONS[surface]
    if fields is not None:
        requested = frozenset(fields)
        unknown = requested - frozenset(PROJECTION_SECTIONS)
        if unknown:
            raise ReadProjectionError("unknown read projection field")
        sections &= requested
    if include_recent_comments is not None:
        sections = (
            sections | {ACTIVITY_SECTION}
            if include_recent_comments
            else sections - {ACTIVITY_SECTION}
        ) & _SURFACE_SECTIONS[surface]

    return ReadProjection(
        profile=resolved_profile,
        surface=surface,
        sections=frozenset(sections),
    )


DEFAULT_SUMMARY_PROJECTION = resolve_read_projection(surface="summary")
DEFAULT_CONTEXT_PROJECTION = resolve_read_projection(surface="context")

# One stable single-character code per registered permission. The key of a
# capability set is derived from its exact permissions in registry order, so
# two different effective permission sets can never collapse onto one key and
# a key means the same thing in every response.
_PERMISSION_CODES: dict[Permission, str] = {
    Permission.DISCOVER: "d",
    Permission.READ: "r",
    Permission.WRITE: "w",
    Permission.CREATE_CHILD: "c",
    Permission.MANAGE_ACCESS: "m",
    Permission.DELETE: "x",
}
EMPTY_CAPABILITY_SET_KEY = "cap-0"


def capability_set_key(permissions: Iterable[Permission]) -> str:
    """Return the stable deduplication key of one exact effective permission set."""
    present = {Permission(permission) for permission in permissions}
    unknown = present - set(_PERMISSION_CODES)
    if unknown:
        raise ReadProjectionError("unknown capability in a projected read")
    codes = "".join(
        code for permission, code in _PERMISSION_CODES.items() if permission in present
    )
    return f"cap-{codes}" if codes else EMPTY_CAPABILITY_SET_KEY


def capability_set_permissions(key: str) -> list[Permission]:
    """Return the exact permissions one capability-set key stands for."""
    if key == EMPTY_CAPABILITY_SET_KEY:
        return []
    codes = key.removeprefix("cap-")
    if key == codes or not codes:
        raise ReadProjectionError("invalid capability set key")
    by_code = {code: permission for permission, code in _PERMISSION_CODES.items()}
    if len(set(codes)) != len(codes) or any(code not in by_code for code in codes):
        raise ReadProjectionError("invalid capability set key")
    return [
        permission for permission, code in _PERMISSION_CODES.items() if code in codes
    ]
