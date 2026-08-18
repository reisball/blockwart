"""Public projection of rejected catalog writes.

Every boundary publishes the same detail structure for a rejected object write:
the canonical public data path, one machine-readable violation code from
`blockwart.domain.object_schema`, the published schema rule when a
postcondition rejected the write, and the published description of that
violation. Rejected relationship commands use the same structure with the
canonical relationship paths of `blockwart.domain.relationships`. The domain
stays the single source of both the field rules and the violation catalog, so a
client can react to a rejected write without parsing any message.

Nothing else is projected. Rejected values, request inputs, Pydantic context,
exception text, internal types, and file paths never reach a client: an unknown
violation, an unknown rule, and an unparsable path each fall back to their safe
generic form instead of leaking the raw failure.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from blockwart.domain.object_schema import (
    GENERIC_SCHEMA_VIOLATION,
    PUBLIC_SCHEMA_RULE_CONTRACTS,
    SCHEMA_VIOLATION_CONTRACTS,
    VIOLATION_FIELD_NOT_ALLOWED,
    VIOLATION_INVALID_FORMAT,
    VIOLATION_REQUIRED_FIELD_MISSING,
    VIOLATION_TYPE_MISMATCH,
    VIOLATION_VALUE_NOT_ALLOWED,
    VIOLATION_VALUE_OUT_OF_RANGE,
    VIOLATION_VALUE_TOO_LONG,
    VIOLATION_VALUE_TOO_SHORT,
    ObjectSchemaError,
)
from blockwart.domain.relationships import (
    RELATIONSHIP_PATH_ROOTS,
    RelationshipIntegrityError,
)

PUBLIC_DETAIL_FIELDS: tuple[str, ...] = ("code", "location", "message", "path", "rule")
# One narrowly scoped extension of the published detail, used only for a
# rejected search page size. It adds the searched field name, the server-side
# allowed range, and the received value re-derived as a bounded integer. Every
# other rejection keeps exactly `PUBLIC_DETAIL_FIELDS`, so the global
# validation contract is not widened and no arbitrary input is echoed.
SEARCH_LIMIT_FIELD = "limit"
SEARCH_LIMIT_DETAIL_FIELDS: tuple[str, ...] = (
    *PUBLIC_DETAIL_FIELDS,
    "field",
    "maximum",
    "minimum",
    "received",
)
MAX_ECHOED_SCALAR = 1_000_000
_DETAIL_SORT_FIELDS: tuple[str, ...] = ("location", "path", "code", "rule")
DATA_PATH_ROOT = "data"
_BODY_LOCATION_ROOT = "body"
# The closed set of canonical roots a published path may start with: the
# catalog data document of an object write and the relationship command fields.
PUBLIC_PATH_ROOTS: tuple[str, ...] = (DATA_PATH_ROOT, *RELATIONSHIP_PATH_ROOTS)
UNKNOWN_LOCATION = "unknown"
MAX_PUBLIC_DETAILS = 20
_MAX_PATH_SEGMENTS = 12
_MAX_SCANNED_DETAILS = 64
_SEGMENT_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}(?:\[[0-9]{1,6}\])?$")
_BOUNDED_INTEGER_PATTERN = re.compile(r"^-?[0-9]{1,9}$")

# Boundary validation types mapped onto the published domain violations. Types
# without an entry fall back to the type-mismatch family or the generic
# violation, so a new upstream validation type can never publish an unreviewed
# code.
_PYDANTIC_VIOLATIONS: Mapping[str, str] = {
    "missing": VIOLATION_REQUIRED_FIELD_MISSING,
    "extra_forbidden": VIOLATION_FIELD_NOT_ALLOWED,
    "literal_error": VIOLATION_VALUE_NOT_ALLOWED,
    "enum": VIOLATION_VALUE_NOT_ALLOWED,
    "string_pattern_mismatch": VIOLATION_INVALID_FORMAT,
    "string_too_short": VIOLATION_VALUE_TOO_SHORT,
    "too_short": VIOLATION_VALUE_TOO_SHORT,
    "string_too_long": VIOLATION_VALUE_TOO_LONG,
    "too_long": VIOLATION_VALUE_TOO_LONG,
    "greater_than": VIOLATION_VALUE_OUT_OF_RANGE,
    "greater_than_equal": VIOLATION_VALUE_OUT_OF_RANGE,
    "less_than": VIOLATION_VALUE_OUT_OF_RANGE,
    "less_than_equal": VIOLATION_VALUE_OUT_OF_RANGE,
    "multiple_of": VIOLATION_VALUE_OUT_OF_RANGE,
}
_TYPE_MISMATCH_SUFFIXES = ("_type", "_parsing")


def violation_description(code: str) -> str:
    """Return the published description of one violation code."""
    return SCHEMA_VIOLATION_CONTRACTS.get(
        code,
        SCHEMA_VIOLATION_CONTRACTS[GENERIC_SCHEMA_VIOLATION],
    )


def public_violation(code: object) -> str:
    """Return a published violation code, or the generic one for anything else."""
    if isinstance(code, str) and code in SCHEMA_VIOLATION_CONTRACTS:
        return code
    return GENERIC_SCHEMA_VIOLATION


def public_rule(rule: object) -> str | None:
    """Return a published schema rule name, or None for anything else."""
    if isinstance(rule, str) and rule in PUBLIC_SCHEMA_RULE_CONTRACTS:
        return rule
    return None


def public_data_path(path: object) -> str | None:
    """Return the canonical public data path, truncated at the first odd segment.

    Only the fixed canonical path grammar is published: dotted keys with
    optional array indices below `data`. A path that starts elsewhere, or a
    segment carrying anything else, is dropped instead of being echoed back.
    """
    return public_path(path, roots=(DATA_PATH_ROOT,))


def public_path(
    path: object,
    *,
    roots: tuple[str, ...] = PUBLIC_PATH_ROOTS,
) -> str | None:
    """Return one canonical public path, truncated at the first odd segment.

    A path is published only when it starts at one of the closed published
    roots and every following segment uses the canonical grammar. Anything else
    is dropped instead of being echoed back.
    """
    if not isinstance(path, str):
        return None
    segments = path.split(".")
    if not segments or segments[0] not in roots:
        return None
    published = [segments[0]]
    for segment in segments[1:_MAX_PATH_SEGMENTS]:
        if not _SEGMENT_PATTERN.fullmatch(segment):
            break
        published.append(segment)
    return ".".join(published)


def public_location(location: object) -> str:
    """Return the boundary location of a rejected value in canonical form."""
    if not isinstance(location, str) or not location:
        return UNKNOWN_LOCATION
    published: list[str] = []
    for segment in location.split(".")[:_MAX_PATH_SEGMENTS]:
        if not _SEGMENT_PATTERN.fullmatch(segment):
            break
        published.append(segment)
    return ".".join(published) if published else UNKNOWN_LOCATION


def public_detail(
    *,
    location: object,
    code: object,
    path: object = None,
    rule: object = None,
) -> dict[str, str | None]:
    """Build one publishable violation detail with fixed, JSON-safe fields."""
    violation = public_violation(code)
    return {
        "code": violation,
        "location": public_location(location),
        "message": violation_description(violation),
        "path": public_path(path),
        "rule": public_rule(rule),
    }


def bounded_scalar(value: object) -> int | None:
    """Return one safely echoable integer, or ``None`` for anything else.

    Only a plain integer, or a compact decimal string of one, is echoed, and
    only while its magnitude stays inside the published bound. A float, a
    boolean, a long digit run, and any other rejected value are dropped rather
    than reflected back to the caller.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        candidate = value
    elif isinstance(value, str) and _BOUNDED_INTEGER_PATTERN.fullmatch(value.strip()):
        candidate = int(value.strip())
    else:
        return None
    return candidate if abs(candidate) <= MAX_ECHOED_SCALAR else None


def search_limit_detail(
    *,
    location: object,
    code: object,
    received: object,
    minimum: int,
    maximum: int,
) -> dict[str, str | int | None]:
    """Build the field-accurate detail of one rejected search page size."""
    detail: dict[str, str | int | None] = dict(
        public_detail(location=location, code=code)
    )
    detail["field"] = SEARCH_LIMIT_FIELD
    detail["minimum"] = minimum
    detail["maximum"] = maximum
    detail["received"] = bounded_scalar(received)
    return detail


def detail_from_relationship_error(
    error: RelationshipIntegrityError,
    *,
    location: str,
) -> dict[str, str | None]:
    """Project one field-attributable relationship rejection onto its public detail.

    Only a rejection the command payload alone decides carries a canonical
    relationship path and a published violation. A rejection that needed the
    stored catalog or the surrounding edge set has neither and stays a
    conflict, so it cannot become a probe for concealed state.
    """
    path = public_path(error.path, roots=RELATIONSHIP_PATH_ROOTS)
    root = public_location(location)
    return public_detail(
        location=root if path is None or root == UNKNOWN_LOCATION else f"{root}.{path}",
        code=error.violation,
        path=path,
    )


def detail_from_object_schema_error(
    error: ObjectSchemaError,
    *,
    location: str,
) -> dict[str, str | None]:
    """Project one domain schema rejection onto its public detail.

    The boundary location is extended by the canonical data path, so a client
    sees where the rejected value sits in its own request as well as which
    canonical field the domain rejected.
    """
    path = public_data_path(error.path)
    root = public_location(location)
    return public_detail(
        location=root if path is None or root == UNKNOWN_LOCATION else f"{root}.{path}",
        code=error.violation,
        path=error.path,
        rule=error.rule,
    )


def detail_from_validation_error(error: Mapping[str, Any]) -> dict[str, str | None]:
    """Project one Pydantic error dict onto its public detail.

    A domain rejection raised inside a validator keeps its canonical path and
    violation; every other validation type is mapped onto the published
    violation catalog without copying its message, context, or input.
    """
    location = ".".join(str(part) for part in error.get("loc", ())) or "body"
    cause = error.get("ctx", {}).get("error") if isinstance(error.get("ctx"), Mapping) else None
    if isinstance(cause, ObjectSchemaError):
        return detail_from_object_schema_error(cause, location=location)
    if isinstance(cause, RelationshipIntegrityError):
        return detail_from_relationship_error(cause, location=location)
    return public_detail(
        location=location,
        code=violation_for_validation_type(error.get("type")),
        path=relationship_path_from_location(location),
    )


def relationship_path_from_location(location: object) -> str | None:
    """Return the canonical relationship path a rejected request location names.

    A relationship command carries its canonical paths as request fields, so a
    boundary rejection inside `from_ref`, `relation_type`, `to_ref`, or
    `metadata` is published with the same path a domain rejection would use.
    Any other location keeps no path.
    """
    if not isinstance(location, str):
        return None
    segments = location.split(".")
    if segments and segments[0] == _BODY_LOCATION_ROOT:
        segments = segments[1:]
    if not segments or segments[0] not in RELATIONSHIP_PATH_ROOTS:
        return None
    return public_path(".".join(segments), roots=RELATIONSHIP_PATH_ROOTS)


def violation_for_validation_type(validation_type: object) -> str:
    """Map one boundary validation type onto a published violation code."""
    if not isinstance(validation_type, str):
        return GENERIC_SCHEMA_VIOLATION
    mapped = _PYDANTIC_VIOLATIONS.get(validation_type)
    if mapped is not None:
        return mapped
    if validation_type.endswith(_TYPE_MISMATCH_SUFFIXES):
        return VIOLATION_TYPE_MISMATCH
    return GENERIC_SCHEMA_VIOLATION


def sanitize_public_details(
    details: object,
    *,
    limit: int = MAX_PUBLIC_DETAILS,
) -> list[dict[str, str | int | None]]:
    """Re-derive publishable details from an untrusted structured error.

    Only a published violation code, a canonical path, and a published rule
    survive; the description is regenerated locally, so no upstream text is
    forwarded. Anything else is dropped.
    """
    if not isinstance(details, Sequence) or isinstance(details, (str, bytes)):
        return []
    published: list[dict[str, str | int | None]] = []
    for detail in details[:_MAX_SCANNED_DETAILS]:
        if not isinstance(detail, Mapping):
            continue
        code = detail.get("code")
        if not isinstance(code, str) or code not in SCHEMA_VIOLATION_CONTRACTS:
            continue
        republished: dict[str, str | int | None] = dict(
            public_detail(
                location=detail.get("location"),
                code=code,
                path=detail.get("path"),
                rule=detail.get("rule"),
            )
        )
        minimum = bounded_scalar(detail.get("minimum"))
        maximum = bounded_scalar(detail.get("maximum"))
        if (
            detail.get("field") == SEARCH_LIMIT_FIELD
            and minimum is not None
            and maximum is not None
        ):
            # The one narrowly scoped extension survives re-derivation, with
            # every value validated as a bounded integer here rather than
            # trusted from the upstream body.
            republished["field"] = SEARCH_LIMIT_FIELD
            republished["minimum"] = minimum
            republished["maximum"] = maximum
            republished["received"] = bounded_scalar(detail.get("received"))
        published.append(republished)
    return order_public_details(published, limit=limit)


def order_public_details[T: Mapping[str, Any]](
    details: Iterable[T],
    *,
    limit: int = MAX_PUBLIC_DETAILS,
) -> list[T]:
    """Return details in one stable order without repeating the same violation."""
    unique: dict[tuple[str, ...], T] = {}
    for detail in details:
        unique.setdefault(_sort_key(detail), detail)
    return [unique[key] for key in sorted(unique)[:limit]]


def _sort_key(detail: Mapping[str, Any]) -> tuple[str, ...]:
    return tuple(detail.get(field) or "" for field in _DETAIL_SORT_FIELDS)
