"""Canonical service-local component and dependency contract.

Components are embedded business data of one ``service`` catalog object.  They
never receive catalog identities, grants, lifecycle, health, placement, or
independent audit records.  A local dependency means that ``component_id``
depends on ``depends_on``; this deliberately mirrors the direction of the
global ``depends_on`` relationship without sharing its storage namespace.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from typing import Any

SERVICE_COMPONENT_ROLE_VALUES = (
    "application",
    "api",
    "database",
    "worker",
    "cache",
    "queue",
    "other",
)
SERVICE_COMPONENT_ROLES = frozenset(SERVICE_COMPONENT_ROLE_VALUES)
MAX_SERVICE_COMPONENTS = 100
MAX_SERVICE_COMPONENT_DEPENDENCIES = 400
MAX_SERVICE_COMPONENT_TRAVERSAL_NODES = MAX_SERVICE_COMPONENTS
MAX_SERVICE_COMPONENT_TRAVERSAL_EDGES = MAX_SERVICE_COMPONENT_DEPENDENCIES
SERVICE_COMPONENT_ID_PATTERN = r"^[a-z0-9](?:[a-z0-9_-]{0,62}[a-z0-9])?$"
_COMPONENT_ID_RE = re.compile(SERVICE_COMPONENT_ID_PATTERN)

COMPONENT_DOCUMENT_KEYS = frozenset({"items", "dependencies"})
COMPONENT_ITEM_KEYS = frozenset({"id", "name", "role", "description"})
COMPONENT_DEPENDENCY_KEYS = frozenset(
    {"component_id", "depends_on", "description"}
)


@dataclass(frozen=True, slots=True)
class ServiceComponentViolation:
    path: str
    message: str
    violation: str


def normalize_service_components(data: Mapping[str, Any]) -> dict[str, Any]:
    """Return data with canonical component whitespace and ordering.

    Invalid shapes are left structurally intact for the schema validator to
    reject with an exact field path.  No item or edge is silently removed.
    """

    normalized = deepcopy(dict(data))
    document = normalized.get("components")
    if not isinstance(document, dict):
        return normalized

    items = document.get("items")
    if isinstance(items, list):
        for item in items:
            if not isinstance(item, dict):
                continue
            for field in ("id", "name", "description"):
                if isinstance(item.get(field), str):
                    item[field] = item[field].strip()
        if all(isinstance(item, Mapping) for item in items):
            items.sort(
                key=lambda item: (
                    str(item.get("id", "")),
                    str(item.get("name", "")),
                    str(item.get("role", "")),
                    str(item.get("description", "")),
                )
            )

    dependencies = document.get("dependencies")
    if isinstance(dependencies, list):
        for dependency in dependencies:
            if not isinstance(dependency, dict):
                continue
            for field in ("component_id", "depends_on", "description"):
                if isinstance(dependency.get(field), str):
                    dependency[field] = dependency[field].strip()
        if all(isinstance(dependency, Mapping) for dependency in dependencies):
            dependencies.sort(
                key=lambda dependency: (
                    str(dependency.get("component_id", "")),
                    str(dependency.get("depends_on", "")),
                    str(dependency.get("description", "")),
                )
            )
    return normalized


def service_component_violations(
    data: Mapping[str, Any],
) -> tuple[ServiceComponentViolation, ...]:
    """Return graph-level violations after declarative field validation."""

    document = data.get("components")
    if document is None or not isinstance(document, Mapping):
        return ()
    for required_key in ("items", "dependencies"):
        if required_key not in document:
            return (
                ServiceComponentViolation(
                    f"data.components.{required_key}",
                    "is required when data.components is present",
                    "value_not_allowed",
                ),
            )

    raw_items = document.get("items")
    raw_dependencies = document.get("dependencies")
    if not isinstance(raw_items, list) or not isinstance(raw_dependencies, list):
        return ()

    component_ids: set[str] = set()
    for index, item in enumerate(raw_items):
        if not isinstance(item, Mapping):
            continue
        component_id = item.get("id")
        if not isinstance(component_id, str):
            continue
        if _COMPONENT_ID_RE.fullmatch(component_id) is None:
            return (
                ServiceComponentViolation(
                    f"data.components.items[{index}].id",
                    "must be a lowercase local id using letters, digits, '_' or '-'",
                    "value_not_allowed",
                ),
            )
        if component_id in component_ids:
            return (
                ServiceComponentViolation(
                    f"data.components.items[{index}].id",
                    "repeats an earlier component id",
                    "value_not_allowed",
                ),
            )
        component_ids.add(component_id)

    dependency_pairs: set[tuple[str, str]] = set()
    for index, dependency in enumerate(raw_dependencies):
        if not isinstance(dependency, Mapping):
            continue
        source = dependency.get("component_id")
        target = dependency.get("depends_on")
        if not isinstance(source, str) or not isinstance(target, str):
            continue
        if _COMPONENT_ID_RE.fullmatch(source) is None:
            return (
                ServiceComponentViolation(
                    f"data.components.dependencies[{index}].component_id",
                    "must be a valid local component id",
                    "value_not_allowed",
                ),
            )
        if _COMPONENT_ID_RE.fullmatch(target) is None:
            return (
                ServiceComponentViolation(
                    f"data.components.dependencies[{index}].depends_on",
                    "must be a valid local component id",
                    "value_not_allowed",
                ),
            )
        if source == target:
            return (
                ServiceComponentViolation(
                    f"data.components.dependencies[{index}].depends_on",
                    "must not reference the same component",
                    "value_not_allowed",
                ),
            )
        if source not in component_ids:
            return (
                ServiceComponentViolation(
                    f"data.components.dependencies[{index}].component_id",
                    "must reference a component in this service",
                    "value_not_allowed",
                ),
            )
        if target not in component_ids:
            return (
                ServiceComponentViolation(
                    f"data.components.dependencies[{index}].depends_on",
                    "must reference a component in this service",
                    "value_not_allowed",
                ),
            )
        pair = (source, target)
        if pair in dependency_pairs:
            return (
                ServiceComponentViolation(
                    f"data.components.dependencies[{index}].depends_on",
                    "repeats an earlier directed dependency",
                    "value_not_allowed",
                ),
            )
        dependency_pairs.add(pair)
    return ()


def service_components_view(data: Mapping[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Return the bounded canonical view used by UI/read projections."""

    normalized = normalize_service_components(data)
    document = normalized.get("components")
    if not isinstance(document, Mapping):
        return {"items": [], "dependencies": []}
    items = document.get("items")
    dependencies = document.get("dependencies")
    return {
        "items": [dict(item) for item in items if isinstance(item, Mapping)]
        if isinstance(items, list)
        else [],
        "dependencies": [
            dict(dependency)
            for dependency in dependencies
            if isinstance(dependency, Mapping)
        ]
        if isinstance(dependencies, list)
        else [],
    }


def put_service_component(
    data: Mapping[str, Any],
    *,
    component_id: str,
    name: str,
    role: str,
    description: str,
    previous_id: str | None = None,
) -> dict[str, Any]:
    """Add or replace one component, renaming incident local references."""

    updated = _editable_document(data)
    document = updated["components"]
    items = document["items"]
    dependencies = document["dependencies"]
    lookup_id = previous_id or component_id
    replacement = {
        "id": component_id,
        "name": name,
        "role": role,
        "description": description,
    }
    match = next(
        (index for index, item in enumerate(items) if item.get("id") == lookup_id),
        None,
    )
    if previous_id is not None and match is None:
        raise ValueError("component to edit does not exist")
    if match is None:
        items.append(replacement)
    else:
        items[match] = replacement
    if lookup_id != component_id:
        for dependency in dependencies:
            if dependency.get("component_id") == lookup_id:
                dependency["component_id"] = component_id
            if dependency.get("depends_on") == lookup_id:
                dependency["depends_on"] = component_id
    return normalize_service_components(updated)


def remove_service_component(data: Mapping[str, Any], *, component_id: str) -> dict[str, Any]:
    """Remove one component and its now-invalid incident dependencies."""

    updated = _editable_document(data)
    document = updated["components"]
    items = document["items"]
    if not any(item.get("id") == component_id for item in items):
        raise ValueError("component to remove does not exist")
    document["items"] = [item for item in items if item.get("id") != component_id]
    document["dependencies"] = [
        dependency
        for dependency in document["dependencies"]
        if dependency.get("component_id") != component_id
        and dependency.get("depends_on") != component_id
    ]
    return normalize_service_components(updated)


def put_service_component_dependency(
    data: Mapping[str, Any],
    *,
    component_id: str,
    depends_on: str,
    description: str | None = None,
) -> dict[str, Any]:
    """Add or replace one directed local dependency."""

    updated = _editable_document(data)
    dependencies = updated["components"]["dependencies"]
    replacement: dict[str, str] = {
        "component_id": component_id,
        "depends_on": depends_on,
    }
    if description is not None and description.strip():
        replacement["description"] = description
    match = next(
        (
            index
            for index, dependency in enumerate(dependencies)
            if dependency.get("component_id") == component_id
            and dependency.get("depends_on") == depends_on
        ),
        None,
    )
    if match is None:
        dependencies.append(replacement)
    else:
        dependencies[match] = replacement
    return normalize_service_components(updated)


def remove_service_component_dependency(
    data: Mapping[str, Any],
    *,
    component_id: str,
    depends_on: str,
) -> dict[str, Any]:
    updated = _editable_document(data)
    dependencies = updated["components"]["dependencies"]
    kept = [
        dependency
        for dependency in dependencies
        if not (
            dependency.get("component_id") == component_id
            and dependency.get("depends_on") == depends_on
        )
    ]
    if len(kept) == len(dependencies):
        raise ValueError("component dependency to remove does not exist")
    updated["components"]["dependencies"] = kept
    return normalize_service_components(updated)


def service_component_contract_projection() -> dict[str, Any]:
    return {
        "storage_path": "data.components",
        "identity_scope": "parent_service",
        "roles": list(SERVICE_COMPONENT_ROLE_VALUES),
        "dependency_direction": "component_id depends_on depends_on",
        "cross_service_references_allowed": False,
        "self_references_allowed": False,
        "duplicate_component_ids_allowed": False,
        "duplicate_dependency_pairs_allowed": False,
        "cycles": {
            "allowed": True,
            "reason": "Matches the generic global depends_on graph semantics.",
        },
        "limits": {
            "components": MAX_SERVICE_COMPONENTS,
            "dependencies": MAX_SERVICE_COMPONENT_DEPENDENCIES,
            "traversal_nodes": MAX_SERVICE_COMPONENT_TRAVERSAL_NODES,
            "traversal_edges": MAX_SERVICE_COMPONENT_TRAVERSAL_EDGES,
        },
        "local_id": {
            "max_length": 64,
            "pattern": SERVICE_COMPONENT_ID_PATTERN,
        },
        "deterministic_order": {
            "items": ["id", "name", "role", "description"],
            "dependencies": ["component_id", "depends_on", "description"],
        },
        "inheritance": {
            "visibility": True,
            "rbac": True,
            "revision": True,
            "etag_cas": True,
            "audit": True,
            "lifecycle": True,
            "independent_identity_or_grants": False,
        },
    }


def _editable_document(data: Mapping[str, Any]) -> dict[str, Any]:
    updated = deepcopy(dict(data))
    document = updated.get("components")
    if document is None:
        updated["components"] = {"items": [], "dependencies": []}
        return updated
    if not isinstance(document, Mapping):
        raise ValueError("service component document is invalid")
    items = document.get("items")
    dependencies = document.get("dependencies")
    if not isinstance(items, list) or not isinstance(dependencies, list):
        raise ValueError("service component document is invalid")
    if not all(isinstance(item, Mapping) for item in items):
        raise ValueError("service component document is invalid")
    if not all(isinstance(item, Mapping) for item in dependencies):
        raise ValueError("service component document is invalid")
    updated["components"] = {
        "items": [dict(item) for item in items],
        "dependencies": [dict(item) for item in dependencies],
    }
    return updated
