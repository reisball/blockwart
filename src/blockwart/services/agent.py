import json
from collections.abc import Mapping
from ipaddress import ip_address
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.orm import Session

from blockwart.domain.security import FORBIDDEN_SECRET_KEYS, looks_like_secret
from blockwart.models import CatalogObject, Relationship
from blockwart.schemas.agent import (
    AgentAssetNode,
    AgentCatalogObjectContext,
    AgentCatalogObjectSummary,
    AgentRelationshipOut,
)
from blockwart.schemas.catalog import ObjectKind

REDACTED = "[redacted-secret-field]"
PLACEMENT_RELATION_TYPES = {"hosts", "provides"}


def search_agent_objects(
    session: Session,
    *,
    query: str | None = None,
    kind: ObjectKind | None = None,
    parent: str | None = None,
    ip: str | None = None,
    port: int | None = None,
    status: str | None = None,
    lifecycle: str | None = None,
    health: str | None = None,
    limit: int = 10,
) -> list[AgentCatalogObjectSummary]:
    resolver = _AgentCatalogResolver(session)
    objects = resolver.search(
        query=query,
        kind=kind,
        parent=parent,
        ip=ip,
        port=port,
        status=status,
        lifecycle=lifecycle,
        health=health,
        limit=limit,
    )
    return [resolver.summary(obj) for obj in objects]


def get_agent_object_context(
    session: Session,
    object_id: str,
) -> AgentCatalogObjectContext | None:
    resolver = _AgentCatalogResolver(session)
    catalog_object = resolver.object_by_id.get(object_id)
    if catalog_object is None:
        return None
    return resolver.context(catalog_object)


def build_agent_context(
    session: Session,
    *,
    query: str | None = None,
    kind: ObjectKind | None = None,
    parent: str | None = None,
    ip: str | None = None,
    port: int | None = None,
    status: str | None = None,
    lifecycle: str | None = None,
    health: str | None = None,
    limit: int = 5,
) -> list[AgentCatalogObjectContext]:
    resolver = _AgentCatalogResolver(session)
    objects = resolver.search(
        query=query,
        kind=kind,
        parent=parent,
        ip=ip,
        port=port,
        status=status,
        lifecycle=lifecycle,
        health=health,
        limit=limit,
    )
    return [resolver.context(obj) for obj in objects]


class _AgentCatalogResolver:
    def __init__(self, session: Session) -> None:
        self.objects = list(
            session.scalars(
                select(CatalogObject).order_by(CatalogObject.kind, CatalogObject.label)
            ).all()
        )
        self.object_by_id = {obj.id: obj for obj in self.objects}
        self.object_by_ref = {_object_ref(obj): obj for obj in self.objects}
        self.relationships = list(
            session.scalars(
                select(Relationship).order_by(
                    Relationship.relation_type,
                    Relationship.from_ref,
                    Relationship.to_ref,
                )
            ).all()
        )
        self.parents_by_ref: dict[str, list[str]] = {}
        self.children_by_ref: dict[str, list[str]] = {}
        self._index_placements()

    def search(
        self,
        *,
        query: str | None,
        kind: ObjectKind | None,
        parent: str | None,
        ip: str | None,
        port: int | None,
        status: str | None,
        lifecycle: str | None,
        health: str | None,
        limit: int,
    ) -> list[CatalogObject]:
        matches: list[CatalogObject] = []
        query_term = query.casefold() if query else None
        for obj in self.objects:
            if kind and obj.kind != kind:
                continue
            if status and obj.status.casefold() != status.casefold():
                continue
            data = _safe_object_data(obj)
            if query_term and not _matches_query(obj, data, query_term):
                continue
            if lifecycle and not _matches_data_value(data, "lifecycle", lifecycle):
                continue
            if health and not _matches_data_value(data, "health", health):
                continue
            if parent and parent not in self.parent_path_refs(obj):
                continue
            if ip and ip not in self.resolved_ips(obj):
                continue
            if port is not None and port not in self.ports(obj):
                continue
            matches.append(obj)
            if len(matches) == limit:
                break
        return matches

    def summary(self, obj: CatalogObject) -> AgentCatalogObjectSummary:
        data = _safe_object_data(obj)
        parent_ref = self.canonical_parent_ref(obj)
        endpoints = self.endpoints(obj)
        return AgentCatalogObjectSummary(
            ref=_object_ref(obj),
            id=obj.id,
            kind=obj.kind,
            label=obj.label,
            status=obj.status,
            summary=obj.summary,
            parent=self.node(parent_ref) if parent_ref else None,
            ips=self.resolved_ips(obj),
            hostnames=self.resolved_hostnames(obj),
            primary_endpoint=endpoints[0] if endpoints else None,
            lifecycle=_optional_text(data.get("lifecycle")),
            health=_optional_text(data.get("health")),
        )

    def context(self, obj: CatalogObject) -> AgentCatalogObjectContext:
        data = _safe_object_data(obj)
        object_ref = _object_ref(obj)
        relationships = [
            AgentRelationshipOut(
                from_ref=row.from_ref,
                relation_type=row.relation_type,
                to_ref=row.to_ref,
            )
            for row in self.relationships
            if row.from_ref == object_ref or row.to_ref == object_ref
        ]
        return AgentCatalogObjectContext(
            **self.summary(obj).model_dump(),
            data=data,
            relationships=relationships,
            parent_path=[
                node
                for parent_ref in self.parent_path_refs(obj)
                if (node := self.node(parent_ref)) is not None
            ],
            children=[
                node
                for child_ref in self.children_by_ref.get(object_ref, [])
                if (node := self.node(child_ref)) is not None
            ],
            endpoints=self.endpoints(obj),
            source_references=[
                dict(reference) for reference in _mapping_list(data.get("source_references"))
            ],
            updated_at=obj.updated_at.isoformat() if obj.updated_at else None,
            dependencies=_dependencies(data),
            credential_references=sorted(_collect_credential_references(data)),
        )

    def node(self, object_ref: str) -> AgentAssetNode | None:
        obj = self.object_by_ref.get(object_ref)
        if obj is None:
            return None
        return AgentAssetNode(
            ref=object_ref,
            id=obj.id,
            kind=obj.kind,
            label=obj.label,
            status=obj.status,
        )

    def canonical_parent_ref(self, obj: CatalogObject) -> str | None:
        parents = self.parents_by_ref.get(_object_ref(obj), [])
        if not parents:
            return None
        preference = {"system": 0, "host": 1} if obj.kind == "service" else {"host": 0}
        return min(
            parents,
            key=lambda ref: (
                preference.get(_ref_kind(ref), 2),
                ref,
            ),
        )

    def parent_path_refs(self, obj: CatalogObject) -> list[str]:
        path: list[str] = []
        seen = {_object_ref(obj)}
        parent_ref = self.canonical_parent_ref(obj)
        while parent_ref and parent_ref not in seen:
            path.append(parent_ref)
            seen.add(parent_ref)
            parent = self.object_by_ref.get(parent_ref)
            parent_ref = self.canonical_parent_ref(parent) if parent is not None else None
        path.reverse()
        return path

    def endpoints(self, obj: CatalogObject) -> list[dict[str, Any]]:
        data = _safe_object_data(obj)
        endpoints: list[dict[str, Any]] = []
        for endpoint in _mapping_list(data.get("endpoints")):
            endpoints.append(_normalize_endpoint(endpoint, source="endpoint"))
        for access_method in _mapping_list(data.get("access_methods")):
            endpoint_url = access_method.get("endpoint")
            if not isinstance(endpoint_url, str) or not endpoint_url:
                continue
            endpoints.append(
                _normalize_endpoint(
                    {
                        "type": access_method.get("type"),
                        "url": endpoint_url,
                    },
                    source="access_method",
                )
            )
        return _unique_endpoints(endpoints)

    def resolved_ips(self, obj: CatalogObject) -> list[str]:
        own_ips = _object_ips(_safe_object_data(obj), self.endpoints(obj))
        if own_ips:
            return own_ips
        for parent_ref in reversed(self.parent_path_refs(obj)):
            parent = self.object_by_ref.get(parent_ref)
            if parent is None:
                continue
            parent_ips = _object_ips(_safe_object_data(parent), self.endpoints(parent))
            if parent_ips:
                return parent_ips
        return []

    def resolved_hostnames(self, obj: CatalogObject) -> list[str]:
        own_hostnames = _object_hostnames(_safe_object_data(obj), self.endpoints(obj))
        if own_hostnames:
            return own_hostnames
        for parent_ref in reversed(self.parent_path_refs(obj)):
            parent = self.object_by_ref.get(parent_ref)
            if parent is None:
                continue
            parent_hostnames = _object_hostnames(
                _safe_object_data(parent),
                self.endpoints(parent),
            )
            if parent_hostnames:
                return parent_hostnames
        return []

    def ports(self, obj: CatalogObject) -> set[int]:
        ports = {
            endpoint["port"]
            for endpoint in self.endpoints(obj)
            if isinstance(endpoint.get("port"), int)
        }
        for port_entry in _mapping_list(_safe_object_data(obj).get("ports")):
            port_value = port_entry.get("port")
            if isinstance(port_value, int) and not isinstance(port_value, bool):
                ports.add(port_value)
        return ports

    def _index_placements(self) -> None:
        for relationship in self.relationships:
            if relationship.relation_type not in PLACEMENT_RELATION_TYPES:
                continue
            self._add_placement(relationship.from_ref, relationship.to_ref)

        for obj in self.objects:
            if obj.kind != "service":
                continue
            system_ref = _safe_object_data(obj).get("system_id")
            if isinstance(system_ref, str):
                self._add_placement(system_ref, _object_ref(obj))

        for refs in (*self.parents_by_ref.values(), *self.children_by_ref.values()):
            refs.sort()

    def _add_placement(self, parent_ref: str, child_ref: str) -> None:
        parent = self.object_by_ref.get(parent_ref)
        child = self.object_by_ref.get(child_ref)
        if parent is None or child is None or parent_ref == child_ref:
            return
        if parent.kind not in {"host", "system"} or child.kind not in {"system", "service"}:
            return
        _append_unique(self.parents_by_ref, child_ref, parent_ref)
        _append_unique(self.children_by_ref, parent_ref, child_ref)


def _safe_object_data(obj: CatalogObject) -> dict[str, Any]:
    try:
        data = json.loads(obj.data_json)
    except (TypeError, json.JSONDecodeError):
        return {}
    sanitized = _sanitize_for_agent(data)
    return sanitized if isinstance(sanitized, dict) else {}


def _matches_query(obj: CatalogObject, data: Mapping[str, Any], query_term: str) -> bool:
    values = [obj.id, obj.label, obj.summary or "", json.dumps(data, sort_keys=True)]
    return any(query_term in value.casefold() for value in values)


def _matches_data_value(data: Mapping[str, Any], key: str, expected: str) -> bool:
    value = data.get(key)
    return isinstance(value, str) and value.casefold() == expected.casefold()


def _object_ref(obj: CatalogObject) -> str:
    return f"{obj.kind}:{obj.id}"


def _ref_kind(value: str) -> str:
    return value.split(":", 1)[0]


def _optional_text(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _mapping_list(value: Any) -> list[Mapping[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, Mapping)]


def _dependencies(data: Mapping[str, Any]) -> dict[str, list[str]]:
    dependencies = data.get("dependencies")
    if not isinstance(dependencies, Mapping):
        return {}
    resolved: dict[str, list[str]] = {}
    for direction in ("upstream", "downstream"):
        references = dependencies.get(direction)
        if isinstance(references, list):
            resolved[direction] = [ref for ref in references if isinstance(ref, str)]
    return resolved


def _normalize_endpoint(endpoint: Mapping[str, Any], *, source: str) -> dict[str, Any]:
    normalized = {
        str(key): value
        for key, value in endpoint.items()
        if value is not None and key not in FORBIDDEN_SECRET_KEYS
    }
    normalized["source"] = source
    url = normalized.get("url")
    if isinstance(url, str):
        try:
            parsed = urlsplit(url)
            if parsed.hostname and "host" not in normalized:
                normalized["host"] = parsed.hostname
            if parsed.port is not None and "port" not in normalized:
                normalized["port"] = parsed.port
            if parsed.scheme and "protocol" not in normalized:
                normalized["protocol"] = parsed.scheme
            if parsed.path and parsed.path != "/" and "path" not in normalized:
                normalized["path"] = parsed.path
        except ValueError:
            pass
    return normalized


def _unique_endpoints(endpoints: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique: list[dict[str, Any]] = []
    seen: set[str] = set()
    for endpoint in endpoints:
        fingerprint = json.dumps(endpoint, sort_keys=True)
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        unique.append(endpoint)
    return unique


def _object_ips(data: Mapping[str, Any], endpoints: list[dict[str, Any]]) -> list[str]:
    candidates: list[Any] = []
    network = data.get("network")
    if isinstance(network, Mapping):
        candidates.extend(
            address.get("ip") for address in _mapping_list(network.get("addresses"))
        )
    candidates.extend(endpoint.get("host") for endpoint in endpoints)
    return _unique_strings(value for value in candidates if _is_ip(value))


def _object_hostnames(data: Mapping[str, Any], endpoints: list[dict[str, Any]]) -> list[str]:
    candidates: list[Any] = []
    network = data.get("network")
    if isinstance(network, Mapping):
        hostnames = network.get("hostnames")
        if isinstance(hostnames, list):
            candidates.extend(hostnames)
    candidates.extend(endpoint.get("host") for endpoint in endpoints)
    return _unique_strings(
        value for value in candidates if isinstance(value, str) and not _is_ip(value)
    )


def _is_ip(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        ip_address(value)
    except ValueError:
        return False
    return True


def _unique_strings(values: Any) -> list[str]:
    unique: list[str] = []
    for value in values:
        if isinstance(value, str) and value not in unique:
            unique.append(value)
    return unique


def _append_unique(target: dict[str, list[str]], key: str, value: str) -> None:
    values = target.setdefault(key, [])
    if value not in values:
        values.append(value)


def _sanitize_for_agent(value: Any) -> Any:
    if isinstance(value, Mapping):
        safe: dict[str, Any] = {}
        for key, child in value.items():
            key_text = str(key)
            if key_text.lower() in FORBIDDEN_SECRET_KEYS:
                safe[key_text] = REDACTED
                continue
            safe[key_text] = _sanitize_for_agent(child)
        return safe
    if isinstance(value, list):
        return [_sanitize_for_agent(item) for item in value]
    if isinstance(value, str) and looks_like_secret(value):
        return REDACTED
    return value


def _collect_credential_references(value: Any) -> set[str]:
    references: set[str] = set()
    if isinstance(value, Mapping):
        for key, child in value.items():
            if key == "credential_references" and isinstance(child, list):
                references.update(item for item in child if _is_credential_reference(item))
            elif _is_credential_reference(child):
                references.add(child)
            references.update(_collect_credential_references(child))
    elif isinstance(value, list):
        for item in value:
            if _is_credential_reference(item):
                references.add(item)
            references.update(_collect_credential_references(item))
    return references


def _is_credential_reference(value: Any) -> bool:
    return isinstance(value, str) and value.startswith("credential_reference:")
