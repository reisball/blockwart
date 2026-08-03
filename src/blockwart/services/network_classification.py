from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session
from yaml.constructor import ConstructorError
from yaml.nodes import MappingNode

from blockwart.domain.object_schema import (
    NETWORK_CATEGORIES,
    ObjectSchemaError,
    validate_object_data,
)
from blockwart.models import CatalogObject


class NetworkClassificationError(ValueError):
    pass


class _UniqueKeySafeLoader(yaml.SafeLoader):
    def construct_mapping(self, node: MappingNode, deep: bool = False) -> dict[Any, Any]:
        self.flatten_mapping(node)
        mapping: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                duplicate = key in mapping
            except TypeError as exc:
                raise ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    "found an unhashable mapping key",
                    key_node.start_mark,
                ) from exc
            if duplicate:
                raise ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    f"found duplicate key {key!r}",
                    key_node.start_mark,
                )
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


@dataclass(frozen=True, slots=True)
class NetworkClassificationEvidence:
    object_id: str
    target_category: str
    evidence_source: str


@dataclass(frozen=True, slots=True)
class NetworkClassificationEntry:
    object_ref: str
    label: str
    current_category: str | None
    target_category: str | None
    evidence_source: str | None
    action: Literal["none", "set_category", "replace_category", "blocked"]
    blockers: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class NetworkClassificationPlan:
    entries: tuple[NetworkClassificationEntry, ...]
    diagnostics: tuple[str, ...]

    @property
    def scanned_networks(self) -> int:
        return len(self.entries)

    @property
    def changed_networks(self) -> int:
        return sum(entry.action in {"set_category", "replace_category"} for entry in self.entries)

    @property
    def blocked_networks(self) -> int:
        return sum(bool(entry.blockers) for entry in self.entries)


def load_network_classification_evidence(
    path: str | Path,
) -> dict[str, NetworkClassificationEvidence]:
    source_path = Path(path)
    try:
        payload = yaml.load(
            source_path.read_text(encoding="utf-8"),
            Loader=_UniqueKeySafeLoader,
        )
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise NetworkClassificationError("network mapping file is invalid") from exc
    if not isinstance(payload, Mapping) or set(payload) != {"schema_version", "networks"}:
        raise NetworkClassificationError(
            "network mapping must contain only schema_version and networks"
        )
    schema_version = payload.get("schema_version")
    if (
        type(schema_version) is not int
        or schema_version != 1
        or not isinstance(payload.get("networks"), list)
    ):
        raise NetworkClassificationError("network mapping schema is invalid")

    evidence: dict[str, NetworkClassificationEvidence] = {}
    for index, raw_entry in enumerate(payload["networks"]):
        if not isinstance(raw_entry, Mapping) or set(raw_entry) != {
            "object_id",
            "target_category",
            "evidence_source",
        }:
            raise NetworkClassificationError(
                f"network mapping entry {index} has invalid fields"
            )
        object_id = raw_entry.get("object_id")
        target_category = raw_entry.get("target_category")
        evidence_source = raw_entry.get("evidence_source")
        if not isinstance(object_id, str) or not object_id.strip():
            raise NetworkClassificationError(
                f"network mapping entry {index} has invalid object_id"
            )
        if (
            not isinstance(target_category, str)
            or target_category not in NETWORK_CATEGORIES
        ):
            raise NetworkClassificationError(
                f"network mapping entry {index} has invalid target_category"
            )
        if not isinstance(evidence_source, str) or not evidence_source.strip():
            raise NetworkClassificationError(
                f"network mapping entry {index} has invalid evidence_source"
            )
        normalized_id = object_id.strip()
        if normalized_id in evidence:
            raise NetworkClassificationError(
                f"network mapping contains duplicate object_id {normalized_id}"
            )
        evidence[normalized_id] = NetworkClassificationEvidence(
            object_id=normalized_id,
            target_category=str(target_category),
            evidence_source=evidence_source.strip(),
        )
    return evidence


def build_network_classification_plan(
    session: Session,
    evidence: Mapping[str, NetworkClassificationEvidence] | None = None,
) -> NetworkClassificationPlan:
    evidence = dict(evidence or {})
    rows = session.scalars(
        select(CatalogObject)
        .where(CatalogObject.kind == "network")
        .order_by(CatalogObject.id)
    ).all()
    known_ids = {row.id for row in rows}
    diagnostics = tuple(
        f"unknown_mapping_ref:network:{object_id}"
        for object_id in sorted(set(evidence) - known_ids)
    )
    entries = tuple(_classification_entry(row, evidence.get(row.id)) for row in rows)
    return NetworkClassificationPlan(entries=entries, diagnostics=diagnostics)


def classification_entry_payload(entry: NetworkClassificationEntry) -> dict[str, Any]:
    return {
        "object_ref": entry.object_ref,
        "label": entry.label,
        "current_category": entry.current_category,
        "target_category": entry.target_category,
        "evidence_source": entry.evidence_source,
        "action": entry.action,
        "blockers": list(entry.blockers),
    }


def _classification_entry(
    row: CatalogObject,
    evidence: NetworkClassificationEvidence | None,
) -> NetworkClassificationEntry:
    blockers: list[str] = []
    try:
        raw_data = json.loads(row.data_json)
    except (TypeError, json.JSONDecodeError):
        raw_data = None
        blockers.append("invalid_data_json")

    if isinstance(raw_data, Mapping):
        try:
            validate_object_data(
                "network",
                raw_data,
                allow_legacy_network_without_category=True,
            )
        except ObjectSchemaError:
            blockers.append("invalid_network_data")
    elif "invalid_data_json" not in blockers:
        blockers.append("invalid_network_data")

    network = raw_data.get("network") if isinstance(raw_data, Mapping) else None
    raw_category = network.get("category") if isinstance(network, Mapping) else None
    current_category = raw_category if isinstance(raw_category, str) else None
    if raw_category is not None and not isinstance(raw_category, str):
        blockers.append("invalid_current_category_type")

    if evidence is None:
        if current_category in NETWORK_CATEGORIES:
            target_category = current_category
            evidence_source = "catalog:data.network.category"
            action: Literal["none", "set_category", "replace_category", "blocked"] = "none"
        else:
            target_category = None
            evidence_source = None
            blockers.append(
                "missing_category_evidence"
                if current_category is None
                else "unknown_current_category"
            )
            action = "blocked"
    else:
        target_category = evidence.target_category
        evidence_source = evidence.evidence_source
        if blockers:
            action = "blocked"
        elif current_category == target_category:
            action = "none"
        elif current_category is None:
            action = "set_category"
        else:
            action = "replace_category"

    if blockers:
        action = "blocked"
    return NetworkClassificationEntry(
        object_ref=f"network:{row.id}",
        label=row.label,
        current_category=current_category,
        target_category=target_category,
        evidence_source=evidence_source,
        action=action,
        blockers=tuple(sorted(set(blockers))),
    )
