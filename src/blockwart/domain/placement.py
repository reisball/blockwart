from collections.abc import Iterable, Mapping
from typing import Any

CANONICAL_PLACEMENT_RELATION_TYPE = "hosts"
SUPPORTED_PLACEMENT_PAIRS = {
    ("host", "system"),
    ("host", "service"),
    ("system", "service"),
}


class PlacementError(ValueError):
    """The stored asset placement cannot produce one canonical hierarchy."""


def validate_placement_pair(parent_kind: str, child_kind: str) -> None:
    if (parent_kind, child_kind) not in SUPPORTED_PLACEMENT_PAIRS:
        raise PlacementError(
            f"unsupported placement: {parent_kind} hosts {child_kind}"
        )


class PlacementGraph:
    """Read model for the canonical host → system → service hierarchy."""

    def __init__(
        self,
        objects: Iterable[Any],
        relationships: Iterable[Any],
    ) -> None:
        self.object_by_ref = {
            _object_ref(obj): obj
            for obj in objects
        }
        self._parents_by_ref: dict[str, list[str]] = {}
        self._children_by_ref: dict[str, list[str]] = {}
        for relationship in relationships:
            if (
                _record_value(relationship, "relation_type")
                != CANONICAL_PLACEMENT_RELATION_TYPE
            ):
                continue
            parent_ref = str(_record_value(relationship, "from_ref"))
            child_ref = str(_record_value(relationship, "to_ref"))
            parent = self.object_by_ref.get(parent_ref)
            child = self.object_by_ref.get(child_ref)
            if parent is None or child is None or parent_ref == child_ref:
                continue
            parent_kind = str(_record_value(parent, "kind"))
            child_kind = str(_record_value(child, "kind"))
            if (parent_kind, child_kind) not in SUPPORTED_PLACEMENT_PAIRS:
                continue
            _append_unique(self._parents_by_ref, child_ref, parent_ref)
            _append_unique(self._children_by_ref, parent_ref, child_ref)

        for refs in (
            *self._parents_by_ref.values(),
            *self._children_by_ref.values(),
        ):
            refs.sort()

    def parent_ref(self, object_ref: str) -> str | None:
        parents = self._parents_by_ref.get(object_ref, [])
        if len(parents) > 1:
            joined = ", ".join(parents)
            raise PlacementError(
                f"{object_ref} has multiple placement parents: {joined}"
            )
        return parents[0] if parents else None

    def parent_path_refs(self, object_ref: str) -> list[str]:
        path: list[str] = []
        seen = {object_ref}
        parent_ref = self.parent_ref(object_ref)
        while parent_ref is not None:
            if parent_ref in seen:
                raise PlacementError(f"placement cycle detected at {parent_ref}")
            path.append(parent_ref)
            seen.add(parent_ref)
            parent_ref = self.parent_ref(parent_ref)
        path.reverse()
        return path

    def children_refs(self, object_ref: str) -> list[str]:
        return list(self._children_by_ref.get(object_ref, []))


def _record_value(record: Any, field: str) -> Any:
    if isinstance(record, Mapping):
        return record[field]
    return getattr(record, field)


def _object_ref(obj: Any) -> str:
    return f"{_record_value(obj, 'kind')}:{_record_value(obj, 'id')}"


def _append_unique(target: dict[str, list[str]], key: str, value: str) -> None:
    values = target.setdefault(key, [])
    if value not in values:
        values.append(value)
