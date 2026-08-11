"""Canonical source-coverage vocabulary, fingerprints, and drift resolver.

This module is the single domain implementation shared by the Markdown
collector/dry-run and the runtime read surfaces. API, MCP, and CLI layers
project it; none of them re-implements a near-duplicate rule.

Trust boundary: nothing here reads a file, a database, or the network. It
operates on an already-collected, sanitized snapshot. No secret value,
credential, source excerpt, or arbitrary private file content is representable
in the model: an entry carries a stable URI, an optional stable entry ID, a
controlled classification, a controlled decision reason, opaque fingerprints,
and timestamps. Coverage means the *inventory* of a source entry is accounted
for; it never means the referenced content is stored.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal, get_args
from urllib.parse import urlsplit

from blockwart.domain.security import find_secret_violations

SourceClassification = Literal[
    "operational",
    "retired",
    "historical",
    "research",
    "migration",
    "generated",
    "ignored",
]
SOURCE_CLASSIFICATIONS: tuple[SourceClassification, ...] = get_args(SourceClassification)

CoverageState = Literal[
    "mapped_current",
    "mapped_stale",
    "unmapped_operational",
    "intentionally_unmapped",
    "orphaned_catalog_reference",
    "missing_source",
    "ambiguous_mapping",
    "duplicate_mapping",
    "source_changed_since_import",
]
COVERAGE_STATES: tuple[CoverageState, ...] = get_args(CoverageState)

MappingIntent = Literal["expect_object", "no_catalog_object"]
MAPPING_INTENTS: tuple[MappingIntent, ...] = get_args(MappingIntent)

MappingRole = Literal["primary", "derived"]
MAPPING_ROLES: tuple[MappingRole, ...] = get_args(MappingRole)

EntryPresence = Literal["present", "absent"]
ENTRY_PRESENCES: tuple[EntryPresence, ...] = get_args(EntryPresence)

# Decision reasons are a closed controlled vocabulary rather than free text.
# A collector can therefore never smuggle a source excerpt, a private path, or
# a credential hint into an audibly persisted "reason".
DecisionReason = Literal[
    "operational_inventory",
    "retired_asset",
    "historical_record",
    "research_material",
    "migration_artifact",
    "generated_artifact",
    "explicitly_ignored",
    "not_infrastructure",
    "unclassified",
]
DECISION_REASONS: tuple[DecisionReason, ...] = get_args(DecisionReason)

# The intent and reason a classification implies unless a collector states an
# explicit, audible exception. Only `operational` rows are expected to become
# catalog objects; every other classification is intentionally unmapped.
CLASSIFICATION_DEFAULTS: Mapping[SourceClassification, tuple[MappingIntent, DecisionReason]] = {
    "operational": ("expect_object", "operational_inventory"),
    "retired": ("no_catalog_object", "retired_asset"),
    "historical": ("no_catalog_object", "historical_record"),
    "research": ("no_catalog_object", "research_material"),
    "migration": ("no_catalog_object", "migration_artifact"),
    "generated": ("no_catalog_object", "generated_artifact"),
    "ignored": ("no_catalog_object", "explicitly_ignored"),
}

# States that can exist without any authorizable catalog object. They are
# source-only facts and are published exclusively through the elevated
# operations authority.
SOURCE_ONLY_STATES: frozenset[str] = frozenset(
    {
        "unmapped_operational",
        "intentionally_unmapped",
        "orphaned_catalog_reference",
        "missing_source",
    }
)

MAX_SOURCE_URI_LENGTH = 512
MAX_ENTRY_ID_LENGTH = 256
MAX_SNAPSHOT_ENTRIES = 5000
MAX_MAPPINGS_PER_ENTRY = 100
MAX_SNAPSHOT_MAPPINGS = 10000
FINGERPRINT_LENGTH = 64
COLLECTOR_MARKDOWN_TOOLS = "markdown_tools"

_SOURCE_URI_PATTERN = re.compile(r"^[a-z][a-z0-9+.-]*:[A-Za-z0-9._~!$&'()*+,;=:@/%-]{1,500}$")
_ENTRY_ID_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._:/-]*[A-Za-z0-9])?$")
_FINGERPRINT_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_COLLECTOR_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
_OBJECT_ID_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?$")


class SourceCoverageError(ValueError):
    """A snapshot violates the canonical source-coverage contract."""


@dataclass(frozen=True, slots=True)
class SourceMapping:
    """One explicit many-to-many edge between a source entry and an object.

    The registry is this edge, never ``CatalogProvenance.source_ref``. Object
    provenance keeps describing where an object came from; this table records
    which source entries are considered covered by which catalog objects.
    """

    object_id: str
    role: MappingRole = "primary"
    imported_entry_fingerprint: str = ""
    imported_at: str | None = None
    verified_at: str | None = None


@dataclass(frozen=True, slots=True)
class SourceEntry:
    """One configured, sanitized source entry inside a snapshot."""

    source_uri: str
    entry_id: str | None
    classification: SourceClassification
    intent: MappingIntent
    decision_reason: DecisionReason
    entry_fingerprint: str
    source_fingerprint: str
    observed_at: str
    presence: EntryPresence = "present"
    mappings: tuple[SourceMapping, ...] = ()

    @property
    def key(self) -> tuple[str, str]:
        return (self.source_uri, self.entry_id or "")


@dataclass(frozen=True, slots=True)
class SourceSnapshot:
    """One deterministic, digest-bound collection result."""

    collector: str
    collected_at: str
    entries: tuple[SourceEntry, ...]
    digest: str = ""

    def with_digest(self) -> SourceSnapshot:
        return SourceSnapshot(
            collector=self.collector,
            collected_at=self.collected_at,
            entries=self.entries,
            digest=snapshot_digest(self.collector, self.collected_at, self.entries),
        )

    @property
    def source_uris(self) -> tuple[str, ...]:
        return tuple(sorted({entry.source_uri for entry in self.entries}))


@dataclass(frozen=True, slots=True)
class CatalogTarget:
    """The catalog-side facts the resolver needs about one mapped object."""

    object_id: str
    kind: str
    exists: bool
    is_stale: bool


@dataclass(frozen=True, slots=True)
class CoverageMapping:
    """One resolved mapping projected next to its coverage detail."""

    object_id: str
    target_kind: str | None
    role: MappingRole
    exists: bool
    source_changed: bool
    imported_at: str | None
    verified_at: str | None


@dataclass(frozen=True, slots=True)
class CoverageDetail:
    """One resolved coverage row for exactly one source entry."""

    source_uri: str
    entry_id: str | None
    classification: SourceClassification
    intent: MappingIntent
    decision_reason: DecisionReason
    state: CoverageState
    presence: EntryPresence
    entry_fingerprint: str
    source_fingerprint: str
    observed_at: str
    mappings: tuple[CoverageMapping, ...] = ()

    @property
    def key(self) -> tuple[str, str]:
        return (self.source_uri, self.entry_id or "")

    @property
    def target_kinds(self) -> frozenset[str]:
        return frozenset(
            mapping.target_kind
            for mapping in self.mappings
            if mapping.exists and mapping.target_kind is not None
        )


@dataclass(frozen=True, slots=True)
class CoverageSummary:
    """Aggregated counts over exactly one authorized detail set."""

    total: int
    by_state: dict[str, int] = field(default_factory=dict)
    by_classification: dict[str, int] = field(default_factory=dict)


def normalize_source_uri(value: str) -> str:
    """Validate one stable, scheme-qualified source URI."""
    normalized = value.strip()
    if not normalized or len(normalized) > MAX_SOURCE_URI_LENGTH:
        raise SourceCoverageError("source URI must be 1..512 characters")
    if not _SOURCE_URI_PATTERN.fullmatch(normalized):
        raise SourceCoverageError("source URI must be a stable scheme-qualified reference")
    parsed = urlsplit(normalized)
    if parsed.username is not None or parsed.password is not None:
        raise SourceCoverageError("source URI must not contain credentials")
    if parsed.query or parsed.fragment:
        raise SourceCoverageError("source URI must not contain a query or fragment")
    return normalized


def normalize_entry_id(value: str | None) -> str | None:
    """Validate one optional stable entry identifier."""
    if value is None:
        return None
    normalized = value.strip()
    if not normalized:
        return None
    if len(normalized) > MAX_ENTRY_ID_LENGTH or not _ENTRY_ID_PATTERN.fullmatch(normalized):
        raise SourceCoverageError("entry id must be a stable identifier")
    return normalized


def content_fingerprint(parts: Iterable[object]) -> str:
    """Return one opaque, order-stable fingerprint over normalized parts.

    Only the digest is ever stored or projected; the fingerprinted material
    never leaves the collector.
    """
    payload = json.dumps(
        [_canonical_part(part) for part in parts],
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def source_fingerprint(entry_fingerprints: Iterable[str]) -> str:
    """Return the aggregate fingerprint of one source's entries."""
    return content_fingerprint(sorted(entry_fingerprints))


def snapshot_digest(
    collector: str,
    collected_at: str,
    entries: Sequence[SourceEntry],
) -> str:
    """Return the deterministic digest that binds cursors to this snapshot.

    Row order, insertion order, and mapping order cannot change the digest.
    """
    # Collection, observation, import, and verification times are audit facts,
    # not inventory identity. Excluding them makes a repeated collection of the
    # same normalized inventory reproducible while still changing the digest
    # whenever a classification, intent, fingerprint, presence, or mapping
    # changes.
    del collected_at
    payload = {
        "collector": collector,
        "entries": sorted(
            (
                {
                    "source_uri": entry.source_uri,
                    "entry_id": entry.entry_id,
                    "classification": entry.classification,
                    "intent": entry.intent,
                    "decision_reason": entry.decision_reason,
                    "entry_fingerprint": entry.entry_fingerprint,
                    "source_fingerprint": entry.source_fingerprint,
                    "presence": entry.presence,
                    "mappings": sorted(
                        (
                            {
                                "object_id": mapping.object_id,
                                "role": mapping.role,
                                "imported_entry_fingerprint": (
                                    mapping.imported_entry_fingerprint
                                ),
                            }
                            for mapping in entry.mappings
                        ),
                        key=lambda item: (item["object_id"], item["role"]),
                    ),
                }
                for entry in entries
            ),
            key=lambda item: (item["source_uri"], item["entry_id"] or ""),
        ),
    }
    serialized = json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def validate_snapshot(snapshot: SourceSnapshot) -> SourceSnapshot:
    """Fail closed on any unsanitized, malformed, or unbounded snapshot."""
    if not _COLLECTOR_PATTERN.fullmatch(snapshot.collector):
        raise SourceCoverageError("collector must be a stable identifier")
    if len(snapshot.entries) > MAX_SNAPSHOT_ENTRIES:
        raise SourceCoverageError("snapshot exceeds the maximum entry count")
    _validate_timestamp(snapshot.collected_at)
    seen: set[tuple[str, str]] = set()
    mapping_count = 0
    entries_by_source: dict[str, list[SourceEntry]] = {}
    for entry in snapshot.entries:
        normalize_source_uri(entry.source_uri)
        normalize_entry_id(entry.entry_id)
        if entry.classification not in SOURCE_CLASSIFICATIONS:
            raise SourceCoverageError("unknown source classification")
        if entry.intent not in MAPPING_INTENTS:
            raise SourceCoverageError("unknown mapping intent")
        if entry.decision_reason not in DECISION_REASONS:
            raise SourceCoverageError("unknown decision reason")
        if entry.presence not in ENTRY_PRESENCES:
            raise SourceCoverageError("unknown entry presence")
        _validate_timestamp(entry.observed_at)
        for fingerprint in (entry.entry_fingerprint, entry.source_fingerprint):
            if not _FINGERPRINT_PATTERN.fullmatch(fingerprint):
                raise SourceCoverageError("fingerprints must be sha256 hex digests")
        if entry.key in seen:
            raise SourceCoverageError("duplicate source entry key in one snapshot")
        seen.add(entry.key)
        entries_by_source.setdefault(entry.source_uri, []).append(entry)
        mapping_keys: set[str] = set()
        if len(entry.mappings) > MAX_MAPPINGS_PER_ENTRY:
            raise SourceCoverageError("source entry exceeds the maximum mapping count")
        for mapping in entry.mappings:
            if (
                len(mapping.object_id) > 128
                or not _OBJECT_ID_PATTERN.fullmatch(mapping.object_id)
            ):
                raise SourceCoverageError("mapping object id is invalid")
            if mapping.role not in MAPPING_ROLES:
                raise SourceCoverageError("unknown mapping role")
            if not _FINGERPRINT_PATTERN.fullmatch(mapping.imported_entry_fingerprint):
                raise SourceCoverageError("mapping fingerprints must be sha256 hex digests")
            if mapping.object_id in mapping_keys:
                raise SourceCoverageError("duplicate mapping object id for one entry")
            mapping_keys.add(mapping.object_id)
            if mapping.imported_at is not None:
                _validate_timestamp(mapping.imported_at)
            if mapping.verified_at is not None:
                _validate_timestamp(mapping.verified_at)
        mapping_count += len(entry.mappings)
    if mapping_count > MAX_SNAPSHOT_MAPPINGS:
        raise SourceCoverageError("snapshot exceeds the maximum mapping count")
    for entries in entries_by_source.values():
        expected_source_fingerprint = source_fingerprint(
            entry.entry_fingerprint
            for entry in entries
            if entry.presence == "present"
        )
        if any(
            entry.source_fingerprint != expected_source_fingerprint
            for entry in entries
        ):
            raise SourceCoverageError("source fingerprint does not match its present entries")
    violations = find_secret_violations(_secret_scan_payload(snapshot))
    if violations:
        raise SourceCoverageError("; ".join(violations))
    if snapshot.digest and snapshot.digest != snapshot.with_digest().digest:
        raise SourceCoverageError("snapshot digest does not match its normalized inventory")
    return snapshot


def resolve_coverage(
    snapshot: SourceSnapshot,
    targets: Mapping[str, CatalogTarget],
) -> tuple[CoverageDetail, ...]:
    """Resolve every entry to exactly one stable state, catalog-wide.

    The state never depends on the caller: it is resolved against the whole
    catalog and only afterwards filtered by authorization. That keeps
    concealment from turning into an existence oracle (a hidden object can
    never make a row look orphaned).

    Precedence is fixed and total:
    ``missing_source`` > ``orphaned_catalog_reference`` >
    ``unmapped_operational``/``intentionally_unmapped`` > ``ambiguous_mapping``
    > ``duplicate_mapping`` > ``source_changed_since_import`` >
    ``mapped_stale`` > ``mapped_current``.
    """
    primary_owners: dict[str, int] = {}
    for entry in snapshot.entries:
        if entry.presence != "present":
            continue
        for mapping in entry.mappings:
            if mapping.role != "primary":
                continue
            primary_owners[mapping.object_id] = primary_owners.get(mapping.object_id, 0) + 1

    details = [
        _resolve_entry(entry, targets, primary_owners)
        for entry in snapshot.entries
    ]
    return tuple(sorted(details, key=lambda detail: detail.key))


def resolve_visible_coverage(
    snapshot: SourceSnapshot,
    targets: Mapping[str, CatalogTarget],
    *,
    visible_object_ids: frozenset[str],
    include_source_only: bool,
) -> tuple[CoverageDetail, ...]:
    """Resolve the view authorized for one principal without an existence oracle.

    Source-only facts are an explicit elevated view, but that authority does
    not bypass object ACLs. Existing concealed mappings are removed in both
    views. Missing mapping targets may be included only in the elevated view
    because they have no object ACL. Consequently a concealed object cannot
    affect rows, states, counts, or cursors in either projection.
    """
    visible_entries: list[SourceEntry] = []
    visible_targets = {
        object_id: target
        for object_id, target in targets.items()
        if object_id in visible_object_ids and target.exists
    }
    for entry in snapshot.entries:
        if entry.presence != "present" and not include_source_only:
            continue
        mappings = tuple(
            mapping
            for mapping in entry.mappings
            if mapping.object_id in visible_targets
            or (
                include_source_only
                and mapping.object_id in targets
                and not targets[mapping.object_id].exists
            )
        )
        if not mappings and entry.mappings and entry.presence == "present":
            # Every original edge points at a concealed existing object. Its
            # source entry must not be transformed into an apparent gap.
            continue
        if not mappings and not include_source_only:
            continue
        visible_entries.append(
            SourceEntry(
                source_uri=entry.source_uri,
                entry_id=entry.entry_id,
                classification=entry.classification,
                intent=entry.intent,
                decision_reason=entry.decision_reason,
                entry_fingerprint=entry.entry_fingerprint,
                source_fingerprint=entry.source_fingerprint,
                observed_at=entry.observed_at,
                presence=entry.presence,
                mappings=mappings,
            )
        )
    visible_snapshot = SourceSnapshot(
        collector=snapshot.collector,
        collected_at=snapshot.collected_at,
        entries=tuple(visible_entries),
        digest=snapshot.digest,
    )
    return resolve_coverage(visible_snapshot, visible_targets)


def summarize_coverage(details: Sequence[CoverageDetail]) -> CoverageSummary:
    """Aggregate exactly the detail set handed in, after authorization."""
    by_state = {state: 0 for state in COVERAGE_STATES}
    by_classification = {classification: 0 for classification in SOURCE_CLASSIFICATIONS}
    for detail in details:
        by_state[detail.state] += 1
        by_classification[detail.classification] += 1
    return CoverageSummary(
        total=len(details),
        by_state=by_state,
        by_classification=by_classification,
    )


def coverage_view_digest(details: Sequence[CoverageDetail]) -> str:
    """Hash exactly one authorized projection for response and cursor binding."""
    return content_fingerprint(
        [
            {
                "source_uri": detail.source_uri,
                "entry_id": detail.entry_id,
                "classification": detail.classification,
                "intent": detail.intent,
                "decision_reason": detail.decision_reason,
                "state": detail.state,
                "presence": detail.presence,
                "entry_fingerprint": detail.entry_fingerprint,
                "source_fingerprint": detail.source_fingerprint,
                "mappings": [
                    {
                        "object_id": mapping.object_id,
                        "target_kind": mapping.target_kind,
                        "role": mapping.role,
                        "source_changed": mapping.source_changed,
                    }
                    for mapping in detail.mappings
                ],
            }
            for detail in sorted(details, key=lambda item: item.key)
        ]
    )


def _resolve_entry(
    entry: SourceEntry,
    targets: Mapping[str, CatalogTarget],
    primary_owners: Mapping[str, int],
) -> CoverageDetail:
    mappings = tuple(
        CoverageMapping(
            object_id=mapping.object_id,
            target_kind=(
                targets[mapping.object_id].kind
                if mapping.object_id in targets and targets[mapping.object_id].exists
                else None
            ),
            role=mapping.role,
            exists=(
                mapping.object_id in targets and targets[mapping.object_id].exists
            ),
            source_changed=(
                mapping.imported_entry_fingerprint != entry.entry_fingerprint
            ),
            imported_at=mapping.imported_at,
            verified_at=mapping.verified_at,
        )
        for mapping in sorted(entry.mappings, key=lambda item: (item.object_id, item.role))
    )
    return CoverageDetail(
        source_uri=entry.source_uri,
        entry_id=entry.entry_id,
        classification=entry.classification,
        intent=entry.intent,
        decision_reason=entry.decision_reason,
        state=_resolve_state(entry, mappings, targets, primary_owners),
        presence=entry.presence,
        entry_fingerprint=entry.entry_fingerprint,
        source_fingerprint=entry.source_fingerprint,
        observed_at=entry.observed_at,
        mappings=mappings,
    )


def _resolve_state(
    entry: SourceEntry,
    mappings: Sequence[CoverageMapping],
    targets: Mapping[str, CatalogTarget],
    primary_owners: Mapping[str, int],
) -> CoverageState:
    if entry.presence == "absent":
        return "missing_source"
    if any(not mapping.exists for mapping in mappings):
        return "orphaned_catalog_reference"
    if not mappings:
        if entry.intent == "no_catalog_object":
            return "intentionally_unmapped"
        return "unmapped_operational"
    primary = [mapping for mapping in mappings if mapping.role == "primary"]
    if len(primary) > 1:
        return "ambiguous_mapping"
    if any(primary_owners.get(mapping.object_id, 0) > 1 for mapping in primary):
        return "duplicate_mapping"
    if any(mapping.source_changed for mapping in mappings):
        return "source_changed_since_import"
    if any(
        mapping.object_id in targets and targets[mapping.object_id].is_stale
        for mapping in mappings
    ):
        return "mapped_stale"
    return "mapped_current"


def _secret_scan_payload(snapshot: SourceSnapshot) -> dict[str, object]:
    return {
        "collector": snapshot.collector,
        "entries": [
            {
                "source_uri": entry.source_uri,
                "entry_id": entry.entry_id,
                "classification": entry.classification,
                "decision_reason": entry.decision_reason,
                "object_ids": [mapping.object_id for mapping in entry.mappings],
            }
            for entry in snapshot.entries
        ],
    }


def _canonical_part(part: object) -> object:
    if isinstance(part, str | int | float | bool) or part is None:
        return part
    if isinstance(part, Mapping):
        return {str(key): _canonical_part(value) for key, value in part.items()}
    if isinstance(part, Sequence):
        return [_canonical_part(item) for item in part]
    return str(part)


def _validate_timestamp(value: str) -> None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SourceCoverageError("timestamps must be RFC3339") from exc
    if parsed.tzinfo is None:
        raise SourceCoverageError("timestamps must include an UTC offset")
