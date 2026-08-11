"""Authorized, read-only projection of the recorded source-coverage snapshot.

The request path never crawls the OpenClaw workspace and never opens a source
file. It reads exactly one already-recorded, sanitized, digest-bound snapshot
plus the catalog rows the snapshot already references, and it writes nothing.

Authorization happens before both details and counts. Ordinary rows are
resolved from visible mappings only, so concealed objects cannot affect their
state, count, response digest, or cursor.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from blockwart.domain.auth import Permission
from blockwart.domain.provenance import is_stale, load_provenance
from blockwart.domain.source_coverage import (
    COVERAGE_STATES,
    MAX_SNAPSHOT_ENTRIES,
    MAX_SNAPSHOT_MAPPINGS,
    SOURCE_CLASSIFICATIONS,
    CatalogTarget,
    CoverageDetail,
    CoverageSummary,
    SourceCoverageError,
    SourceEntry,
    SourceMapping,
    SourceSnapshot,
    coverage_view_digest,
    normalize_source_uri,
    resolve_coverage,
    resolve_visible_coverage,
    summarize_coverage,
    validate_snapshot,
)
from blockwart.domain.timestamps import format_rfc3339_utc
from blockwart.models import CatalogObject
from blockwart.models.source_coverage import (
    SourceEntry as SourceEntryRow,
)
from blockwart.models.source_coverage import (
    SourceEntryMapping as SourceEntryMappingRow,
)
from blockwart.models.source_coverage import (
    SourceSnapshot as SourceSnapshotRow,
)
from blockwart.services.pagination import SortDirection, paginate_items
from blockwart.services.principal_management import (
    PlatformAdminDenied,
    require_platform_admin,
)
from blockwart.services.read_access import ReadAccess

COVERAGE_RESOURCE = "source-coverage"
COVERAGE_SORT_FIELD = "source_uri"
# A bounded parameter batch keeps the catalog target lookup one small set of
# statements instead of one authorization query per mapped object.
_TARGET_CHUNK_SIZE = 400

CoverageScope = str
COVERAGE_SCOPES: tuple[str, ...] = ("mapped", "all")

__all__ = [
    "COVERAGE_RESOURCE",
    "COVERAGE_SCOPES",
    "CoverageAuthorityDenied",
    "SourceCoveragePage",
    "SourceCoverageSnapshotInfo",
    "load_current_snapshot",
    "query_source_coverage_page",
    "record_source_snapshot",
    "resolve_snapshot_coverage",
]


class CoverageAuthorityDenied(PermissionError):
    """Source-only coverage was requested without the elevated authority."""


@dataclass(frozen=True, slots=True)
class SourceCoverageSnapshotInfo:
    digest: str
    collector: str
    collected_at: str
    source_count: int
    entry_count: int
    mapping_count: int


@dataclass(frozen=True, slots=True)
class SourceCoveragePage:
    snapshot: SourceCoverageSnapshotInfo | None
    summary: CoverageSummary
    items: list[CoverageDetail]
    next_cursor: str | None
    total: int | None
    scope: str


def record_source_snapshot(
    session: Session,
    snapshot: SourceSnapshot,
) -> SourceCoverageSnapshotInfo:
    """Persist one validated snapshot; recording an identical digest is a no-op.

    Recording touches only the source-coverage tables. It creates, updates, or
    deletes no catalog object, relationship, comment, or audit row.
    """
    validated = validate_snapshot(snapshot)
    digest = validated.digest or validated.with_digest().digest
    current = _current_snapshot_row(session)
    if current is not None and current.digest == digest:
        return _snapshot_info(current, validated)

    collected_at = _parse_timestamp(validated.collected_at)
    snapshot_row = SourceSnapshotRow(
        id=str(uuid4()),
        digest=digest,
        collector=validated.collector,
        collected_at=collected_at,
        entry_count=len(validated.entries),
        mapping_count=sum(len(entry.mappings) for entry in validated.entries),
    )
    session.add(snapshot_row)
    session.flush()
    for entry in sorted(validated.entries, key=lambda item: item.key):
        entry_row = SourceEntryRow(
            snapshot_id=snapshot_row.id,
            source_uri=entry.source_uri,
            entry_id=entry.entry_id,
            entry_key=entry.entry_id or "",
            classification=entry.classification,
            intent=entry.intent,
            decision_reason=entry.decision_reason,
            presence=entry.presence,
            entry_fingerprint=entry.entry_fingerprint,
            source_fingerprint=entry.source_fingerprint,
            observed_at=_parse_timestamp(entry.observed_at),
        )
        session.add(entry_row)
        session.flush()
        for mapping in sorted(entry.mappings, key=lambda item: (item.object_id, item.role)):
            session.add(
                SourceEntryMappingRow(
                    snapshot_id=snapshot_row.id,
                    entry_row_id=entry_row.id,
                    object_id=mapping.object_id,
                    role=mapping.role,
                    imported_entry_fingerprint=mapping.imported_entry_fingerprint,
                    imported_at=_optional_timestamp(mapping.imported_at),
                    verified_at=_optional_timestamp(mapping.verified_at),
                )
            )
    session.flush()
    return _snapshot_info(snapshot_row, validated)


def load_current_snapshot(session: Session) -> SourceSnapshot | None:
    """Load the newest recorded snapshot, deterministically and bounded.

    Ties on ``collected_at`` are broken by digest so two snapshots recorded in
    the same instant still resolve to exactly one current snapshot regardless
    of database row order.
    """
    snapshot_row = _current_snapshot_row(session)
    if snapshot_row is None:
        return None
    return _load_snapshot(session, snapshot_row)


def _current_snapshot_row(session: Session) -> SourceSnapshotRow | None:
    return session.scalars(
        select(SourceSnapshotRow)
        .order_by(
            SourceSnapshotRow.collected_at.desc(),
            SourceSnapshotRow.digest.desc(),
        )
        .limit(1)
    ).first()


def resolve_snapshot_coverage(
    session: Session,
    snapshot: SourceSnapshot,
) -> tuple[CoverageDetail, ...]:
    """Resolve one explicitly collected snapshot against the current catalog."""
    return resolve_coverage(snapshot, _catalog_targets(session, snapshot))


def query_source_coverage_page(
    session: Session,
    access: ReadAccess,
    *,
    source: str | None = None,
    classification: str | None = None,
    state: str | None = None,
    target_kind: str | None = None,
    scope: str = "mapped",
    limit: int = 50,
    cursor: str | None = None,
    direction: SortDirection = "asc",
    include_total: bool = False,
) -> SourceCoveragePage:
    """Return one authorized coverage page plus its matching summary.

    The summary aggregates exactly the authorized, filtered detail set that the
    pages enumerate, so ``summary.total`` always equals the number of items a
    caller can page through.
    """
    if limit < 1 or limit > 100:
        raise SourceCoverageError("coverage limit must be between 1 and 100")
    if scope not in COVERAGE_SCOPES:
        raise SourceCoverageError("unknown coverage scope")
    if classification is not None and classification not in SOURCE_CLASSIFICATIONS:
        raise SourceCoverageError("unknown source classification")
    if state is not None and state not in COVERAGE_STATES:
        raise SourceCoverageError("unknown coverage state")
    if direction not in {"asc", "desc"}:
        raise SourceCoverageError("unknown coverage ordering")
    normalized_source = normalize_source_uri(source) if source is not None else None
    normalized_target_kind = target_kind.strip() if target_kind is not None else None
    if normalized_target_kind == "" or (
        normalized_target_kind is not None and len(normalized_target_kind) > 64
    ):
        raise SourceCoverageError("target kind is invalid")
    if scope == "all":
        try:
            require_platform_admin(access)
        except PlatformAdminDenied as exc:
            raise CoverageAuthorityDenied(
                "source-only coverage requires the platform administrator authority"
            ) from exc

    snapshot = load_current_snapshot(session)
    if snapshot is None:
        return SourceCoveragePage(
            snapshot=None,
            summary=summarize_coverage(()),
            items=[],
            next_cursor=None,
            total=0 if include_total else None,
            scope=scope,
        )

    targets = _catalog_targets(session, snapshot)
    visible_object_ids = access.policy.authorized_ids(Permission.READ)
    authorized = list(
        resolve_visible_coverage(
            snapshot,
            targets,
            visible_object_ids=visible_object_ids,
            include_source_only=scope == "all",
        )
    )
    authorized_digest = coverage_view_digest(authorized)
    filtered = [
        detail
        for detail in authorized
        if _matches_filters(
            detail,
            source=normalized_source,
            classification=classification,
            state=state,
            target_kind=normalized_target_kind,
        )
    ]
    page = paginate_items(
        filtered,
        key=lambda detail: (detail.source_uri, detail.entry_id or ""),
        limit=limit,
        resource=COVERAGE_RESOURCE,
        sort=COVERAGE_SORT_FIELD,
        direction=direction,
        query={
            "access": access.cursor_scope,
            "classification": classification or "",
            "limit": limit,
            "scope": scope,
            "snapshot": authorized_digest,
            "source": normalized_source or "",
            "state": state or "",
            "target_kind": normalized_target_kind or "",
        },
        cursor=cursor,
        include_total=include_total,
    )
    return SourceCoveragePage(
        snapshot=SourceCoverageSnapshotInfo(
            digest=authorized_digest,
            collector=snapshot.collector,
            collected_at=snapshot.collected_at,
            source_count=len({detail.source_uri for detail in filtered}),
            entry_count=len(filtered),
            mapping_count=sum(len(detail.mappings) for detail in filtered),
        ),
        summary=summarize_coverage(filtered),
        items=page.items,
        next_cursor=page.next_cursor,
        total=page.total,
        scope=scope,
    )


def _matches_filters(
    detail: CoverageDetail,
    *,
    source: str | None,
    classification: str | None,
    state: str | None,
    target_kind: str | None,
) -> bool:
    if source is not None and detail.source_uri != source:
        return False
    if classification is not None and detail.classification != classification:
        return False
    if state is not None and detail.state != state:
        return False
    if target_kind is not None and target_kind not in detail.target_kinds:
        return False
    return True


def _catalog_targets(
    session: Session,
    snapshot: SourceSnapshot,
) -> dict[str, CatalogTarget]:
    object_ids = sorted(
        {
            mapping.object_id
            for entry in snapshot.entries
            for mapping in entry.mappings
        }
    )
    targets: dict[str, CatalogTarget] = {}
    for chunk in _chunked(object_ids, _TARGET_CHUNK_SIZE):
        rows = session.execute(
            select(
                CatalogObject.id,
                CatalogObject.kind,
                CatalogObject.provenance_json,
            ).where(CatalogObject.id.in_(chunk))
        ).all()
        for row in rows:
            provenance, _valid = load_provenance(row.provenance_json)
            targets[str(row.id)] = CatalogTarget(
                object_id=str(row.id),
                kind=str(row.kind),
                exists=True,
                is_stale=is_stale(provenance),
            )
    for object_id in object_ids:
        targets.setdefault(
            object_id,
            CatalogTarget(
                object_id=object_id,
                kind="",
                exists=False,
                is_stale=False,
            ),
        )
    return targets


def _load_snapshot(
    session: Session,
    snapshot_row: SourceSnapshotRow,
) -> SourceSnapshot:
    entry_rows = session.scalars(
        select(SourceEntryRow)
        .where(SourceEntryRow.snapshot_id == snapshot_row.id)
        .order_by(
            SourceEntryRow.source_uri,
            SourceEntryRow.entry_key,
        )
        .limit(MAX_SNAPSHOT_ENTRIES + 1)
    ).all()
    if len(entry_rows) > MAX_SNAPSHOT_ENTRIES:
        raise SourceCoverageError("recorded snapshot exceeds the maximum entry count")
    mapping_rows = session.scalars(
        select(SourceEntryMappingRow)
        .where(SourceEntryMappingRow.snapshot_id == snapshot_row.id)
        .order_by(
            SourceEntryMappingRow.entry_row_id,
            SourceEntryMappingRow.object_id,
            SourceEntryMappingRow.role,
        )
        .limit(MAX_SNAPSHOT_MAPPINGS + 1)
    ).all()
    if len(mapping_rows) > MAX_SNAPSHOT_MAPPINGS:
        raise SourceCoverageError("recorded snapshot exceeds the maximum mapping count")
    mappings_by_entry: dict[int, list[SourceMapping]] = {}
    for row in mapping_rows:
        mappings_by_entry.setdefault(row.entry_row_id, []).append(
            SourceMapping(
                object_id=row.object_id,
                role=row.role,
                imported_entry_fingerprint=row.imported_entry_fingerprint,
                imported_at=format_rfc3339_utc(row.imported_at),
                verified_at=format_rfc3339_utc(row.verified_at),
            )
        )
    entries = tuple(
        SourceEntry(
            source_uri=row.source_uri,
            entry_id=row.entry_id,
            classification=row.classification,
            intent=row.intent,
            decision_reason=row.decision_reason,
            entry_fingerprint=row.entry_fingerprint,
            source_fingerprint=row.source_fingerprint,
            observed_at=format_rfc3339_utc(row.observed_at) or "",
            presence=row.presence,
            mappings=tuple(
                sorted(
                    mappings_by_entry.get(row.id, ()),
                    key=lambda item: (item.object_id, item.role),
                )
            ),
        )
        for row in sorted(entry_rows, key=lambda item: (item.source_uri, item.entry_key))
    )
    snapshot = SourceSnapshot(
        collector=snapshot_row.collector,
        collected_at=format_rfc3339_utc(snapshot_row.collected_at) or "",
        entries=entries,
        digest=snapshot_row.digest,
    )
    validate_snapshot(snapshot)
    if snapshot.with_digest().digest != snapshot.digest:
        raise SourceCoverageError("recorded snapshot digest is invalid")
    return snapshot


def _snapshot_info(
    snapshot_row: SourceSnapshotRow,
    snapshot: SourceSnapshot,
) -> SourceCoverageSnapshotInfo:
    return SourceCoverageSnapshotInfo(
        digest=snapshot_row.digest,
        collector=snapshot_row.collector,
        collected_at=format_rfc3339_utc(snapshot_row.collected_at) or "",
        source_count=len(snapshot.source_uris),
        entry_count=snapshot_row.entry_count,
        mapping_count=snapshot_row.mapping_count,
    )


def _chunked[T](values: Sequence[T], size: int) -> Iterable[Sequence[T]]:
    for start in range(0, len(values), size):
        yield values[start : start + size]


def _parse_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SourceCoverageError("timestamps must be RFC3339") from exc
    if parsed.tzinfo is None:
        raise SourceCoverageError("timestamps must include an UTC offset")
    return parsed.astimezone(UTC).replace(tzinfo=None)


def _optional_timestamp(value: str | None) -> datetime | None:
    return None if value is None else _parse_timestamp(value)
