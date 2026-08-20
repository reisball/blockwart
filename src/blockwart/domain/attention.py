"""The closed "needs attention" vocabulary and its pure derivation.

Blockwart already resolves several independent canonical signals: manual
lifecycle/health, the provider-neutral monitoring projection, provenance
freshness, record-integrity and placement diagnostics, Runbook readiness,
knowledge review state, and recorded source coverage.  This module is the one
place that turns those *already authorized* facts into one comparable list of
things a human or agent should look at.

It deliberately owns no new truth:

- it performs no I/O, no probe, no crawl, and no write;
- it never re-implements a domain rule that #135 (monitoring) or #174 (source
  coverage) already owns, it only classifies their published output;
- it reads only scalar fields of a catalog document, never a typed reference,
  so an authorized-reference projection cannot change what it reports;
- every value it emits comes from a closed vocabulary declared below.

Because of the third rule the derivation is authorization-stable: concealing an
object can remove items (the object is no longer readable) but can never change
the classification of an object that stays readable.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal, get_args

from blockwart.domain.asset_state import ASSET_HEALTH_VALUES, is_asset_kind
from blockwart.domain.monitoring import (
    MONITORING_DIAGNOSTIC_VALUES,
    MONITORING_ERROR_CODE_VALUES,
)
from blockwart.domain.object_schema import (
    DECISION_STATUS_VALUES,
    PROJECT_STATUS_VALUES,
    RUNBOOK_STATUS_VALUES,
)
from blockwart.domain.provenance import parse_rfc3339_utc
from blockwart.domain.source_coverage import COVERAGE_STATES

AttentionCategory = Literal[
    "record_integrity",
    "monitoring",
    "lifecycle",
    "endpoint",
    "placement",
    "provenance",
    "runbook",
    "knowledge",
    "source_coverage",
]
# Declaration order is the published tie-breaker between two items of equal
# severity.  It is a stable part of the contract, not an implementation detail.
ATTENTION_CATEGORY_VALUES: tuple[str, ...] = get_args(AttentionCategory)
ATTENTION_CATEGORIES = frozenset(ATTENTION_CATEGORY_VALUES)

AttentionSeverity = Literal["critical", "warning", "info"]
ATTENTION_SEVERITY_VALUES: tuple[str, ...] = get_args(AttentionSeverity)
ATTENTION_SEVERITIES = frozenset(ATTENTION_SEVERITY_VALUES)

# `current`   the evidence is present and current, and it asserts the problem now
# `stale`     evidence exists but is past its freshness boundary; it is never
#             re-interpreted as healthy
# `unknown`   the signal applies but no usable evidence exists yet
# `not_applicable`  nothing in the authorized scope produces this signal at all;
#             only a summary signal status may carry it, never an item
AttentionSignalState = Literal["current", "stale", "unknown", "not_applicable"]
ATTENTION_SIGNAL_STATE_VALUES: tuple[str, ...] = get_args(AttentionSignalState)
ATTENTION_SIGNAL_STATES = frozenset(ATTENTION_SIGNAL_STATE_VALUES)

AttentionTargetScope = Literal["object", "catalog"]

# The one catalog-scoped target. It carries no object identity at all, so the
# "coverage was never collected" fact cannot become an object hint.
CATALOG_COVERAGE_REF = "catalog:source-coverage"

AttentionReason = Literal[
    "record_corrupt",
    "monitoring_observed_down",
    "monitoring_check_error",
    "monitoring_config_invalid",
    "monitoring_observation_stale",
    "monitoring_never_observed",
    "lifecycle_health_down",
    "lifecycle_health_degraded",
    "lifecycle_health_unknown",
    "lifecycle_maintenance",
    "endpoint_target_unresolved",
    "placement_missing",
    "provenance_stale",
    "provenance_unverified",
    "runbook_review_overdue",
    "runbook_unverified",
    "runbook_deprecated_unresolved",
    "knowledge_review_overdue",
    "knowledge_review_unscheduled",
    "coverage_import_drift",
    "coverage_mapping_ambiguous",
    "coverage_not_collected",
]
ATTENTION_REASON_VALUES: tuple[str, ...] = get_args(AttentionReason)
ATTENTION_REASONS = frozenset(ATTENTION_REASON_VALUES)


class AttentionContractError(ValueError):
    """One derived attention value left its closed vocabulary."""


@dataclass(frozen=True, slots=True)
class AttentionReasonSpec:
    """The immutable published meaning of exactly one reason code."""

    reason_code: AttentionReason
    category: AttentionCategory
    severity: AttentionSeverity
    signal_state: Literal["current", "stale", "unknown"]
    description: str


def _spec(
    reason_code: str,
    category: str,
    severity: str,
    signal_state: str,
    description: str,
) -> AttentionReasonSpec:
    return AttentionReasonSpec(
        reason_code=reason_code,  # type: ignore[arg-type]
        category=category,  # type: ignore[arg-type]
        severity=severity,  # type: ignore[arg-type]
        signal_state=signal_state,  # type: ignore[arg-type]
        description=description,
    )


# The registry is ordered by category, and inside one category by descending
# priority. Deduplication compares this rank, so raw input order cannot change
# which reason wins for one target and category.
ATTENTION_REASON_SPECS: tuple[AttentionReasonSpec, ...] = (
    _spec(
        "record_corrupt",
        "record_integrity",
        "critical",
        "current",
        "The stored record does not satisfy the canonical catalog schema.",
    ),
    _spec(
        "monitoring_observed_down",
        "monitoring",
        "critical",
        "current",
        "The current provider-neutral observation reports the service as down.",
    ),
    _spec(
        "monitoring_check_error",
        "monitoring",
        "warning",
        "current",
        "The monitoring check itself failed; this is not a claim that the service is down.",
    ),
    _spec(
        "monitoring_config_invalid",
        "monitoring",
        "warning",
        "unknown",
        "The stored monitoring document is malformed, so no check can run.",
    ),
    _spec(
        "monitoring_observation_stale",
        "monitoring",
        "warning",
        "stale",
        "The last observation is past its due time and is not re-read as healthy.",
    ),
    _spec(
        "monitoring_never_observed",
        "monitoring",
        "info",
        "unknown",
        "Monitoring is enabled but no observation has been recorded yet.",
    ),
    _spec(
        "lifecycle_health_down",
        "lifecycle",
        "critical",
        "current",
        "The manually recorded health of this active asset is down.",
    ),
    _spec(
        "lifecycle_health_degraded",
        "lifecycle",
        "warning",
        "current",
        "The manually recorded health of this active asset is degraded.",
    ),
    _spec(
        "lifecycle_health_unknown",
        "lifecycle",
        "info",
        "unknown",
        "The active asset has no current manually recorded health assessment.",
    ),
    _spec(
        "lifecycle_maintenance",
        "lifecycle",
        "info",
        "current",
        "The asset is in declared maintenance; automated incidents stay suppressed.",
    ),
    _spec(
        "endpoint_target_unresolved",
        "endpoint",
        "warning",
        "unknown",
        "The canonical endpoint contract does not resolve one monitoring target.",
    ),
    _spec(
        "placement_missing",
        "placement",
        "warning",
        "unknown",
        "The object has no canonical placement parent and no declared unassigned state.",
    ),
    _spec(
        "provenance_stale",
        "provenance",
        "warning",
        "stale",
        "The recorded provenance passed its declared stale-after boundary.",
    ),
    _spec(
        "provenance_unverified",
        "provenance",
        "info",
        "unknown",
        "The record carries no provenance verification time.",
    ),
    _spec(
        "runbook_review_overdue",
        "runbook",
        "warning",
        "stale",
        "The Runbook passed its declared review date.",
    ),
    _spec(
        "runbook_unverified",
        "runbook",
        "warning",
        "unknown",
        "An approved or active Runbook records no verification time.",
    ),
    _spec(
        "runbook_deprecated_unresolved",
        "runbook",
        "info",
        "current",
        "A deprecated Runbook records neither a rationale nor a successor recommendation.",
    ),
    _spec(
        "knowledge_review_overdue",
        "knowledge",
        "warning",
        "stale",
        "The knowledge record passed its declared review date.",
    ),
    _spec(
        "knowledge_review_unscheduled",
        "knowledge",
        "info",
        "unknown",
        "A currently valid knowledge record schedules no review.",
    ),
    _spec(
        "coverage_import_drift",
        "source_coverage",
        "warning",
        "stale",
        "The mapped source entry changed after the recorded import.",
    ),
    _spec(
        "coverage_mapping_ambiguous",
        "source_coverage",
        "warning",
        "current",
        "The recorded coverage mapping for this object is ambiguous or duplicated.",
    ),
    _spec(
        "coverage_not_collected",
        "source_coverage",
        "info",
        "unknown",
        "No authorized mapped source-coverage evidence is available, so coverage is unknown.",
    ),
)

REASON_SPEC_BY_CODE: Mapping[str, AttentionReasonSpec] = {
    spec.reason_code: spec for spec in ATTENTION_REASON_SPECS
}
_CATEGORY_RANK: Mapping[str, int] = {
    category: index for index, category in enumerate(ATTENTION_CATEGORY_VALUES)
}
_SEVERITY_RANK: Mapping[str, int] = {
    severity: index for index, severity in enumerate(ATTENTION_SEVERITY_VALUES)
}
_REASON_RANK: Mapping[str, int] = {
    spec.reason_code: index for index, spec in enumerate(ATTENTION_REASON_SPECS)
}

# Every supporting code an item may carry comes from a vocabulary another
# reviewed domain already publishes.  Free text can therefore never reach the
# `detail_code` field.
ATTENTION_DETAIL_CODE_VALUES: tuple[str, ...] = tuple(
    sorted(
        {
            *MONITORING_DIAGNOSTIC_VALUES,
            *MONITORING_ERROR_CODE_VALUES,
            *COVERAGE_STATES,
            *ASSET_HEALTH_VALUES,
            *RUNBOOK_STATUS_VALUES,
            *DECISION_STATUS_VALUES,
            *PROJECT_STATUS_VALUES,
        }
    )
)
ATTENTION_DETAIL_CODES = frozenset(ATTENTION_DETAIL_CODE_VALUES)

# Canonical Runbook, Decision, and Project states that still describe currently
# valid knowledge.  Everything else is finished or withdrawn and must not become
# an incident.
_LIVE_RUNBOOK_STATUSES = frozenset({"draft", "approved", "active", "deprecated"})
_CURRENT_RUNBOOK_STATUSES = frozenset({"approved", "active"})
_LIVE_DECISION_STATUSES = frozenset({"proposed", "accepted"})
_CURRENT_DECISION_STATUSES = frozenset({"accepted"})
_LIVE_PROJECT_STATUSES = frozenset({"planned", "active", "paused"})
_CURRENT_PROJECT_STATUSES = frozenset({"active"})

# Coverage states that describe a mapped object problem. `mapped_stale` is
# deliberately absent: it is exactly the object provenance fact the provenance
# category already reports, and reporting it twice would double-count one cause.
_COVERAGE_STATE_REASONS: Mapping[str, str] = {
    "source_changed_since_import": "coverage_import_drift",
    "ambiguous_mapping": "coverage_mapping_ambiguous",
    "duplicate_mapping": "coverage_mapping_ambiguous",
}


@dataclass(frozen=True, slots=True)
class AttentionTarget:
    """The authorized navigation reference of exactly one item."""

    scope: AttentionTargetScope
    ref: str
    object_id: str | None = None
    kind: str | None = None
    label: str | None = None
    detail_path: str | None = None


@dataclass(frozen=True, slots=True)
class AttentionItem:
    """One deduplicated, classified thing to look at."""

    reason_code: AttentionReason
    category: AttentionCategory
    severity: AttentionSeverity
    signal_state: Literal["current", "stale", "unknown"]
    target: AttentionTarget
    description: str
    detail_code: str | None = None
    observed_at: str | None = None

    @property
    def key(self) -> tuple[str, str]:
        """The deterministic keyset ordering position of this item."""
        primary = "-".join(
            (
                f"{_SEVERITY_RANK[self.severity]:02d}",
                f"{_CATEGORY_RANK[self.category]:02d}",
                f"{_REASON_RANK[self.reason_code]:02d}",
            )
        )
        return primary, self.target.ref


@dataclass(frozen=True, slots=True)
class AttentionSignalStatus:
    """Whether one whole category could be judged at all, and on what evidence."""

    state: AttentionSignalState
    evaluated: int
    items: int


@dataclass(frozen=True, slots=True)
class AttentionSummary:
    """Aggregated counts over exactly one authorized, filtered item set."""

    total: int
    by_severity: dict[str, int] = field(default_factory=dict)
    by_category: dict[str, int] = field(default_factory=dict)
    by_reason: dict[str, int] = field(default_factory=dict)
    signals: dict[str, AttentionSignalStatus] = field(default_factory=dict)
    coverage_snapshot_state: Literal["collected", "not_collected"] = "not_collected"


@dataclass(frozen=True, slots=True)
class AttentionObjectInput:
    """One authorized, already projected readable catalog object.

    Only scalar facts appear here. `data` is passed for the small set of scalar
    knowledge fields the derivation reads; no typed reference is ever consulted.
    """

    object_id: str
    kind: str
    label: str
    lifecycle: str | None
    health: str | None
    record_state: str
    placement_state: str | None
    provenance_source_type: str
    provenance_observed_at: str | None
    provenance_verified_at: str | None
    provenance_stale_after: str | None
    data: Mapping[str, Any]
    monitoring: Mapping[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class AttentionCoverageInput:
    """One authorized coverage row already resolved by the #174 resolver."""

    object_id: str
    state: str
    observed_at: str


@dataclass(frozen=True, slots=True)
class AttentionDerivation:
    """The complete authorized item set plus its evaluation scope."""

    items: tuple[AttentionItem, ...]
    evaluated: Mapping[str, int]
    coverage_collected: bool


def build_attention_derivation(
    *,
    objects: Sequence[AttentionObjectInput],
    coverage: Sequence[AttentionCoverageInput],
    coverage_collected: bool,
    now: datetime,
) -> AttentionDerivation:
    """Classify every authorized signal into one deduplicated ordered set."""

    evaluated = dict.fromkeys(ATTENTION_CATEGORY_VALUES, 0)
    # `category -> target_ref -> item`, so one category keeps at most one item
    # per target and the first (highest priority) raw signal wins.
    collected: dict[str, dict[str, AttentionItem]] = {
        category: {} for category in ATTENTION_CATEGORY_VALUES
    }
    labels: dict[str, AttentionObjectInput] = {}

    def emit(
        candidate: AttentionObjectInput | None,
        reason_code: str,
        *,
        detail_code: str | None = None,
        observed_at: str | None = None,
    ) -> None:
        spec = REASON_SPEC_BY_CODE[reason_code]
        target = (
            _object_target(candidate)
            if candidate is not None
            else AttentionTarget(
                scope="catalog",
                ref=CATALOG_COVERAGE_REF,
                detail_path="/attention?category=source_coverage",
            )
        )
        bucket = collected[spec.category]
        existing = bucket.get(target.ref)
        if (
            existing is not None
            and _REASON_RANK[existing.reason_code] <= _REASON_RANK[reason_code]
        ):
            return
        bucket[target.ref] = _validated_item(
            AttentionItem(
                reason_code=spec.reason_code,
                category=spec.category,
                severity=spec.severity,
                signal_state=spec.signal_state,
                target=target,
                description=spec.description,
                detail_code=detail_code,
                observed_at=observed_at,
            )
        )

    for candidate in objects:
        labels[candidate.object_id] = candidate
        evaluated["record_integrity"] += 1
        if candidate.record_state != "valid":
            emit(candidate, "record_corrupt")
            # A corrupt record has no trustworthy document to classify further.
            # The provider-neutral monitoring projection is one deliberate
            # exception: it totalizes a present malformed monitoring document
            # into the fixed `invalid_monitoring_config` diagnostic without
            # exposing or trusting any rejected value.
            if (
                _is_live(candidate)
                and candidate.monitoring is not None
                and candidate.monitoring.get("diagnostic")
                == "invalid_monitoring_config"
            ):
                _derive_monitoring(candidate, evaluated, emit)
            continue
        if not _is_live(candidate):
            continue
        _derive_placement(candidate, evaluated, emit)
        _derive_lifecycle(candidate, evaluated, emit)
        _derive_monitoring(candidate, evaluated, emit)
        _derive_provenance(candidate, evaluated, emit, now=now)
        _derive_runbook(candidate, evaluated, emit, now=now)
        _derive_knowledge(candidate, evaluated, emit, now=now)

    for row in coverage:
        candidate = labels.get(row.object_id)
        if candidate is None or candidate.record_state != "valid" or not _is_live(candidate):
            continue
        evaluated["source_coverage"] += 1
        reason_code = _COVERAGE_STATE_REASONS.get(row.state)
        if reason_code is None:
            continue
        emit(
            candidate,
            reason_code,
            detail_code=row.state,
            observed_at=row.observed_at,
        )
    if not coverage_collected:
        emit(None, "coverage_not_collected")

    items = tuple(
        sorted(
            (
                item
                for bucket in collected.values()
                for item in bucket.values()
            ),
            key=lambda item: item.key,
        )
    )
    return AttentionDerivation(
        items=items,
        evaluated=evaluated,
        coverage_collected=coverage_collected,
    )


def summarize_attention(
    items: Sequence[AttentionItem],
    derivation: AttentionDerivation,
) -> AttentionSummary:
    """Aggregate exactly the filtered item set handed in.

    Every count describes those items. `signals[category].evaluated` is the one
    deliberate exception: it reports how many authorized inputs the category was
    judged against before item filters, because otherwise `not_applicable` and
    "filtered away" would be indistinguishable.
    """
    by_severity = dict.fromkeys(ATTENTION_SEVERITY_VALUES, 0)
    by_category = dict.fromkeys(ATTENTION_CATEGORY_VALUES, 0)
    by_reason = dict.fromkeys(ATTENTION_REASON_VALUES, 0)
    states: dict[str, set[str]] = {
        category: set() for category in ATTENTION_CATEGORY_VALUES
    }
    for item in items:
        by_severity[item.severity] += 1
        by_category[item.category] += 1
        by_reason[item.reason_code] += 1
        states[item.category].add(item.signal_state)
    signals = {
        category: AttentionSignalStatus(
            state=_category_signal_state(
                category,
                evaluated=derivation.evaluated.get(category, 0),
                states=states[category],
                coverage_collected=derivation.coverage_collected,
            ),
            evaluated=derivation.evaluated.get(category, 0),
            items=by_category[category],
        )
        for category in ATTENTION_CATEGORY_VALUES
    }
    return AttentionSummary(
        total=len(items),
        by_severity=by_severity,
        by_category=by_category,
        by_reason=by_reason,
        signals=signals,
        coverage_snapshot_state=(
            "collected" if derivation.coverage_collected else "not_collected"
        ),
    )


def attention_contract_projection() -> dict[str, Any]:
    """Publish the closed vocabulary so all three surfaces can be compared."""
    return {
        "categories": list(ATTENTION_CATEGORY_VALUES),
        "severities": list(ATTENTION_SEVERITY_VALUES),
        "signal_states": list(ATTENTION_SIGNAL_STATE_VALUES),
        "reasons": [
            {
                "reason_code": spec.reason_code,
                "category": spec.category,
                "severity": spec.severity,
                "signal_state": spec.signal_state,
                "description": spec.description,
            }
            for spec in ATTENTION_REASON_SPECS
        ],
        "detail_codes": list(ATTENTION_DETAIL_CODE_VALUES),
        "read_only": True,
        "performs_probe_or_source_read": False,
    }


def _object_target(candidate: AttentionObjectInput) -> AttentionTarget:
    return AttentionTarget(
        scope="object",
        ref=f"{candidate.kind}:{candidate.object_id}",
        object_id=candidate.object_id,
        kind=candidate.kind,
        label=candidate.label,
        detail_path=f"/objects/{candidate.object_id}",
    )


def _validated_item(item: AttentionItem) -> AttentionItem:
    if item.reason_code not in ATTENTION_REASONS:
        raise AttentionContractError("unknown attention reason code")
    if item.category not in ATTENTION_CATEGORIES:
        raise AttentionContractError("unknown attention category")
    if item.severity not in ATTENTION_SEVERITIES:
        raise AttentionContractError("unknown attention severity")
    if item.signal_state not in {"current", "stale", "unknown"}:
        raise AttentionContractError("an item signal state must not be not_applicable")
    if item.detail_code is not None and item.detail_code not in ATTENTION_DETAIL_CODES:
        raise AttentionContractError("unknown attention detail code")
    return item


def _is_live(candidate: AttentionObjectInput) -> bool:
    """Whether the record still describes something that can need attention.

    Planned and retired assets, and finished or withdrawn knowledge, are
    deliberately excluded: an intentional state must never be published as an
    incident. Record integrity is judged before this gate, because a corrupt
    row cannot be trusted to declare its own lifecycle intent.
    """
    if is_asset_kind(candidate.kind):
        return candidate.lifecycle == "active"
    if candidate.kind == "runbook":
        return _status(candidate, "runbook_status", _LIVE_RUNBOOK_STATUSES)
    if candidate.kind == "decision":
        return _status(candidate, "decision_status", _LIVE_DECISION_STATUSES)
    if candidate.kind == "project":
        return _status(candidate, "project_status", _LIVE_PROJECT_STATUSES)
    return True


def _status(
    candidate: AttentionObjectInput,
    key: str,
    allowed: frozenset[str],
) -> bool:
    """Treat a legacy record without the closed status as still live."""
    value = candidate.data.get(key)
    if not isinstance(value, str):
        return True
    return value in allowed


def _derive_placement(candidate, evaluated, emit) -> None:
    # `unassigned` is the explicit, reviewed "deliberately not placed" state and
    # is not a problem. `unknown` means no parent edge and no declaration.
    if candidate.placement_state is None:
        return
    evaluated["placement"] += 1
    if candidate.placement_state == "unknown":
        emit(candidate, "placement_missing")


def _derive_lifecycle(candidate, evaluated, emit) -> None:
    if not is_asset_kind(candidate.kind):
        return
    evaluated["lifecycle"] += 1
    if candidate.health == "down":
        emit(candidate, "lifecycle_health_down", detail_code="down")
    elif candidate.health == "degraded":
        emit(candidate, "lifecycle_health_degraded", detail_code="degraded")
    elif candidate.health == "unknown":
        emit(candidate, "lifecycle_health_unknown", detail_code="unknown")
    elif candidate.health == "maintenance":
        emit(candidate, "lifecycle_maintenance", detail_code="maintenance")


def _derive_monitoring(candidate, evaluated, emit) -> None:
    monitoring = candidate.monitoring
    if monitoring is None:
        return
    invalid = monitoring.get("diagnostic") == "invalid_monitoring_config"
    if not monitoring.get("enabled") and not invalid:
        # An absent or disabled monitoring document is exactly "not monitored".
        return
    evaluated["monitoring"] += 1
    evaluated["endpoint"] += 1
    if invalid:
        emit(candidate, "monitoring_config_invalid", detail_code="invalid_monitoring_config")
        return
    diagnostic = monitoring.get("diagnostic")
    if isinstance(diagnostic, str):
        emit(candidate, "endpoint_target_unresolved", detail_code=diagnostic)
    last_checked_at = monitoring.get("last_checked_at")
    if candidate.health == "maintenance":
        # Declared maintenance is authoritative: it silences the observed
        # incident without deleting or hiding the observation itself.
        return
    freshness = monitoring.get("freshness")
    if freshness == "pending":
        emit(candidate, "monitoring_never_observed")
        return
    if freshness == "stale":
        emit(
            candidate,
            "monitoring_observation_stale",
            detail_code=_detail(monitoring.get("observed_state")),
            observed_at=last_checked_at,
        )
        return
    state = monitoring.get("state")
    if state == "down":
        emit(
            candidate,
            "monitoring_observed_down",
            detail_code=_detail(monitoring.get("error_code")),
            observed_at=last_checked_at,
        )
    elif state == "check_error":
        emit(
            candidate,
            "monitoring_check_error",
            detail_code=_detail(monitoring.get("error_code")),
            observed_at=last_checked_at,
        )


def _derive_provenance(candidate, evaluated, emit, *, now: datetime) -> None:
    evaluated["provenance"] += 1
    if _is_past(candidate.provenance_stale_after, now):
        emit(
            candidate,
            "provenance_stale",
            observed_at=candidate.provenance_verified_at or candidate.provenance_observed_at,
        )
        return
    # The canonical provenance contract distinguishes knowing a source or its
    # observation time from actually verifying the record. A missing
    # `verified_at` therefore remains unknown even when those other fields are
    # present; it must not be guessed current merely because `is_stale` is false.
    if candidate.provenance_verified_at is None:
        emit(candidate, "provenance_unverified")


def _derive_runbook(candidate, evaluated, emit, *, now: datetime) -> None:
    if candidate.kind != "runbook":
        return
    evaluated["runbook"] += 1
    status = candidate.data.get("runbook_status")
    detail_code = _detail(status) if status in RUNBOOK_STATUS_VALUES else None
    review_after = _text(candidate.data.get("review_after"))
    if _is_past(review_after, now):
        emit(
            candidate,
            "runbook_review_overdue",
            detail_code=detail_code,
            observed_at=review_after,
        )
        return
    if status in _CURRENT_RUNBOOK_STATUSES and _text(
        candidate.data.get("last_verified_at")
    ) is None:
        emit(candidate, "runbook_unverified", detail_code=detail_code)
        return
    if (
        status == "deprecated"
        and _text(candidate.data.get("deprecation_rationale")) is None
        and _text(candidate.data.get("successor_recommendation")) is None
    ):
        emit(candidate, "runbook_deprecated_unresolved", detail_code=detail_code)


def _derive_knowledge(candidate, evaluated, emit, *, now: datetime) -> None:
    if candidate.kind == "decision":
        status_key, current = "decision_status", _CURRENT_DECISION_STATUSES
    elif candidate.kind == "project":
        status_key, current = "project_status", _CURRENT_PROJECT_STATUSES
    else:
        return
    evaluated["knowledge"] += 1
    status = candidate.data.get(status_key)
    detail_code = _detail(status) if status in ATTENTION_DETAIL_CODES else None
    review_after = _text(candidate.data.get("review_after"))
    if _is_past(review_after, now):
        emit(
            candidate,
            "knowledge_review_overdue",
            detail_code=detail_code,
            observed_at=review_after,
        )
        return
    if review_after is None and status in current:
        emit(candidate, "knowledge_review_unscheduled", detail_code=detail_code)


def _category_signal_state(
    category: str,
    *,
    evaluated: int,
    states: set[str],
    coverage_collected: bool,
) -> AttentionSignalState:
    if category == "source_coverage" and not coverage_collected:
        # "Never collected" is explicitly unknown; it must not be reported as a
        # clean coverage result.
        return "unknown"
    if evaluated == 0:
        return "not_applicable"
    if "stale" in states:
        return "stale"
    if "unknown" in states:
        return "unknown"
    return "current"


def _detail(value: Any) -> str | None:
    return value if isinstance(value, str) and value in ATTENTION_DETAIL_CODES else None


def _text(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    return normalized or None


def _is_past(value: str | None, now: datetime) -> bool:
    if value is None:
        return False
    try:
        boundary = parse_rfc3339_utc(value)
    except ValueError:
        # A malformed stored timestamp is a record-integrity concern, not a
        # licence to invent an overdue review.
        return False
    return boundary <= now
