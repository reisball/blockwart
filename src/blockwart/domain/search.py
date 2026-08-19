"""The central, typed catalog search contract shared by every read surface.

REST v1, the legacy Agent API, and the MCP wrapper converge on one query
contract, one closed search projection, and one deterministic rank ladder, so
the three surfaces cannot drift apart.

Three things are deliberately closed here:

* **The query contract.** ``SearchQuery`` carries the free-text term, the match
  mode, the operational filter, and every structured filter. Boundaries parse
  transport input and build this object; nothing below it re-reads request
  state.
* **The searched projection.** Free text is compared against a
  server-defined allowlist of bounded fields, never against the serialized
  catalog document, the provenance header, or an arbitrary imported body.
  Generic migration and import metadata therefore cannot produce broad
  false-positive matches.
* **The rank ladder.** Matches are ordered by the fixed precedence
  ``exact ref/id`` → ``exact label`` → ``identity`` → ``structured domain
  field`` → ``top-level summary`` → ``other allowlisted field``. The ladder is
  a pure function of already-authorized values, so ranking a concealed or
  discover-only object can never depend on a value its reader may not see.

No semantic, vector, embedding, or model-based ranking exists in this module,
and none may be added to it: every decision below is an explicit, reviewable
comparison of normalized strings.
"""

from __future__ import annotations

import unicodedata
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal

from blockwart.domain.asset_state import AssetHealth, AssetLifecycle
from blockwart.domain.decisions import DecisionStatus
from blockwart.domain.projects import ProjectCategory, ProjectStatus
from blockwart.domain.provenance import SourceType
from blockwart.domain.runbooks import RunbookRisk, RunbookStatus

SearchMatchMode = Literal["normal", "exact_ref", "exact_label"]
SEARCH_MATCH_MODES: tuple[SearchMatchMode, ...] = (
    "normal",
    "exact_ref",
    "exact_label",
)

# The published maximum length of a free-text search term. Boundaries reject a
# longer term instead of truncating it, so two different terms cannot collapse
# into the same query.
SEARCH_TEXT_MAX_LENGTH = 200

# The published hard bounds of every search page size. Each surface may publish
# a smaller maximum for its own resource, but never a larger one.
SEARCH_LIMIT_MIN = 1
SEARCH_LIMIT_MAX = 100
CONTEXT_LIMIT_MAX = 20
AGENT_SEARCH_LIMIT_MAX = 50

# Deterministic rank precedence. A lower value wins; the ladder is published
# so a client can reason about ordering without reading server code.
RANK_EXACT_REF = 0
RANK_EXACT_LABEL = 1
RANK_IDENTITY = 2
RANK_DOMAIN_FIELD = 3
RANK_SUMMARY = 4
RANK_SECONDARY_FIELD = 5
# Every object of a query without free text shares one rank, so relevance
# ordering degrades to its stable label/id tie-breaker instead of becoming
# arbitrary.
RANK_UNRANKED = 9

SEARCH_SNIPPET_MAX_LENGTH = 240
SNIPPET_TRUNCATION_MARKER = "…"

# Bounded projection work per object: a damaged or unusually large document
# cannot turn one search into unbounded string scanning.
_MAX_PROJECTED_VALUES = 64
_MAX_PROJECTED_VALUE_LENGTH = 4000

# The canonical knowledge field a detailed summary falls back to when an object
# carries no top-level summary. Every entry is an authorized, bounded, curated
# text field of that kind; no other data path may be added without review.
KNOWLEDGE_SNIPPET_FIELDS: Mapping[str, str] = {
    "decision": "decision",
    "project": "current_summary",
    "runbook": "purpose",
}

# Structured domain fields shared by the asset kinds. These are the values an
# operator actually searches for: names, addresses, and endpoints.
_ASSET_DOMAIN_FIELDS: tuple[str, ...] = (
    "network.hostnames[]",
    "network.addresses[].ip",
    "endpoints[].host",
    "endpoints[].url",
    "endpoints[].type",
)
_ASSET_SECONDARY_FIELDS: tuple[str, ...] = (
    "network.location",
    "network.manufacturer",
    "network.model",
    "installed_software[].name",
    "owner",
)

# The closed per-kind search projection. A path absent from this table is never
# compared against a search term, however the document was imported. In
# particular `sources`, `docs`, `source_references`, `schema_version`,
# `components`, `monitoring`, `credential_references`, and every command body
# stay out: they carry generic import, migration, and boilerplate text.
_DOMAIN_FIELDS: Mapping[str, tuple[str, ...]] = {
    "host": _ASSET_DOMAIN_FIELDS,
    "system": _ASSET_DOMAIN_FIELDS,
    "service": _ASSET_DOMAIN_FIELDS,
    "network": _ASSET_DOMAIN_FIELDS,
    "device": _ASSET_DOMAIN_FIELDS,
    "decision": ("decision",),
    "project": ("current_summary", "objective"),
    "runbook": ("purpose",),
}
_SECONDARY_FIELDS: Mapping[str, tuple[str, ...]] = {
    "host": _ASSET_SECONDARY_FIELDS,
    "system": _ASSET_SECONDARY_FIELDS,
    "service": _ASSET_SECONDARY_FIELDS,
    "network": _ASSET_SECONDARY_FIELDS,
    "device": _ASSET_SECONDARY_FIELDS,
    "decision": ("context", "rationale", "consequences[]", "alternatives[]"),
    "project": (
        "next_actions[]",
        "open_questions[]",
        "blockers[]",
        "in_scope[]",
        "out_of_scope[]",
    ),
    "runbook": (
        "in_scope[]",
        "out_of_scope[]",
        "approval_requirement",
        "steps[].title",
    ),
}

# The canonical non-operational states of `operational_only=true`. Object
# status and asset lifecycle are canonical columns; the knowledge entries are
# the canonical retired family of each knowledge kind. Nothing else is
# filtered, so the flag never silently hides an active record.
NON_OPERATIONAL_STATUSES: frozenset[str] = frozenset({"inactive", "deleted"})
NON_OPERATIONAL_LIFECYCLE: str = "retired"
RETIRED_KNOWLEDGE_STATUSES: Mapping[str, frozenset[str]] = {
    "decision": frozenset({"superseded", "deprecated"}),
    "project": frozenset({"archived"}),
    "runbook": frozenset({"retired", "superseded", "deprecated"}),
}
_KNOWLEDGE_STATUS_FIELDS: Mapping[str, str] = {
    "decision": "decision_status",
    "project": "project_status",
    "runbook": "runbook_status",
}


def normalize_search_text(value: str | None) -> str | None:
    """Return the one canonical comparison form of a search term or label.

    The published normalization is identical for the query text, the compared
    label, and the compared canonical reference: Unicode NFKC, whitespace runs
    collapsed to a single space, surrounding whitespace removed, and case
    folded. An empty result is returned as ``None`` so a blank term is exactly
    an absent term.
    """
    if value is None:
        return None
    collapsed = " ".join(unicodedata.normalize("NFKC", value).split())
    return collapsed.casefold() or None


@dataclass(frozen=True, slots=True)
class SearchQuery:
    """One immutable, fully typed catalog search request.

    ``kind`` is typed as a plain string here because the published kind
    vocabulary lives in the transport schema; every boundary validates it
    against that closed vocabulary before building this object.
    """

    query: str | None = None
    match: SearchMatchMode = "normal"
    operational_only: bool = False
    kind: str | None = None
    parent: str | None = None
    ip: str | None = None
    port: int | None = None
    endpoint_type: str | None = None
    protocol: str | None = None
    exposure: str | None = None
    status: str | None = None
    decision_status: DecisionStatus | None = None
    applies_to: str | None = None
    runbook_status: RunbookStatus | None = None
    runbook_risk: RunbookRisk | None = None
    project_category: ProjectCategory | None = None
    project_status: ProjectStatus | None = None
    related_object: str | None = None
    lifecycle: AssetLifecycle | None = None
    health: AssetHealth | None = None
    source_type: SourceType | None = None
    stale: bool | None = None

    @property
    def term(self) -> str | None:
        """The normalized free-text term, or ``None`` when no text was sent."""
        return normalize_search_text(self.query)

    @property
    def is_exact(self) -> bool:
        return self.match != "normal"

    @property
    def has_detail_filters(self) -> bool:
        """Whether this query evaluates values a discover-only stub conceals.

        Detail filters exclude stubs rather than probing their hidden values,
        so `operational_only` joins the existing detail filters instead of
        reading canonical state a stub never publishes.
        """
        return bool(
            self.operational_only
            or self.status
            or self.decision_status
            or self.applies_to
            or self.runbook_status
            or self.runbook_risk
            or self.project_category
            or self.project_status
            or self.related_object
            or self.lifecycle
            or self.health
            or self.ip
            or self.endpoint_type
            or self.protocol
            or self.exposure
            or self.port is not None
            or self.source_type is not None
            or self.stale is not None
        )

    def cursor_fields(self) -> dict[str, object]:
        """Return the fingerprint fields a cursor of this query binds.

        Every search parameter appears exactly once, in its normalized form, so
        a cursor cannot be replayed against a different term, match mode,
        operational filter, or structured filter.
        """
        return {
            "applies_to": self.applies_to,
            "decision_status": self.decision_status,
            "endpoint_type": _normalized_filter(self.endpoint_type),
            "exposure": _normalized_filter(self.exposure),
            "health": self.health,
            "ip": self.ip,
            "kind": self.kind,
            "lifecycle": self.lifecycle,
            "match": self.match,
            "operational_only": self.operational_only,
            "parent": self.parent,
            "port": self.port,
            "project_category": self.project_category,
            "project_status": self.project_status,
            "protocol": _normalized_filter(self.protocol),
            "q": self.term,
            "related_object": self.related_object,
            "runbook_risk": self.runbook_risk,
            "runbook_status": self.runbook_status,
            "source_type": self.source_type,
            "stale": self.stale,
            "status": _normalized_filter(self.status),
        }


# The empty query. It is an immutable module-level value so a service default
# argument stays a constant rather than a per-call construction.
EMPTY_SEARCH = SearchQuery()


def rank_match(
    query: SearchQuery,
    *,
    ref: str,
    object_id: str,
    label: str,
    summary: str | None,
    kind: str,
    data: Mapping[str, Any] | None,
) -> int | None:
    """Return the deterministic rank of one authorized object, or ``None``.

    ``None`` means the object does not match the active free-text term and must
    be dropped from the result set. ``data`` is the caller's already authorized
    and secret-redacted projection; a discover-only stub passes ``None``, so
    only its identity fields can ever be compared.
    """
    term = query.term
    if term is None:
        return RANK_UNRANKED
    normalized_ref = normalize_search_text(ref)
    normalized_id = normalize_search_text(object_id)
    normalized_label = normalize_search_text(label)
    if query.match == "exact_ref":
        return RANK_EXACT_REF if term in {normalized_ref, normalized_id} else None
    if query.match == "exact_label":
        return RANK_EXACT_LABEL if term == normalized_label else None
    if term in {normalized_ref, normalized_id}:
        return RANK_EXACT_REF
    if term == normalized_label:
        return RANK_EXACT_LABEL
    if _contains(term, (normalized_id, normalized_label)):
        return RANK_IDENTITY
    if data is None:
        return None
    if _contains(term, _projected_values(kind, data, _DOMAIN_FIELDS)):
        return RANK_DOMAIN_FIELD
    if _contains(term, (normalize_search_text(summary),)):
        return RANK_SUMMARY
    if _contains(term, _projected_values(kind, data, _SECONDARY_FIELDS)):
        return RANK_SECONDARY_FIELD
    return None


def is_operational(
    *,
    kind: str,
    status: str | None,
    lifecycle: str | None,
    data: Mapping[str, Any],
) -> bool:
    """Whether one authorized object survives ``operational_only=true``.

    Inactive and deleted object status and the retired asset lifecycle are read
    from the canonical columns. A knowledge object additionally leaves the
    operational set once its canonical status enters the retired family of its
    kind.
    """
    if status is not None and (normalize_search_text(status) in NON_OPERATIONAL_STATUSES):
        return False
    if lifecycle is not None and normalize_search_text(lifecycle) == NON_OPERATIONAL_LIFECYCLE:
        return False
    retired_statuses = RETIRED_KNOWLEDGE_STATUSES.get(kind)
    if retired_statuses is None:
        return True
    knowledge_status = data.get(_KNOWLEDGE_STATUS_FIELDS[kind])
    if not isinstance(knowledge_status, str):
        return True
    return normalize_search_text(knowledge_status) not in retired_statuses


def search_snippet(
    *,
    kind: str,
    summary: str | None,
    data: Mapping[str, Any],
) -> str | None:
    """Return the bounded snippet of one detailed, authorized search summary.

    The top-level summary wins. Without one, exactly the canonical knowledge
    field of the kind is used: Runbook `purpose`, Decision `decision`, or
    Project `current_summary`. No other data path, no full document, no
    provenance value, and no diagnostic ever becomes a snippet, and the caller
    must pass an already authorized, secret-redacted projection.
    """
    candidate = summary if isinstance(summary, str) and summary.strip() else None
    if candidate is None:
        field = KNOWLEDGE_SNIPPET_FIELDS.get(kind)
        if field is not None:
            value = data.get(field)
            candidate = value if isinstance(value, str) and value.strip() else None
    if candidate is None:
        return None
    collapsed = " ".join(candidate.split())
    if len(collapsed) <= SEARCH_SNIPPET_MAX_LENGTH:
        return collapsed
    # The truncation marker counts towards the published maximum, so the
    # returned snippet is never longer than `SEARCH_SNIPPET_MAX_LENGTH`.
    kept = SEARCH_SNIPPET_MAX_LENGTH - len(SNIPPET_TRUNCATION_MARKER)
    return collapsed[:kept].rstrip() + SNIPPET_TRUNCATION_MARKER


def _normalized_filter(value: str | None) -> str | None:
    return value.casefold() if value else None


def _contains(term: str, values: Iterable[str | None]) -> bool:
    return any(value is not None and term in value for value in values)


def _projected_values(
    kind: str,
    data: Mapping[str, Any],
    projection: Mapping[str, tuple[str, ...]],
) -> list[str]:
    """Collect the normalized values of one closed field projection."""
    collected: list[str] = []
    for path in projection.get(kind, ()):
        for value in _values_at(data, path.split(".")):
            normalized = normalize_search_text(value[:_MAX_PROJECTED_VALUE_LENGTH])
            if normalized is not None:
                collected.append(normalized)
            if len(collected) >= _MAX_PROJECTED_VALUES:
                return collected
    return collected


def _values_at(value: Any, segments: Sequence[str]) -> list[str]:
    """Resolve one allowlisted path, where a `[]` suffix walks an array."""
    if not segments:
        return [value] if isinstance(value, str) else []
    head, *rest = segments
    key, _, marker = head.partition("[")
    if key:
        if not isinstance(value, Mapping):
            return []
        value = value.get(key)
    if marker:
        if not isinstance(value, list):
            return []
        resolved: list[str] = []
        for item in value[:_MAX_PROJECTED_VALUES]:
            resolved.extend(_values_at(item, rest))
        return resolved
    return _values_at(value, rest)
