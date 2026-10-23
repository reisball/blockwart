"""Typed PM semantics shared by UI, API and MCP. Refs #288–#296.

Project locking/CAS and authorization stay in save_record. No automatic
classification of existing records, external writes or semantic acceptance.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import select

from blockwart.domain.timestamps import format_rfc3339_utc
from blockwart.models import (
    IdempotencyRecord,
    Principal,
    ProjectRecord,
    ProjectRecordEvent,
    ProjectRecordVersion,
)
from blockwart.schemas.project_workspace import (
    RECORD_ADAPTER,
    ProjectActionIn,
    ProjectEventOut,
    ProjectEventPageOut,
)
from blockwart.services.commands import (
    CommandConflict,
    CommandPreconditionFailed,
    CommandValidationFailed,
)
from blockwart.services.pagination import paginate_items
from blockwart.services.project_workspace import (
    _record,
    read_project,
    record_out,
    save_record,
)
from blockwart.services.read_access import ReadAccess

RELATION_TYPES = {
    "implements": ({"task", "decision"}, {"requirement"}),
    "applies_to": ({"requirement"}, {"use_case"}),
    "depends_on": (
        {"task", "question", "blocker", "decision"},
        {"task", "question", "blocker", "decision"},
    ),
    "precedes": ({"task", "question", "decision"}, {"task", "question", "decision"}),
    "blocked_by": ({"task", "question", "requirement", "use_case"}, {"blocker"}),
    "supersedes": ({"requirement", "page"}, {"requirement", "page"}),
    "informed_by": (
        {"task", "question", "blocker", "decision", "requirement", "use_case", "page"},
        {"page", "evidence"},
    ),
    "documents": ({"page"}, {"task", "decision", "requirement", "use_case", "evidence"}),
    "evidence_for": ({"evidence"}, {"requirement"}),
}


def _rows(session, project):
    return session.scalars(
        select(ProjectRecord).where(ProjectRecord.project_instance_id == project.instance_id)
    ).all()


def _type(data):
    return data.get("item_type") if data["kind"] == "item" else data["kind"]


def validate_record(session, context, project, identity, data, previous):
    """Validate the proposed complete graph under the project's write lock."""
    # Explicit baseline and provenance cannot be silently rewritten/erased.
    if previous:
        old = json.loads(previous.data_json)
        if old.get("legacy_origin") and data.get("legacy_origin") != old["legacy_origin"]:
            raise CommandValidationFailed("Legacy provenance is immutable")
        old_original = (old.get("requirement") or {}).get("original")
        if old_original and (data.get("requirement") or {}).get("original") != old_original:
            raise CommandValidationFailed("Original requirement is immutable; document a revision")
        if old.get("item_type") == "requirement" and any(
            old.get(k) != data.get(k) for k in ("title", "description", "criteria", "requirement")
        ):
            if not (data.get("requirement") or {}).get("change_reason"):
                raise CommandValidationFailed("Requirement changes need an explicit reason")
    parent_id = data.get("parent_id")
    if parent_id and data.get("item_type") in {"use_case", "requirement_group", "requirement"}:
        parent_type = _type(json.loads(_record(session, project, parent_id).data_json))
        allowed = {
            "use_case": {"use_case"},
            "requirement_group": {"use_case", "requirement_group"},
            "requirement": {"use_case", "requirement_group"},
        }[data["item_type"]]
        if parent_type not in allowed:
            raise CommandValidationFailed("Invalid parent for this semantic item type")
    # Capture referenced versions on new/explicitly refreshed documentation links.
    old_relations = json.loads(previous.data_json).get("relations", []) if previous else []
    for edge in data.get("relations", []):
        if edge["relation"] in {"documents", "informed_by"} and edge.get("target_version") is None:
            old_edge = next(
                (
                    e
                    for e in old_relations
                    if e["relation"] == edge["relation"] and e["target_id"] == edge["target_id"]
                ),
                None,
            )
            edge["target_version"] = (old_edge or {}).get("target_version") or _record(
                session, project, edge["target_id"]
            ).version
    rows = _rows(session, project)
    graph = {r.id: json.loads(r.data_json) for r in rows}
    graph[identity] = data
    # Revalidate inbound edges too: changing a target's type cannot orphan them.
    for source, value in graph.items():
        for edge in value.get("relations", []):
            target = edge["target_id"]
            if target not in graph:
                _record(session, project, target)  # conceal missing/cross-project targets
                raise CommandValidationFailed("Relationship endpoints must use canonical UUIDs")
            if source == target:
                raise CommandConflict("Self-relations are not allowed")
            left, right = RELATION_TYPES[edge["relation"]]
            if _type(value) not in left or _type(graph[target]) not in right:
                raise CommandValidationFailed("Invalid typed relation endpoints")
    for value in graph.values():
        parent = value.get("parent_id")
        typ = value.get("item_type")
        if parent and typ in {"use_case", "requirement_group", "requirement"}:
            allowed = {
                "use_case": {"use_case"},
                "requirement_group": {"use_case", "requirement_group"},
                "requirement": {"use_case", "requirement_group"},
            }[typ]
            if parent not in graph or _type(graph[parent]) not in allowed:
                raise CommandValidationFailed("Invalid semantic child after type change")
        ev = value.get("evidence")
        if ev and (
            ev["requirement_id"] not in graph or _type(graph[ev["requirement_id"]]) != "requirement"
        ):
            raise CommandValidationFailed("Existing evidence requires a requirement target")
    for value in graph.values():
        for edge in value.get("relations", []):
            target = graph[edge["target_id"]]
            if edge["relation"] == "supersedes" and _type(value) != _type(target):
                raise CommandValidationFailed("Supersession requires the same semantic type")
            version = edge.get("target_version")
            if version is not None:
                if edge["relation"] not in {"documents", "informed_by"}:
                    raise CommandValidationFailed("Only narrative references carry target versions")
                if session.get(ProjectRecordVersion, (edge["target_id"], version)) is None:
                    raise CommandValidationFailed("Referenced record version does not exist")
    # Dependency, ordering and supersession are separate DAGs. Hierarchy is
    # checked independently; reference-only links need not be acyclic.
    for family in ({"depends_on", "blocked_by"}, {"precedes"}, {"supersedes"}):
        indegree = dict.fromkeys(graph, 0)
        edges = {
            key: [e["target_id"] for e in value.get("relations", []) if e["relation"] in family]
            for key, value in graph.items()
        }
        for targets in edges.values():
            for target in targets:
                indegree[target] += 1
        queue = [key for key, degree in indegree.items() if degree == 0]
        count = 0
        while queue:
            key = queue.pop()
            count += 1
            for target in edges[key]:
                indegree[target] -= 1
                if indegree[target] == 0:
                    queue.append(target)
        if count != len(graph):
            raise CommandConflict("Relation graph cannot contain cycles")
    if data.get("assignee_principal_id"):
        principal = session.get(Principal, data["assignee_principal_id"])
        if principal is None or not principal.active:
            raise CommandValidationFailed("Assignee must be an active principal")
    if data["kind"] == "repository":
        key = (data["owner"].casefold(), data["name"].casefold())
        for key_id, value in graph.items():
            if (
                key_id != identity
                and value["kind"] == "repository"
                and (
                    (value["owner"].casefold(), value["name"].casefold()) == key
                    or data.get("github_id")
                    and value.get("github_id") == data["github_id"]
                )
            ):
                raise CommandConflict("Repository already linked")
    if data.get("kind") == "repository" and data.get("sync_enabled") and not data.get("github_id"):
        raise CommandValidationFailed(
            "Enable sync only after binding a stable GitHub repository ID"
        )
    for ref in data.get("github_references", []):
        target = _record(session, project, ref["repository_id"])
        if target.id != ref["repository_id"] or target.kind != "repository":
            raise CommandValidationFailed("GitHub reference must target a repository")
    evidence = data.get("evidence")
    if evidence:
        requirement = _record(session, project, evidence["requirement_id"])
        target = json.loads(requirement.data_json)
        if requirement.id != evidence["requirement_id"] or target.get("item_type") != "requirement":
            raise CommandValidationFailed("Evidence must target a requirement")
        if evidence["requirement_revision"] > requirement.requirement_revision:
            raise CommandValidationFailed("Unknown future requirement revision")
        # Old evidence retains its original criteria. For new evidence on a
        # historical revision, recover the actual historical requirement shape.
        criteria = _requirement_at_revision(session, requirement, evidence["requirement_revision"])
        if not set(evidence["criteria"]) <= {c["id"] for c in criteria}:
            raise CommandValidationFailed("Evidence cites unknown criteria")
    origin = data.get("legacy_origin")
    if origin and not previous:
        values = json.loads(project.data_json).get(origin["field"], [])
        if origin["index"] >= len(values) or values[origin["index"]] != origin["text"]:
            raise CommandPreconditionFailed("Legacy entry changed")
    if origin:
        for key, value in graph.items():
            if key != identity and value.get("legacy_origin") == origin:
                raise CommandConflict("Legacy entry already imported")
        if previous and json.loads(previous.data_json).get("legacy_origin") != origin:
            raise CommandValidationFailed("Legacy provenance cannot be replaced")


def _requirement_at_revision(session, row, revision):
    from blockwart.models import ProjectRecordVersion

    versions = session.scalars(
        select(ProjectRecordVersion)
        .where(ProjectRecordVersion.entry_id == row.id)
        .order_by(ProjectRecordVersion.version)
    ).all()
    last, current = None, 1
    for version in versions:
        data = json.loads(version.data_json)
        content = [data.get(k) for k in ("title", "description", "criteria", "requirement")]
        if last is not None and data.get("item_type") == "requirement" and content != last:
            current += 1
        last = content
        if data.get("item_type") == "requirement" and current == revision:
            return data.get("criteria", [])
    if revision == row.requirement_revision:
        return json.loads(row.data_json).get("criteria", [])
    raise CommandValidationFailed("Requirement revision not found")


def get_record(session, access, *, object_id, record_id):
    project = read_project(session, access, object_id)
    return record_out(session, access, _record(session, project, record_id))


def record_events(session, access, *, object_id, record_id, kind=None, limit=50, cursor=None):
    project = read_project(session, access, object_id)
    record = _record(session, project, record_id)
    rows = session.scalars(
        select(ProjectRecordEvent).where(
            ProjectRecordEvent.project_instance_id == project.instance_id,
            ProjectRecordEvent.record_id == record.id,
        )
    ).all()
    items = [
        ProjectEventOut(
            id=r.id,
            record_id=r.record_id,
            kind=r.kind,
            data=_event_projection(session, access, r),
            author_id=r.author_id,
            author_label=r.author_label,
            origin=r.origin,
            created_at=format_rfc3339_utc(r.created_at),
        )
        for r in rows
        if kind is None or r.kind == kind
    ]
    page = paginate_items(
        items,
        key=lambda r: (r.created_at, r.id),
        limit=limit,
        resource=f"projects/{object_id}/workspace/events/{record.id}",
        sort="created_at",
        direction="asc",
        query={"access": access.cursor_scope, "instance": project.instance_id, "kind": kind},
        cursor=cursor,
        include_total=True,
    )
    return ProjectEventPageOut(items=page.items, total=page.total, next_cursor=page.next_cursor)


def _event(session, project, row, context, kind, data):
    entry = ProjectRecordEvent(
        id=str(uuid4()),
        project_instance_id=project.instance_id,
        record_id=row.id,
        kind=kind,
        data_json=json.dumps(data, ensure_ascii=False, sort_keys=True),
        author_id=context.principal.id,
        author_label=context.principal.display_name,
        origin=context.channel,
        created_at=datetime.now(UTC).replace(tzinfo=None),
    )
    session.add(entry)
    return entry


def _all_events(session, project):
    return session.scalars(
        select(ProjectRecordEvent)
        .where(ProjectRecordEvent.project_instance_id == project.instance_id)
        .order_by(ProjectRecordEvent.created_at, ProjectRecordEvent.id)
    ).all()


def _last_assessment(events, identity, revision):
    return next(
        (
            json.loads(e.data_json)
            for e in reversed(events)
            if e.record_id == identity
            and e.kind == "assess"
            and json.loads(e.data_json).get("requirement_revision") == revision
        ),
        None,
    )


def _assessment(session, project, row, action):
    data = json.loads(row.data_json)
    if data.get("item_type") not in {"requirement", "use_case"}:
        raise CommandValidationFailed("Only requirements and use cases are assessed")
    rows = _rows(session, project)
    graph = {r.id: json.loads(r.data_json) for r in rows}
    descendants = _scope(graph, row.id)
    events = _all_events(session, project)
    by_id = {r.id: r for r in rows}
    required = {c["id"] for c in data.get("criteria", []) if c.get("required", True)}
    covered, snapshots = set(), []
    for identity in action.evidence_ids:
        evidence_row = _record(session, project, identity)
        evidence = json.loads(evidence_row.data_json).get("evidence")
        if not evidence or evidence["requirement_id"] != row.id:
            raise CommandValidationFailed("Evidence belongs to another requirement")
        if evidence["requirement_revision"] != row.requirement_revision:
            reused = any(
                e.kind == "reuse_evidence"
                and e.record_id == row.id
                and (entry := json.loads(e.data_json)).get("requirement_revision")
                == row.requirement_revision
                and {"id": evidence_row.id, "version": evidence_row.version}
                in entry.get("evidence", [])
                for e in _all_events(session, project)
            )
            if not reused:
                raise CommandValidationFailed("Historical evidence needs explicit reuse review")
        if evidence["outcome"] == "pass":
            covered.update(evidence["criteria"])
        snapshots.append(
            {"id": evidence_row.id, "version": evidence_row.version, "evidence": evidence}
        )
    missing = sorted(required - covered)
    open_work = sorted(
        key
        for key in descendants - {row.id}
        if graph[key].get("mandatory", True)
        and _work_status(by_id[key], rows, events) != "done"
        and graph[key].get("item_type") in {"task", "question", "blocker", "decision"}
    )
    events = _all_events(session, project)
    unaccepted = sorted(
        r.id
        for r in rows
        if r.id in descendants - {row.id}
        and graph[r.id].get("item_type") in {"requirement", "use_case"}
        and graph[r.id].get("mandatory", True)
        and (
            not (latest := _last_assessment(events, r.id, r.requirement_revision))
            or latest["result"] not in {"accepted", "exception"}
            or not _review_current(latest, r, rows, events)
        )
    )
    if action.result == "accepted":
        if (
            missing
            or open_work
            or unaccepted
            or (
                data.get("item_type") == "requirement"
                and (
                    not required
                    or (data.get("requirement") or {}).get("disposition", "active") != "active"
                )
            )
        ):
            raise CommandConflict(
                "Required criteria/work are not accepted; use a reasoned exception"
            )
        if data.get("item_type") == "use_case" and not any(
            v.get("item_type") == "requirement" for k, v in graph.items() if k in descendants
        ):
            raise CommandConflict("A use case without requirements needs an explicit exception")
    return {
        "result": action.result,
        "reason": action.reason,
        "requirement_revision": row.requirement_revision,
        "record_version": row.version,
        "evidence": snapshots,
        "missing_criteria": missing,
        "open_work": open_work,
        "unaccepted_requirements": unaccepted,
        "basis": _review_basis(row, rows, events),
    }


def apply_action(
    session,
    context,
    *,
    object_id,
    record_id,
    payload: ProjectActionIn,
    expected_record,
    idempotency_key,
    idempotency_ttl_seconds,
):
    access = ReadAccess(context.principal, context.policy)
    project = read_project(session, access, object_id)
    row = _record(session, project, record_id)
    data = json.loads(row.data_json)
    if payload.action == "patch":
        if {"kind", "legacy_origin"} & payload.changes.keys():
            raise CommandValidationFailed("Kind and legacy provenance are immutable")
        data.update(payload.changes)
    from pydantic import ValidationError

    try:
        record_payload = RECORD_ADAPTER.validate_python(data)
    except ValidationError as exc:
        raise CommandValidationFailed("Invalid record changes") from exc
    # save_record reserves/replays the complete action, locks, reauthorizes and
    # validates record-version CAS. Never use a stale merge without CAS.
    result = save_record(
        session,
        context,
        object_id=object_id,
        record_id=row.id,
        payload=record_payload,
        expected_revision=None,
        record_expected=expected_record,
        command_data=payload.model_dump(mode="json"),
        idempotency_key=idempotency_key,
        idempotency_ttl_seconds=idempotency_ttl_seconds,
    )
    if result.replayed:
        return result
    from dataclasses import replace

    from blockwart.services.policy import policy_for_principal

    # save_record acquired the principal/project locks and reauthorized. Do not
    # reuse the pre-lock policy for credential access or response projection.
    context = replace(context, policy=policy_for_principal(session, context.principal.id))
    access = ReadAccess(context.principal, context.policy)
    event_data = payload.model_dump(mode="json")
    if payload.action == "assess":
        event_data = _assessment(session, project, row, payload)
    elif payload.action == "reuse_evidence":
        if data.get("item_type") != "requirement":
            raise CommandValidationFailed("Evidence reuse belongs to a requirement")
        evidence_refs = []
        for identity in payload.evidence_ids:
            evidence_row = _record(session, project, identity)
            evidence = json.loads(evidence_row.data_json).get("evidence")
            if not evidence or evidence["requirement_id"] != row.id:
                raise CommandValidationFailed("Evidence belongs to another requirement")
            evidence_refs.append({"id": evidence_row.id, "version": evidence_row.version})
        event_data = {
            "requirement_revision": row.requirement_revision,
            "reason": payload.reason,
            "evidence": evidence_refs,
        }
    elif payload.action == "sync_github":
        from blockwart.services.project_github import sync_record

        event_data = sync_record(session, context, project, row)
    _event(session, project, row, context, payload.action, event_data)
    session.flush()
    result.record = record_out(session, access, row)
    idem = session.scalar(
        select(IdempotencyRecord).where(
            IdempotencyRecord.principal_id == context.principal.id,
            IdempotencyRecord.key_hash == hashlib.sha256(idempotency_key.encode()).hexdigest(),
        )
    )
    idem.response_json = result.model_dump_json()
    return result


def project_overview(session, access, *, object_id):
    project = read_project(session, access, object_id)
    rows = _rows(session, project)
    graph = {r.id: json.loads(r.data_json) for r in rows}
    events = _all_events(session, project)
    requirements = []
    for row in rows:
        data = graph[row.id]
        if data.get("item_type") != "requirement" or data.get("archived", False):
            continue
        implementations = [
            key
            for key, value in graph.items()
            if value.get("item_type") == "task"
            and any(
                e["relation"] == "implements" and e["target_id"] == row.id
                for e in value.get("relations", [])
            )
        ]
        evidence = [
            key
            for key, value in graph.items()
            if (value.get("evidence") or {}).get("requirement_id") == row.id
        ]
        assessment = _last_assessment(events, row.id, row.requirement_revision)
        if assessment and not _review_current(assessment, row, rows, events):
            assessment = {**assessment, "stale": True}
        requirements.append(
            {
                "record": record_out(session, access, row).model_dump(mode="json"),
                "implementations": implementations,
                "evidence": evidence,
                "assessment": assessment,
                "fulfillment": _fulfillment(row, rows, events),
                "without_implementation": not implementations,
                "without_verification": not _fulfillment(row, rows, events)["evidence_ids"],
                "mandatory": data.get("mandatory", True),
                "blocked_by": [
                    e["target_id"]
                    for e in data.get("relations", [])
                    if e["relation"] in {"blocked_by", "depends_on"}
                    and _work_status(next(r for r in rows if r.id == e["target_id"]), rows, events)
                    != "done"
                ],
            }
        )
    legacy = []
    project_data = json.loads(project.data_json)
    for field in ("open_questions", "blockers", "next_actions"):
        for index, value in enumerate(project_data.get(field, [])):
            origin = {"field": field, "index": index, "text": value}
            migrated, ambiguous = _legacy_match(
                rows, events, field, project_data.get(field, []), index
            )
            legacy.append(
                {
                    **origin,
                    "record_id": migrated.id if migrated else None,
                    "authority": "reconciliation_required"
                    if ambiguous
                    else "record"
                    if migrated
                    else "legacy",
                    "reconciliation_required": ambiguous,
                }
            )
    mandatory = [r for r in requirements if r["mandatory"]]
    return {
        "requirements": requirements,
        "legacy": legacy,
        "coverage": {
            "denominator": len(mandatory),
            "accepted": sum(
                bool(
                    r["assessment"]
                    and r["assessment"]["result"] == "accepted"
                    and not r["assessment"].get("stale")
                )
                for r in mandatory
            ),
            "exceptions": sum(
                bool(
                    r["assessment"]
                    and r["assessment"]["result"] == "exception"
                    and not r["assessment"].get("stale")
                )
                for r in mandatory
            ),
        },
        "summary_authority": "curated",
        "work_authority": "structured_records",
        "project_revision": project.revision,
    }


def _legacy_match(rows, events, field, values, index):
    """Unique text survives reordering; identical occurrences need exact provenance.

    Never guess an occurrence after duplicate source text was added/reordered.
    The immutable import snapshot remains untouched.
    """
    text = values[index]
    candidates = [
        row
        for row in rows
        if (origin := json.loads(row.data_json).get("legacy_origin"))
        and origin["field"] == field
        and origin["text"] == text
    ]
    if not candidates:
        return None, False
    if values.count(text) == 1 and len(candidates) == 1:
        return candidates[0], False
    fingerprint = hashlib.sha256(json.dumps(values).encode()).hexdigest()
    imported = {
        event.record_id: json.loads(event.data_json)
        for event in events
        if event.kind == "import_legacy"
    }
    if any(imported.get(row.id, {}).get("source_fingerprint") != fingerprint for row in candidates):
        return None, True
    matches = [
        row for row in candidates if json.loads(row.data_json)["legacy_origin"]["index"] == index
    ]
    return (matches[0], False) if len(matches) == 1 else (None, len(matches) > 1)


def import_legacy(
    session,
    context,
    *,
    object_id,
    field,
    index,
    text,
    expected_revision,
    idempotency_key,
    idempotency_ttl_seconds,
):
    from dataclasses import replace

    from blockwart.domain.auth import Permission
    from blockwart.models import CatalogObject
    from blockwart.schemas.project_workspace import ProjectItemIn, ProjectRecordCommandOut
    from blockwart.services.access import lock_principal_rows
    from blockwart.services.commands import (
        authorize_object_command,
        parse_if_match,
        reserve_idempotency_record,
        revision_etag,
    )
    from blockwart.services.policy import policy_for_principal
    from blockwart.services.project_workspace import _projected_data, require_record_origin

    authorize_object_command(session, context, object_id=object_id, permission=Permission.WRITE)
    require_record_origin(context, object_id)
    access = ReadAccess(context.principal, context.policy)
    project = read_project(session, access, object_id)
    origin = {"field": field, "index": index, "text": text}
    command = {"import": origin}
    expected = parse_if_match(expected_revision)
    current = json.loads(project.data_json).get(field, [])
    if index >= len(current) or current[index] != text:
        raise CommandPreconditionFailed("Legacy entry changed")
    existing, ambiguous = _legacy_match(
        _rows(session, project), _all_events(session, project), field, current, index
    )
    if ambiguous:
        raise CommandConflict(
            "Legacy occurrence is ambiguous; reconcile source provenance before importing"
        )
    if existing:
        idem, replay = reserve_idempotency_record(
            session,
            context,
            key=idempotency_key,
            operation_context=f"project_record:{project.instance_id}",
            request_payload={"command": command, "record_id": None, "revision": expected},
            ttl_seconds=idempotency_ttl_seconds,
            now=datetime.now(UTC).replace(tzinfo=None),
        )
        lock_principal_rows(session, (context.principal.id,))
        locked = session.scalar(
            select(CatalogObject)
            .where(CatalogObject.id == object_id, CatalogObject.instance_id == project.instance_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if locked is None:
            raise CommandPreconditionFailed("Project instance changed")
        context = replace(context, policy=policy_for_principal(session, context.principal.id))
        authorize_object_command(session, context, object_id=object_id, permission=Permission.WRITE)
        access = ReadAccess(context.principal, context.policy)
        if replay:
            result = ProjectRecordCommandOut.model_validate(replay)
            result.record.data = _projected_data(session, access, json.dumps(result.record.data))
            result.replayed = True
            return result
        current = json.loads(locked.data_json).get(field, [])
        if index >= len(current) or current[index] != text:
            raise CommandPreconditionFailed("Legacy entry changed")
        existing, ambiguous = _legacy_match(
            _rows(session, locked), _all_events(session, locked), field, current, index
        )
        if ambiguous or existing is None:
            raise CommandConflict("Legacy occurrence changed; review source provenance")
        result = ProjectRecordCommandOut(
            record=record_out(session, access, existing),
            revision=locked.revision,
            etag=revision_etag(locked.revision),
            replayed=True,
        )
        idem.resource_id = object_id
        idem.response_json = result.model_dump_json()
        return result
    current = json.loads(project.data_json).get(field, [])
    if index >= len(current) or current[index] != text:
        raise CommandPreconditionFailed("Legacy entry changed")
    kind = {"open_questions": "question", "blockers": "blocker", "next_actions": "task"}[field]
    result = save_record(
        session,
        context,
        object_id=object_id,
        record_id=None,
        payload=ProjectItemIn(
            kind="item", title=text[:255], description=text, item_type=kind, legacy_origin=origin
        ),
        expected_revision=expected_revision,
        idempotency_key=idempotency_key,
        command_data=command,
        idempotency_ttl_seconds=idempotency_ttl_seconds,
    )
    if not result.replayed:
        row = _record(session, project, result.record.id)
        _event(
            session,
            project,
            row,
            context,
            "import_legacy",
            {
                "origin": origin,
                "source_revision": expected,
                "source_fingerprint": hashlib.sha256(json.dumps(current).encode()).hexdigest(),
                "authority": "structured_record",
            },
        )
        session.flush()
    return result


def _scope(graph, identity):
    scope = {identity}
    while True:
        found = {key for key, value in graph.items() if value.get("parent_id") in scope}
        found |= {
            key
            for key, value in graph.items()
            if any(
                e["relation"] in {"applies_to", "implements"} and e["target_id"] in scope
                for e in value.get("relations", [])
            )
        }
        found |= {
            e["target_id"]
            for key in scope
            for e in graph[key].get("relations", [])
            if e["relation"] in {"blocked_by", "depends_on"}
        }
        if found <= scope:
            return scope
        scope |= found


def _review_basis(row, rows, events):
    graph = {r.id: json.loads(r.data_json) for r in rows}
    by_id = {r.id: r for r in rows}
    scope = _scope(graph, row.id)
    basis = {}
    for key in sorted(scope):
        value = graph[key]
        typ = value.get("item_type")
        if key == row.id or typ in {
            "requirement",
            "use_case",
            "task",
            "question",
            "blocker",
            "decision",
        }:
            basis[key] = {k: value.get(k) for k in ("status", "mandatory", "archived", "item_type")}
            basis[key]["status"] = _work_status(by_id[key], rows, events)
            if typ in {"requirement", "use_case"}:
                basis[key]["requirement_revision"] = by_id[key].requirement_revision
                if key != row.id:
                    last = next(
                        (
                            e.id
                            for e in reversed(events)
                            if e.record_id == key and e.kind == "assess"
                        ),
                        None,
                    )
                    basis[key]["assessment_id"] = last
    return basis


def _review_current(assessment, row, rows, events, seen=None):
    seen = set() if seen is None else seen
    if row.id in seen or assessment.get("basis") != _review_basis(row, rows, events):
        return False
    seen = seen | {row.id}
    by_id = {r.id: r for r in rows}
    if not all(
        item["id"] in by_id and by_id[item["id"]].version == item["version"]
        for item in assessment.get("evidence", [])
    ):
        return False
    graph = {r.id: json.loads(r.data_json) for r in rows}
    for key in _scope(graph, row.id) - {row.id}:
        data = graph[key]
        if data.get("item_type") not in {"requirement", "use_case"} or not data.get(
            "mandatory", True
        ):
            continue
        child = by_id[key]
        latest = _last_assessment(events, key, child.requirement_revision)
        if (
            not latest
            or latest["result"] not in {"accepted", "exception"}
            or not _review_current(latest, child, rows, events, seen)
        ):
            return False
    return True


def _external_for(row, rows, events):
    from blockwart.services.project_github import external_state

    data = json.loads(row.data_json)
    external = external_state([e for e in events if e.record_id == row.id], data)
    by_id = {r.id: r for r in rows}
    leading = data.get("leading_reference")
    for observation in (external.get("last_attempt") or {}).get("observations", []):
        if data.get("status_authority") == "github" and observation["reference"] != leading:
            continue
        repo = by_id.get(observation["reference"]["repository_id"])
        if repo is None or repo.version != observation.get("repository_record_version"):
            external["fresh"] = False
            if data.get("status_authority") == "github":
                external["effective_status"] = None
    return external


def _work_status(row, rows, events):
    return _external_for(row, rows, events)["effective_status"]


def record_context(session, row):
    """Derived context contains only same-project records, never secret metadata."""
    rows = session.scalars(
        select(ProjectRecord).where(ProjectRecord.project_instance_id == row.project_instance_id)
    ).all()
    by_id = {r.id: r for r in rows}
    data = json.loads(row.data_json)
    events = session.scalars(
        select(ProjectRecordEvent)
        .where(ProjectRecordEvent.project_instance_id == row.project_instance_id)
        .order_by(ProjectRecordEvent.created_at, ProjectRecordEvent.id)
    ).all()
    assessment = _last_assessment(events, row.id, row.requirement_revision)
    if assessment:
        assessment = {**assessment, "stale": not _review_current(assessment, row, rows, events)}
    blockers = []
    stale_links = []
    for edge in data.get("relations", []):
        target = by_id.get(edge["target_id"])
        if target is None:
            continue
        target_data = json.loads(target.data_json)
        if (
            edge["relation"] in {"depends_on", "blocked_by"}
            and _work_status(target, rows, events) != "done"
        ):
            blockers.append(
                {
                    "id": target.id,
                    "short_code": target.short_code,
                    "title": target_data["title"],
                    "archived": target_data.get("archived", False),
                }
            )
        if edge.get("target_version") and target.version != edge["target_version"]:
            stale_links.append(edge["target_id"])
    external = _external_for(row, rows, events)
    return {
        "assessment": assessment,
        "fulfillment": _fulfillment(row, rows, events)
        if data.get("item_type") == "requirement"
        else None,
        "successors": [
            r.id
            for r in rows
            if any(
                e["relation"] == "supersedes" and e["target_id"] == row.id
                for e in json.loads(r.data_json).get("relations", [])
            )
        ],
        "blockers": blockers,
        "stale_relations": stale_links,
        "external": external,
    }


def _fulfillment(row, rows, events):
    data = json.loads(row.data_json)
    criteria = data.get("criteria", [])
    evidence = []
    for target in rows:
        entry = json.loads(target.data_json).get("evidence")
        if not entry or entry["requirement_id"] != row.id:
            continue
        reusable = entry["requirement_revision"] == row.requirement_revision or any(
            e.record_id == row.id
            and e.kind == "reuse_evidence"
            and (payload := json.loads(e.data_json)).get("requirement_revision")
            == row.requirement_revision
            and {"id": target.id, "version": target.version} in payload.get("evidence", [])
            for e in events
        )
        if reusable:
            evidence.append((target.id, entry))
    states = []
    for criterion in criteria:
        outcomes = {e["outcome"] for _, e in evidence if criterion["id"] in e["criteria"]}
        outcome = (
            "unverified"
            if not outcomes
            else next(iter(outcomes))
            if len(outcomes) == 1
            else "mixed"
        )
        states.append({**criterion, "outcome": outcome})
    required = [c for c in states if c.get("required", True)]
    passed = sum(c["outcome"] == "pass" for c in required)
    status = (
        "verified"
        if required and passed == len(required)
        else "partial"
        if evidence
        else "unverified"
    )
    disposition = (data.get("requirement") or {}).get("disposition", "active")
    if disposition != "active":
        status = disposition
    return {
        "status": status,
        "criteria": states,
        "denominator": len(required),
        "passed": passed,
        "evidence_ids": [identity for identity, _ in evidence],
        "requirement_revision": row.requirement_revision,
    }


def _event_projection(session, access, row):
    """Apply the same live reference concealment as current/history reads."""
    from blockwart.services.project_workspace import _projected_data

    data = json.loads(row.data_json)
    if row.kind == "patch":
        changes = data.get("changes", {})
        changes.pop("new_credential_reference", None)
        data["changes"] = _projected_data(session, access, json.dumps(changes))
    return data
