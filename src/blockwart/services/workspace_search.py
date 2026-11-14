"""Closed, permission-first search of current records and project chronology."""

from __future__ import annotations

import json
import unicodedata
from dataclasses import dataclass
from urllib.parse import quote

from sqlalchemy import select
from sqlalchemy.orm import Session

from blockwart.domain.auth import ObjectVisibility
from blockwart.domain.search import normalize_search_text
from blockwart.models import CatalogObject, ObjectComment, ProjectRecord
from blockwart.schemas.workspace_search import (
    WorkspaceSearchHitOut,
    WorkspaceSearchKind,
    WorkspaceSearchPageOut,
)
from blockwart.services.commands import CommandNotFound, CommandValidationFailed
from blockwart.services.pagination import paginate_items
from blockwart.services.project_workspace import read_project
from blockwart.services.read_access import ReadAccess


@dataclass(frozen=True)
class _ProjectSearchHit:
    project_id: str
    project_label: str
    kind: str
    id: str
    title: str
    excerpt: str
    url: str


@dataclass(frozen=True)
class _ProjectSearchPage:
    items: list[WorkspaceSearchHitOut | _ProjectSearchHit]
    next_cursor: str | None
    total: int


def _record_text(kind: str, data: dict) -> str:
    # Deliberately not a recursive JSON traversal: imported extensions, references,
    # credential identifiers, secret locations and historical versions stay out.
    if kind == "page":
        return "\n".join(
            value for key in ("title", "body") if isinstance(value := data.get(key), str)
        )
    values = [
        data.get(key) for key in ("title", "description", "assignee", "blocked_reason", "issue_url")
    ]
    for key, fields in (
        ("requirement", ("original", "change_reason", "source_url")),
        ("evidence", ("subject", "scope", "limitations", "source_url")),
    ):
        nested = data.get(key)
        if isinstance(nested, dict):
            values.extend(nested.get(field) for field in fields)
    criteria = data.get("criteria", [])
    if isinstance(criteria, list):
        values.extend(row.get("description") for row in criteria if isinstance(row, dict))
    return "\n".join(value for value in values if isinstance(value, str))


def _excerpt(text: str, term: str) -> str:
    """A 300-character, case-preserving window around the normalized match."""
    display = " ".join(unicodedata.normalize("NFKC", text).split())
    position = display.casefold().find(term)
    # Case folding can expand characters (ß → ss), so map the offset back.
    offset, match = 0, 0
    for index, char in enumerate(display):
        offset += len(char.casefold())
        if offset > position:
            match = index
            break
    start = max(0, match - 60)
    window = display[start : start + 298]
    return ("…" if start else "") + window + ("…" if start + 298 < len(display) else "")


def read_workspace_chronology_entry(
    session: Session, access: ReadAccess, *, object_id: str, entry_id: str
):
    project = read_project(session, access, object_id)
    entry = session.scalar(
        select(ObjectComment).where(
            ObjectComment.id == entry_id,
            ObjectComment.object_id == project.id,
            ObjectComment.object_instance_id == project.instance_id,
            ObjectComment.object_created_at == project.created_at,
        )
    )
    if entry is None:
        raise CommandNotFound("Chronology entry not found")
    return project, entry


def search_workspaces(
    session: Session,
    access: ReadAccess,
    *,
    q: str,
    project_id: str | None = None,
    kind: WorkspaceSearchKind | None = None,
    limit: int = 50,
    cursor: str | None = None,
    project_category: str | None = None,
    project_status: str | None = None,
    include_projects: bool = False,
) -> WorkspaceSearchPageOut | _ProjectSearchPage:
    """Search authorized current project records with optional UI-only project hits.

    Args:
        session: Caller-owned database session.
        access: Existing principal and policy snapshot.
        q: Literal normalized text, at most 200 characters.
        project_id: Optional project restriction.
        kind: Existing public content type restriction.
        limit: Page size between one and 100.
        cursor: Query- and principal-bound continuation.
        project_category: UI-only project category restriction.
        project_status: UI-only project status restriction.
        include_projects: Include labeled project hits in a private UI projection.

    Returns:
        Existing public envelope by default, or private project-domain page.
    """
    term = normalize_search_text(q)
    if (
        not term
        or len(q) > 200
        or not 1 <= limit <= 100
        or kind not in {None, "item", "page", "chronology"}
    ):
        raise CommandValidationFailed("Invalid workspace search")
    # No record body, excerpt, count or project label is considered before DETAIL
    # access is established. Discover-only and concealed projects are both absent.
    projects = {
        project.instance_id: project
        for project in session.scalars(select(CatalogObject).where(CatalogObject.kind == "project"))
        if (project_id is None or project.id == project_id)
        and access.policy.visibility_for(project.id) == ObjectVisibility.DETAIL
    }
    if project_category or project_status:
        projects = {
            identity: project
            for identity, project in projects.items()
            if (
                not project_category
                or json.loads(project.data_json).get("category") == project_category
            )
            and (
                not project_status
                or json.loads(project.data_json).get("project_status") == project_status
            )
        }
    hits = []

    def add(project, record_kind, identity, title, text, url):
        if term in (normalize_search_text(text) or ""):
            hits.append(
                WorkspaceSearchHitOut(
                    project_id=project.id,
                    project_label=project.label,
                    kind=record_kind,
                    id=identity,
                    title=title,
                    excerpt=_excerpt(text, term),
                    url=url,
                )
            )

    if include_projects:
        # Reuse the catalog's authorized searchable projection, not raw project JSON.
        from blockwart.services.queries import query_catalog_browse

        matching = {
            item.id
            for item in query_catalog_browse(session, access, query=q, kind="project").objects
        }
        for project in projects.values():
            if project.id in matching:
                hits.append(
                    _ProjectSearchHit(
                        project_id=project.id,
                        project_label=project.label,
                        kind="project",
                        id=project.id,
                        title=project.label,
                        excerpt=project.label,
                        url=f"/projects/{quote(project.id, safe='')}",
                    )
                )
    if projects and kind != "chronology":
        rows = session.scalars(
            select(ProjectRecord).where(
                ProjectRecord.project_instance_id.in_(projects),
                ProjectRecord.kind.in_([kind] if kind else ["item", "page"]),
            )
        )
        for row in rows:
            project = projects[row.project_instance_id]
            data = json.loads(row.data_json)
            add(
                project,
                row.kind,
                row.id,
                data["title"],
                _record_text(row.kind, data),
                f"/projects/{quote(project.id, safe='')}/workspace/record/{quote(row.id, safe='')}",
            )
    if projects and kind in {None, "chronology"}:
        rows = session.scalars(
            select(ObjectComment)
            .join(
                CatalogObject,
                (
                    (ObjectComment.object_id == CatalogObject.id)
                    & (ObjectComment.object_instance_id == CatalogObject.instance_id)
                    & (ObjectComment.object_created_at == CatalogObject.created_at)
                ),
            )
            .where(CatalogObject.instance_id.in_(projects))
        )
        for row in rows:
            project = projects[row.object_instance_id]
            add(
                project,
                "chronology",
                row.id,
                row.project_chronology_kind or "note",
                row.body,
                f"/projects/{quote(project.id, safe='')}/chronology/{quote(row.id, safe='')}",
            )
    page = paginate_items(
        hits,
        key=lambda hit: (hit.project_id, f"{hit.kind}:{hit.id}"),
        limit=limit,
        resource="workspace/search",
        sort="identity",
        direction="asc",
        query={
            "q": term,
            **(
                {
                    "project_category": project_category,
                    "project_status": project_status,
                    "include_projects": True,
                }
                if include_projects
                else {}
            ),
            "project_id": project_id,
            "kind": kind,
            "access": access.cursor_scope,
            "instances": sorted(projects),
        },
        cursor=cursor,
        include_total=True,
    )
    if include_projects:
        return _ProjectSearchPage(items=page.items, next_cursor=page.next_cursor, total=page.total)
    return WorkspaceSearchPageOut(items=page.items, next_cursor=page.next_cursor, total=page.total)
