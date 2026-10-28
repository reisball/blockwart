"""One graph reach contract for policy, scope previews and Owner protection."""
from __future__ import annotations

from sqlalchemy import and_, literal, or_, select
from sqlalchemy.orm import aliased

from blockwart.domain.auth import GrantScope
from blockwart.domain.placement import CANONICAL_PLACEMENT_RELATION_TYPE
from blockwart.models import CatalogObject, Relationship

OPERATIONS_RUNBOOK_RELATION = "operations_runbook_for"
RESPONSIBILITY_KINDS = ("host", "system", "service")
AUTHORITY_RELATION_TYPES = (CANONICAL_PLACEMENT_RELATION_TYPE, OPERATIONS_RUNBOOK_RELATION)


def grant_reach_cte(roots, *, name: str):
    """Traverse only canonical placement and explicit reverse Operations links.

    Roots carry object_id/object_ref/object_kind/scope and optional provenance.
    A Runbook is a terminal: neither arbitrary links nor its data extend ownership.
    Credentials are deliberately absent from this Owner reach.
    """
    child = aliased(CatalogObject)
    child_ref = child.kind + literal(":") + child.id
    reach = roots.cte(name, recursive=True)
    placement = and_(
        reach.c.scope.in_((GrantScope.SUBTREE, GrantScope.RESPONSIBILITY)),
        Relationship.relation_type == CANONICAL_PLACEMENT_RELATION_TYPE,
        Relationship.from_ref == reach.c.object_ref,
        Relationship.to_ref == child_ref,
        or_(
            and_(reach.c.object_kind == "host", child.kind.in_(("system", "service"))),
            and_(reach.c.object_kind == "system", child.kind == "service"),
        ),
    )
    runbook = and_(
        reach.c.scope == GrantScope.RESPONSIBILITY,
        reach.c.object_kind.in_(RESPONSIBILITY_KINDS),
        child.kind == "runbook",
        Relationship.relation_type == OPERATIONS_RUNBOOK_RELATION,
        Relationship.to_ref == reach.c.object_ref,
        Relationship.from_ref == child_ref,
    )
    columns = [
        child.id.label("object_id"), child_ref.label("object_ref"),
        child.kind.label("object_kind"),
    ]
    # Preserve root column order, including all grant provenance columns.
    values = {column.name: column for column in columns}
    descendants = (
        select(*(values.get(column.name, column) for column in reach.c))
        .select_from(reach)
        .join(Relationship, or_(
            and_(Relationship.from_ref == reach.c.object_ref,
                 Relationship.relation_type == CANONICAL_PLACEMENT_RELATION_TYPE),
            and_(Relationship.to_ref == reach.c.object_ref,
                 Relationship.relation_type == OPERATIONS_RUNBOOK_RELATION),
        ))
        .join(child, or_(placement, runbook))
    )
    return reach.union(descendants)
