"""One deterministic synthetic catalog for read-projection budget regressions.

Every object, label, address, comment, and knowledge field here is generated
from a fixed counter, so the fixture is byte-stable across runs and machines
and the recorded measurements can be reproduced exactly. Nothing in it comes
from a real catalog, a real host, or a real deployment: addresses use the RFC
5737 documentation ranges and hostnames use the RFC 2606 reserved
`example.invalid` domain.

The shape is deliberately realistic rather than minimal, because a budget
proven on empty objects would prove nothing: hosts carry addresses and
hostnames, services carry endpoints and dependencies, and the canonical
Runbook, Decision, and Project kinds carry their real required knowledge
fields and typed links.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.orm import Session

from blockwart.domain.auth import (
    GrantScope,
    Permission,
    PrincipalContext,
    PrincipalType,
    Role,
)
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services.access import create_object_grant
from blockwart.services.catalog import create_relationship, upsert_object
from blockwart.services.commands import WriteContext
from blockwart.services.comments import add_object_comment
from blockwart.services.identity import create_service_account, issue_service_token
from blockwart.services.policy import PolicySnapshot
from blockwart.services.read_access import ReadAccess

# Four placement roots keep the fixture realistic for capability and parent
# deduplication: many results share few parents, which is exactly the shape
# that makes a full search page repeat itself.
HOST_COUNT = 4
SYSTEMS_PER_HOST = 2
SERVICES_PER_SYSTEM = 3
RUNBOOK_COUNT = 5
DECISION_COUNT = 5
PROJECT_COUNT = 5
# The published discovery page size of blockwart.search.
SEARCH_HIT_COUNT = 50
# The published known-id batch bound of blockwart.get_object_contexts.
BATCH_OBJECT_COUNT = 20
# Operational comment history per object. A catalog without a comment timeline
# would understate what a default context read actually costs an agent today.
COMMENTS_PER_OBJECT = 2

_HOST_IDS = tuple(f"synthetic-host-{index:02d}" for index in range(1, HOST_COUNT + 1))


@dataclass(frozen=True, slots=True)
class SyntheticCatalog:
    """The ids the fixture created, in deterministic published order."""

    host_ids: tuple[str, ...]
    system_ids: tuple[str, ...]
    service_ids: tuple[str, ...]
    runbook_ids: tuple[str, ...]
    decision_ids: tuple[str, ...]
    project_ids: tuple[str, ...]

    @property
    def all_ids(self) -> tuple[str, ...]:
        return (
            *self.host_ids,
            *self.system_ids,
            *self.service_ids,
            *self.runbook_ids,
            *self.decision_ids,
            *self.project_ids,
        )

    @property
    def batch_ids(self) -> list[str]:
        """One realistic mixed 20-id batch: assets first, then knowledge."""
        mixed = [
            *self.host_ids,
            *self.system_ids[:4],
            *self.service_ids[:5],
            *self.runbook_ids[:3],
            *self.decision_ids[:2],
            *self.project_ids[:2],
        ]
        assert len(mixed) == BATCH_OBJECT_COUNT
        return mixed


def build_synthetic_catalog(session: Session) -> SyntheticCatalog:
    """Create the deterministic synthetic catalog and return its ids."""
    host_ids = _create_hosts(session)
    system_ids = _create_systems(session, host_ids)
    service_ids = _create_services(session, system_ids)
    runbook_ids = _create_runbooks(session, service_ids)
    decision_ids = _create_decisions(session, service_ids)
    project_ids = _create_projects(session, service_ids, runbook_ids)
    catalog = SyntheticCatalog(
        host_ids=host_ids,
        system_ids=system_ids,
        service_ids=service_ids,
        runbook_ids=runbook_ids,
        decision_ids=decision_ids,
        project_ids=project_ids,
    )
    assert len(catalog.all_ids) >= SEARCH_HIT_COUNT
    _create_comments(session, catalog)
    return catalog


def _create_comments(session: Session, catalog: SyntheticCatalog) -> None:
    """Append a deterministic operational comment timeline to every object."""
    context = _comment_context(session, catalog)
    for object_id in catalog.all_ids:
        for index in range(1, COMMENTS_PER_OBJECT + 1):
            add_object_comment(
                session,
                context,
                object_id=object_id,
                body=(
                    f"Synthetic operational note {index} for `{object_id}`. The "
                    "documentation estate was reviewed and no follow-up action is "
                    "outstanding for this object."
                ),
                idempotency_key=f"synthetic-comment-{object_id}-{index:04d}",
                idempotency_ttl_seconds=3600,
            )


def _comment_context(session: Session, catalog: SyntheticCatalog) -> WriteContext:
    principal = create_service_account(
        session,
        login="synthetic.projection.writer",
        display_name="Synthetic Projection Writer",
    )
    for object_id in catalog.all_ids:
        create_object_grant(
            session,
            principal_id=principal.id,
            object_id=object_id,
            role=Role.EDITOR,
            scope=GrantScope.SELF,
        )
    issue_service_token(session, principal_id=principal.id, name="api", audience="api")
    return WriteContext(
        principal=PrincipalContext(
            id=principal.id,
            principal_type=PrincipalType.SERVICE_ACCOUNT,
            login=principal.login,
            display_name=principal.display_name,
            service_token_audience="api",
        ),
        policy=PolicySnapshot(
            principal_id=principal.id,
            _permissions={object_id: frozenset(Permission) for object_id in catalog.all_ids},
            _grants={},
        ),
        channel="api",
        request_id="synthetic-projection-request",
    )


def _create_hosts(session: Session) -> tuple[str, ...]:
    for index, host_id in enumerate(_HOST_IDS, start=1):
        upsert_object(
            session,
            CatalogObjectIn(
                id=host_id,
                kind="host",
                label=f"Synthetic Platform Host {index:02d}",
                lifecycle="active",
                health="healthy",
                summary=(
                    f"Bare-metal platform host {index:02d} in the synthetic "
                    "documentation estate, reserved for read-projection budget proofs."
                ),
                data={
                    "schema_version": 1,
                    "network": {
                        "hostnames": [
                            f"host{index:02d}.example.invalid",
                            f"host{index:02d}.mgmt.example.invalid",
                        ],
                        "addresses": [
                            {"ip": f"192.0.2.{index}"},
                            {"ip": f"198.51.100.{index}"},
                        ],
                    },
                },
            ),
        )
    return _HOST_IDS


def _create_systems(session: Session, host_ids: tuple[str, ...]) -> tuple[str, ...]:
    system_ids: list[str] = []
    counter = 0
    for host_index, host_id in enumerate(host_ids, start=1):
        for _ in range(SYSTEMS_PER_HOST):
            counter += 1
            system_id = f"synthetic-system-{counter:02d}"
            upsert_object(
                session,
                CatalogObjectIn(
                    id=system_id,
                    kind="system",
                    label=f"Synthetic Application System {counter:02d}",
                    lifecycle="active",
                    health="healthy",
                    summary=(
                        f"Application system {counter:02d} hosted on platform host "
                        f"{host_index:02d} of the synthetic documentation estate."
                    ),
                    data={"schema_version": 1},
                ),
            )
            create_relationship(
                session,
                from_ref=f"host:{host_id}",
                relation_type="hosts",
                to_ref=f"system:{system_id}",
            )
            system_ids.append(system_id)
    return tuple(system_ids)


def _create_services(session: Session, system_ids: tuple[str, ...]) -> tuple[str, ...]:
    service_ids: list[str] = []
    counter = 0
    for system_index, system_id in enumerate(system_ids, start=1):
        for _ in range(SERVICES_PER_SYSTEM):
            counter += 1
            service_id = f"synthetic-service-{counter:02d}"
            port = 8000 + counter
            upsert_object(
                session,
                CatalogObjectIn(
                    id=service_id,
                    kind="service",
                    label=f"Synthetic Delivery Service {counter:02d}",
                    lifecycle="active",
                    health="healthy",
                    summary=(
                        f"Delivery service {counter:02d} of application system "
                        f"{system_index:02d}, published for synthetic budget proofs only."
                    ),
                    data={
                        "schema_version": 1,
                        "endpoints": [
                            {
                                "type": "REST API",
                                "url": f"https://service{counter:02d}.example.invalid:{port}/",
                                "host": f"service{counter:02d}.example.invalid",
                                "port": port,
                                "protocol": "https",
                            }
                        ],
                    },
                ),
            )
            create_relationship(
                session,
                from_ref=f"system:{system_id}",
                relation_type="hosts",
                to_ref=f"service:{service_id}",
            )
            service_ids.append(service_id)
    return tuple(service_ids)


def _create_runbooks(session: Session, service_ids: tuple[str, ...]) -> tuple[str, ...]:
    runbook_ids: list[str] = []
    for index in range(1, RUNBOOK_COUNT + 1):
        runbook_id = f"synthetic-runbook-{index:02d}"
        target = service_ids[index % len(service_ids)]
        upsert_object(
            session,
            CatalogObjectIn(
                id=runbook_id,
                kind="runbook",
                label=f"Synthetic Recovery Runbook {index:02d}",
                summary=(
                    f"Recovery runbook {index:02d} for the synthetic delivery estate."
                ),
                data={
                    "schema_version": 1,
                    "runbook_status": "active",
                    "risk_level": "disruptive",
                    "approval_required": True,
                    "approval_requirement": (
                        "One reviewed synthetic change approval before execution."
                    ),
                    "applies_to": [f"service:{target}"],
                    "purpose": (
                        f"Restore synthetic delivery service {index:02d} after a "
                        "controlled failure in the documentation estate."
                    ),
                    "prerequisites": [
                        {
                            "id": "reachable",
                            "description": (
                                "The synthetic estate is reachable and no other "
                                "recovery runbook is executing against the service."
                            ),
                        }
                    ],
                    "steps": [
                        {
                            "id": "confirm",
                            "title": "Confirm the failure",
                            "command": "systemctl status synthetic-delivery.service",
                            "expected_effect": "The unit reports a failed state.",
                        },
                        {
                            "id": "restart",
                            "title": "Restart the unit",
                            "command": "systemctl restart synthetic-delivery.service",
                            "expected_effect": "The unit reports an active state.",
                        },
                    ],
                    "verification": [
                        {
                            "id": "readiness",
                            "description": "Call the published synthetic readiness path.",
                            "success_expectation": "The endpoint answers with HTTP 200.",
                        }
                    ],
                    "rollback": [
                        {
                            "id": "stop",
                            "title": "Stop the unit again",
                            "command": "systemctl stop synthetic-delivery.service",
                            "expected_effect": "The unit reports an inactive state.",
                        }
                    ],
                    "recovery": [
                        {
                            "id": "reinstate",
                            "title": "Reinstate the previous revision",
                            "command": "synthetic-deploy --revision previous",
                            "expected_effect": (
                                "The previous synthetic configuration revision is active."
                            ),
                        }
                    ],
                    "change_fallback": "rollback",
                    "last_verified_at": "2026-02-01T09:00:00Z",
                },
            ),
        )
        runbook_ids.append(runbook_id)
    return tuple(runbook_ids)


def _create_decisions(session: Session, service_ids: tuple[str, ...]) -> tuple[str, ...]:
    decision_ids: list[str] = []
    for index in range(1, DECISION_COUNT + 1):
        decision_id = f"synthetic-decision-{index:02d}"
        target = service_ids[index % len(service_ids)]
        upsert_object(
            session,
            CatalogObjectIn(
                id=decision_id,
                kind="decision",
                label=f"Synthetic Platform Decision {index:02d}",
                summary=f"Recorded platform decision {index:02d} of the synthetic estate.",
                data={
                    "schema_version": 1,
                    "decision_status": "accepted",
                    "applies_to": [f"service:{target}"],
                    "decided_at": "2026-01-15T09:00:00Z",
                    "context": (
                        f"Synthetic decision {index:02d} records why the documentation "
                        "estate standardized one delivery pattern for its services."
                    ),
                    "decision": (
                        "Standardize on the published REST endpoint contract for every "
                        "synthetic delivery service."
                    ),
                    "rationale": (
                        "One endpoint contract keeps the synthetic estate reviewable "
                        "without adding a second delivery pattern."
                    ),
                    "consequences": [
                        "Existing synthetic services keep their endpoint contract.",
                        "New synthetic services must publish the same shape before review.",
                    ],
                },
            ),
        )
        decision_ids.append(decision_id)
    return tuple(decision_ids)


def _create_projects(
    session: Session,
    service_ids: tuple[str, ...],
    runbook_ids: tuple[str, ...],
) -> tuple[str, ...]:
    project_ids: list[str] = []
    for index in range(1, PROJECT_COUNT + 1):
        project_id = f"synthetic-project-{index:02d}"
        target = service_ids[index % len(service_ids)]
        related_runbook = runbook_ids[index % len(runbook_ids)]
        upsert_object(
            session,
            CatalogObjectIn(
                id=project_id,
                kind="project",
                label=f"Synthetic Delivery Project {index:02d}",
                summary=f"Reviewed synthetic delivery project {index:02d}.",
                data={
                    "schema_version": 1,
                    "category": "migration",
                    "project_status": "active",
                    "related_assets": [f"service:{target}"],
                    "related_runbooks": [f"runbook:{related_runbook}"],
                    "objective": (
                        f"Migrate synthetic delivery service {index:02d} onto the "
                        "standardized endpoint contract of the documentation estate."
                    ),
                    "in_scope": [
                        "The synthetic delivery services of the documentation estate.",
                    ],
                    "out_of_scope": [
                        "Every object outside the synthetic documentation estate.",
                    ],
                    "started_at": "2026-03-02T09:00:00Z",
                },
            ),
        )
        project_ids.append(project_id)
    return tuple(project_ids)


def synthetic_read_access(
    catalog: SyntheticCatalog,
    *,
    stub_ids: frozenset[str] = frozenset(),
    concealed_ids: frozenset[str] = frozenset(),
) -> ReadAccess:
    """Return one deterministic mixed-authorization reader.

    Readable objects hold discover/read, stub objects hold discover only, and
    concealed objects hold nothing. Mixing them is what proves that capability
    deduplication keeps different effective rights apart.
    """
    permissions: dict[str, frozenset[Permission]] = {}
    for object_id in catalog.all_ids:
        if object_id in concealed_ids:
            continue
        permissions[object_id] = (
            frozenset({Permission.DISCOVER})
            if object_id in stub_ids
            else frozenset({Permission.DISCOVER, Permission.READ})
        )
    return ReadAccess(
        principal=PrincipalContext(
            id="synthetic-projection-principal",
            principal_type=PrincipalType.SERVICE_ACCOUNT,
            login="synthetic-projection",
            display_name="Synthetic Projection Reader",
        ),
        policy=PolicySnapshot(
            principal_id="synthetic-projection-principal",
            _permissions=permissions,
            _grants={},
        ),
    )


def estimate_agent_tokens(payload: bytes) -> int:
    """Estimate agent tokens from response bytes with a fixed public heuristic.

    This is a deterministic four-bytes-per-token approximation over the exact
    serialized response, not a provider tokenizer result. It exists so a
    budget regression can express an agent-visible cost in a stable, auditable
    way; it is never used to make a product claim about a real instance.
    """
    return -(-len(payload) // 4)
