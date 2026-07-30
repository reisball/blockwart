from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from blockwart.domain.interfaces import (
    InterfaceDiagnostic,
    normalize_interface_data,
)
from blockwart.models import CatalogObject
from blockwart.services.audit import add_audit_event


class InterfaceMigrationError(RuntimeError):
    pass


@dataclass(frozen=True)
class InterfaceObjectChange:
    object_id: str
    kind: str
    before: dict[str, Any]
    after: dict[str, Any]
    diagnostics: tuple[InterfaceDiagnostic, ...]


@dataclass(frozen=True)
class InterfaceMigrationPlan:
    scanned_objects: int
    changes: tuple[InterfaceObjectChange, ...]
    diagnostics: tuple[InterfaceDiagnostic, ...]

    @property
    def changed_objects(self) -> int:
        return len(self.changes)

    @property
    def diagnostic_counts(self) -> dict[str, int]:
        return dict(sorted(Counter(item.code for item in self.diagnostics).items()))


def build_interface_migration_plan(session: Session) -> InterfaceMigrationPlan:
    rows = list(
        session.scalars(
            select(CatalogObject).order_by(CatalogObject.kind, CatalogObject.id)
        ).all()
    )
    changes: list[InterfaceObjectChange] = []
    diagnostics: list[InterfaceDiagnostic] = []
    for row in rows:
        try:
            before = json.loads(row.data_json)
        except (TypeError, json.JSONDecodeError) as exc:
            raise InterfaceMigrationError(
                f"catalog object {row.id} has invalid data_json"
            ) from exc
        if not isinstance(before, dict):
            raise InterfaceMigrationError(
                f"catalog object {row.id} data_json is not an object"
            )
        result = normalize_interface_data(
            before,
            kind=row.kind,
            object_id=row.id,
            allow_legacy=True,
        )
        diagnostics.extend(result.diagnostics)
        if result.data == before:
            continue
        changes.append(
            InterfaceObjectChange(
                object_id=row.id,
                kind=row.kind,
                before=before,
                after=result.data,
                diagnostics=result.diagnostics,
            )
        )
    return InterfaceMigrationPlan(
        scanned_objects=len(rows),
        changes=tuple(changes),
        diagnostics=tuple(sorted(diagnostics)),
    )


def apply_interface_migration_plan(
    session: Session,
    plan: InterfaceMigrationPlan,
) -> int:
    changed_at = datetime.now(UTC).replace(tzinfo=None)
    for change in plan.changes:
        row = session.get(CatalogObject, change.object_id)
        if row is None:
            raise InterfaceMigrationError(
                f"catalog object {change.object_id} disappeared after planning"
            )
        try:
            current = json.loads(row.data_json)
        except (TypeError, json.JSONDecodeError) as exc:
            raise InterfaceMigrationError(
                f"catalog object {change.object_id} changed after planning"
            ) from exc
        if row.kind != change.kind or current != change.before:
            raise InterfaceMigrationError(
                f"catalog object {change.object_id} changed after planning"
            )
        row.data_json = json.dumps(
            change.after,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        row.revision += 1
        row.updated_at = changed_at
        add_audit_event(
            session,
            object_id=row.id,
            action="interface_normalize",
            actor="interface-migration",
            details={
                "object_ref": f"{row.kind}:{row.id}",
                "diagnostic_count": len(change.diagnostics),
            },
        )
    session.flush()
    return len(plan.changes)
