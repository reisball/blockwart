from typing import ClassVar

from pydantic import ValidationError

from blockwart.domain.catalog_data import (
    CatalogDataRead,
    corrupt_catalog_data,
    load_catalog_data,
)
from blockwart.domain.provenance import load_provenance
from blockwart.models import CatalogObject
from blockwart.schemas.catalog import CatalogObjectIn


class _StoredCatalogObjectIn(CatalogObjectIn):
    """Validate legacy-readable rows without weakening the canonical write model."""

    allow_legacy_network_without_category: ClassVar[bool] = True
    allow_legacy_decision_without_status: ClassVar[bool] = True
    allow_legacy_decision_data: ClassVar[bool] = True
    allow_legacy_project_without_category: ClassVar[bool] = True
    allow_legacy_project_data: ClassVar[bool] = True
    allow_legacy_runbook_without_status: ClassVar[bool] = True
    allow_legacy_runbook_data: ClassVar[bool] = True


def read_catalog_record_data(
    row: CatalogObject,
    *,
    retain_schema_invalid_data: bool = False,
) -> CatalogDataRead:
    record = load_catalog_data(row.id, row.data_json)
    if record.record_state == "corrupt":
        return record
    provenance, provenance_valid = load_provenance(row.provenance_json)
    if not provenance_valid:
        corrupt = corrupt_catalog_data(
            row.id,
            f"Catalog object {row.id} has invalid provenance_json",
        )
        if retain_schema_invalid_data:
            return CatalogDataRead(
                data=record.data,
                record_state=corrupt.record_state,
                diagnostics=corrupt.diagnostics,
            )
        return corrupt
    try:
        _StoredCatalogObjectIn.model_validate(
            {
                "id": row.id,
                "kind": row.kind,
                "label": row.label,
                "status": row.status,
                "lifecycle": row.lifecycle,
                "health": row.health,
                "summary": row.summary,
                "data": record.data,
                "provenance": provenance.model_dump(),
            }
        )
    except ValidationError:
        corrupt = corrupt_catalog_data(
            row.id,
            f"Catalog object {row.id} violates the catalog schema",
        )
        if retain_schema_invalid_data:
            return CatalogDataRead(
                data=record.data,
                record_state=corrupt.record_state,
                diagnostics=corrupt.diagnostics,
            )
        return corrupt
    return record
