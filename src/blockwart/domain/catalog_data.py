import json
from dataclasses import dataclass
from typing import Any, Literal

CatalogRecordState = Literal["valid", "corrupt"]


@dataclass(frozen=True)
class CatalogDataDiagnostic:
    code: Literal["corrupt_record"]
    object_id: str
    message: str


@dataclass(frozen=True)
class CatalogDataRead:
    data: dict[str, Any]
    record_state: CatalogRecordState
    diagnostics: tuple[CatalogDataDiagnostic, ...] = ()


def load_catalog_data(object_id: str, data_json: str | None) -> CatalogDataRead:
    """Read catalog JSON without allowing one corrupt row to break read surfaces."""

    try:
        data = json.loads(data_json)
    except (TypeError, json.JSONDecodeError):
        return corrupt_catalog_data(
            object_id,
            f"Catalog object {object_id} has invalid data_json",
        )
    if not isinstance(data, dict):
        return corrupt_catalog_data(
            object_id,
            f"Catalog object {object_id} data_json is not an object",
        )
    return CatalogDataRead(data=data, record_state="valid")


def corrupt_catalog_data(object_id: str, message: str) -> CatalogDataRead:
    return CatalogDataRead(
        data={},
        record_state="corrupt",
        diagnostics=(
            CatalogDataDiagnostic(
                code="corrupt_record",
                object_id=object_id,
                message=message,
            ),
        ),
    )
