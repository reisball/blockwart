from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator

from blockwart.domain.security import find_secret_violations

ObjectKind = Literal["system", "service", "credential_reference", "runbook", "decision", "project"]


class CatalogObjectIn(BaseModel):
    id: str
    kind: ObjectKind
    label: str
    status: str = "unknown"
    summary: str | None = None
    data: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def reject_secret_values(self) -> "CatalogObjectIn":
        violations = find_secret_violations(self.model_dump())
        if violations:
            raise ValueError("; ".join(violations))
        return self


class CatalogObjectOut(CatalogObjectIn):
    pass


class HealthOut(BaseModel):
    ok: bool
    service: str
    version: str

