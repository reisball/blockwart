from dataclasses import dataclass

VALID_REFERENCE_KINDS = {
    "host",
    "system",
    "network",
    "service",
    "credential_reference",
    "runbook",
    "decision",
    "project",
}


@dataclass(frozen=True)
class TypedReference:
    kind: str
    object_id: str

    @classmethod
    def parse(cls, value: str) -> "TypedReference":
        if ":" not in value:
            raise ValueError(f"Typed reference must use kind:id format: {value!r}")
        kind, object_id = value.split(":", 1)
        if kind not in VALID_REFERENCE_KINDS:
            raise ValueError(f"Unsupported reference kind: {kind!r}")
        if not object_id:
            raise ValueError("Typed reference id must not be empty")
        return cls(kind=kind, object_id=object_id)

    def __str__(self) -> str:
        return f"{self.kind}:{self.object_id}"
