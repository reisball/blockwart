from ipaddress import ip_address
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator

from blockwart.domain.references import TypedReference
from blockwart.domain.security import find_secret_violations

ObjectKind = Literal[
    "host",
    "system",
    "netzwerk",
    "service",
    "credential_reference",
    "runbook",
    "decision",
    "project",
]
PublicObjectKind = Literal["host", "system", "netzwerk", "service"]
ObjectStatus = Literal["active", "inactive", "deleted"]
PUBLIC_OBJECT_KINDS: tuple[PublicObjectKind, ...] = ("host", "system", "netzwerk", "service")
OBJECT_STATUSES: tuple[ObjectStatus, ...] = ("active", "inactive", "deleted")

REFERENCE_TARGETS = {
    "credential_references": {"credential_reference"},
    "related_services": {"service"},
    "runbooks": {"runbook"},
    "related_projects": {"project"},
    "related_decisions": {"decision"},
    "related_systems": {"system"},
    "related_runbooks": {"runbook"},
}

DEPENDENCY_TARGETS = {"host", "system", "netzwerk", "service"}
CREDENTIAL_PROVIDERS = {"vaultwarden", "secrets_json", "env_file", "local_file", "external"}
CREDENTIAL_ACCESS_TYPES = {"ssh", "web", "api", "database", "smb", "sudo", "token", "other"}
RUNBOOK_RISK_LEVELS = {"read-only", "safe-change", "disruptive", "destructive"}
FORBIDDEN_CREDENTIAL_REFERENCE_KEYS = {
    "credential",
    "credentials",
    "plaintext",
    "raw",
    "raw_value",
    "secret_value",
    "value",
}


def _require_mapping(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{path} must be an object")
    return value


def _require_string(value: Any, path: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{path} must be a string")
    return value


def _require_bool(value: Any, path: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{path} must be a boolean")
    return value


def _require_list(value: Any, path: str) -> list[Any]:
    if not isinstance(value, list):
        raise ValueError(f"{path} must be a list")
    return value


def _validate_reference(value: Any, allowed_kinds: set[str], path: str) -> None:
    parsed = TypedReference.parse(_require_string(value, path))
    if parsed.kind not in allowed_kinds:
        allowed = ", ".join(sorted(allowed_kinds))
        raise ValueError(f"{path} must reference one of: {allowed}")


def _validate_reference_list(data: dict[str, Any], field: str, allowed_kinds: set[str]) -> None:
    if field not in data:
        return
    for index, value in enumerate(_require_list(data[field], f"data.{field}")):
        _validate_reference(value, allowed_kinds, f"data.{field}[{index}]")


def _validate_dependencies(data: dict[str, Any]) -> None:
    if "dependencies" not in data:
        return
    dependencies = _require_mapping(data["dependencies"], "data.dependencies")
    for side in ("upstream", "downstream"):
        if side not in dependencies:
            continue
        references = _require_list(dependencies[side], f"data.dependencies.{side}")
        for index, value in enumerate(references):
            _validate_reference(value, DEPENDENCY_TARGETS, f"data.dependencies.{side}[{index}]")


def _validate_ports(data: dict[str, Any]) -> None:
    if "ports" not in data:
        return
    for index, value in enumerate(_require_list(data["ports"], "data.ports")):
        port_data = _require_mapping(value, f"data.ports[{index}]")
        if "port" not in port_data:
            continue
        port = port_data["port"]
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            raise ValueError(f"data.ports[{index}].port must be an integer from 1 to 65535")
        if "protocol" in port_data and port_data["protocol"] not in {"tcp", "udp"}:
            raise ValueError(f"data.ports[{index}].protocol must be tcp or udp")


def _validate_network(data: dict[str, Any]) -> None:
    if "network" not in data:
        return
    network = _require_mapping(data["network"], "data.network")
    if "hostnames" in network:
        hostnames = _require_list(network["hostnames"], "data.network.hostnames")
        for index, value in enumerate(hostnames):
            _require_string(value, f"data.network.hostnames[{index}]")
    if "addresses" in network:
        addresses = _require_list(network["addresses"], "data.network.addresses")
        for index, value in enumerate(addresses):
            address = _require_mapping(value, f"data.network.addresses[{index}]")
            if "ip" in address:
                try:
                    ip = _require_string(address["ip"], f"data.network.addresses[{index}].ip")
                    ip_address(ip)
                except ValueError as exc:
                    raise ValueError(
                        f"data.network.addresses[{index}].ip must be a valid IP address"
                    ) from exc


def _validate_access_methods(data: dict[str, Any]) -> None:
    if "access_methods" not in data:
        return
    for index, value in enumerate(_require_list(data["access_methods"], "data.access_methods")):
        access_method = _require_mapping(value, f"data.access_methods[{index}]")
        if "credential_references" not in access_method:
            continue
        for ref_index, reference in enumerate(
            _require_list(
                access_method["credential_references"],
                f"data.access_methods[{index}].credential_references",
            )
        ):
            _validate_reference(
                reference,
                {"credential_reference"},
                f"data.access_methods[{index}].credential_references[{ref_index}]",
            )


def _validate_system_data(data: dict[str, Any]) -> None:
    _validate_network(data)
    _validate_ports(data)
    _validate_access_methods(data)
    _validate_dependencies(data)
    for field, allowed_kinds in REFERENCE_TARGETS.items():
        _validate_reference_list(data, field, allowed_kinds)


def _validate_service_data(data: dict[str, Any]) -> None:
    if "system_id" in data:
        _validate_reference(data["system_id"], {"system"}, "data.system_id")
    if "owner" in data:
        _require_string(data["owner"], "data.owner")
    if "endpoints" in data:
        for index, value in enumerate(_require_list(data["endpoints"], "data.endpoints")):
            endpoint = _require_mapping(value, f"data.endpoints[{index}]")
            if "port" in endpoint:
                port = endpoint["port"]
                if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
                    raise ValueError(
                        f"data.endpoints[{index}].port must be an integer from 1 to 65535"
                    )
    if "auth" in data:
        auth = _require_mapping(data["auth"], "data.auth")
        if "credential_references" in auth:
            for index, reference in enumerate(
                _require_list(auth["credential_references"], "data.auth.credential_references")
            ):
                _validate_reference(
                    reference,
                    {"credential_reference"},
                    f"data.auth.credential_references[{index}]",
                )
    _validate_dependencies(data)
    for field, allowed_kinds in REFERENCE_TARGETS.items():
        _validate_reference_list(data, field, allowed_kinds)


def _reject_credential_value_keys(value: Any, path: str = "data") -> None:
    if isinstance(value, dict):
        for key, child_value in value.items():
            key_text = str(key).lower()
            child_path = f"{path}.{key}"
            if key_text in FORBIDDEN_CREDENTIAL_REFERENCE_KEYS:
                raise ValueError(
                    f"{child_path}: credential references may not contain raw value fields"
                )
            _reject_credential_value_keys(child_value, child_path)
    elif isinstance(value, list):
        for index, child_value in enumerate(value):
            _reject_credential_value_keys(child_value, f"{path}[{index}]")


def _validate_credential_reference_data(data: dict[str, Any]) -> None:
    _reject_credential_value_keys(data)
    if "provider" in data and data["provider"] not in CREDENTIAL_PROVIDERS:
        raise ValueError("data.provider must be a supported credential reference provider")
    if "reference" in data:
        reference = _require_mapping(data["reference"], "data.reference")
        for field in ("name", "path", "key", "item_hint"):
            if field in reference:
                _require_string(reference[field], f"data.reference.{field}")
    if "scope" in data:
        scope = _require_mapping(data["scope"], "data.scope")
        if "access_type" in scope and scope["access_type"] not in CREDENTIAL_ACCESS_TYPES:
            raise ValueError("data.scope.access_type must be a supported access type")
        _validate_reference_list(scope, "systems", {"system"})
        _validate_reference_list(scope, "services", {"service"})
    if "used_by" in data:
        used_by = _require_mapping(data["used_by"], "data.used_by")
        _validate_reference_list(used_by, "systems", {"system"})
        _validate_reference_list(used_by, "services", {"service"})
        _validate_reference_list(used_by, "runbooks", {"runbook"})
    if "handling_rules" in data:
        handling_rules = _require_mapping(data["handling_rules"], "data.handling_rules")
        for field in ("telegram_allowed", "markdown_secret_allowed", "agents_may_read_value"):
            if field not in handling_rules:
                continue
            allowed = _require_bool(handling_rules[field], f"data.handling_rules.{field}")
            if allowed:
                raise ValueError(f"data.handling_rules.{field} must be false")
    if "secret_value_stored" in data and _require_bool(
        data["secret_value_stored"],
        "data.secret_value_stored",
    ):
        raise ValueError("data.secret_value_stored must be false")


def _validate_runbook_data(data: dict[str, Any]) -> None:
    if "risk_level" in data and data["risk_level"] not in RUNBOOK_RISK_LEVELS:
        raise ValueError("data.risk_level must be a supported runbook risk level")
    needs_approval = data.get("risk_level") in {"disruptive", "destructive"}
    if needs_approval and data.get("approval_required") is False:
        raise ValueError(
            "data.approval_required must be true for disruptive or destructive runbooks"
        )
    for field in ("steps", "verification", "prerequisites", "docs"):
        if field not in data:
            continue
        for index, value in enumerate(_require_list(data[field], f"data.{field}")):
            if isinstance(value, str):
                continue
            if isinstance(value, dict):
                continue
            raise ValueError(f"data.{field}[{index}] must be a string or object")
    if "applies_to" in data:
        applies_to = _require_mapping(data["applies_to"], "data.applies_to")
        _validate_reference_list(applies_to, "systems", {"system"})
        _validate_reference_list(applies_to, "services", {"service"})
    _validate_reference_list(data, "credential_references", {"credential_reference"})
    _validate_reference_list(data, "related_decisions", {"decision"})


class CatalogObjectIn(BaseModel):
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]*[a-z0-9]$|^[a-z0-9]$")
    kind: ObjectKind
    label: str
    status: ObjectStatus = "active"
    summary: str | None = None
    data: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def reject_secret_values(self) -> "CatalogObjectIn":
        violations = find_secret_violations(self.model_dump())
        if violations:
            raise ValueError("; ".join(violations))
        return self

    @model_validator(mode="after")
    def validate_catalog_data(self) -> "CatalogObjectIn":
        if "schema_version" in self.data and self.data["schema_version"] != 1:
            raise ValueError("data.schema_version must be 1")
        if self.kind in {"host", "system"}:
            _validate_system_data(self.data)
        elif self.kind == "netzwerk":
            _validate_network(self.data)
        elif self.kind == "service":
            _validate_service_data(self.data)
        elif self.kind == "credential_reference":
            _validate_credential_reference_data(self.data)
        elif self.kind == "runbook":
            _validate_runbook_data(self.data)
        return self


class CatalogObjectOut(CatalogObjectIn):
    created_at: str | None = None
    updated_at: str | None = None
    last_changed: str | None = None


class HealthOut(BaseModel):
    ok: bool
    service: str
    version: str
