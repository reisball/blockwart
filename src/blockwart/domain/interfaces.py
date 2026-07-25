from __future__ import annotations

import re
from copy import deepcopy
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

CANONICAL_ENDPOINT_TYPES = (
    "Web",
    "REST API",
    "MCP",
    "HEC",
    "SSH",
    "SMB",
    "Database",
    "S2S",
    "Metrics",
    "Webhook",
    "HTTP",
    "TCP",
    "UDP",
)
CANONICAL_ACCESS_TYPES = (
    "ssh",
    "admin_web",
    "admin_api",
    "database",
    "smb",
    "sudo",
    "token",
    "other",
)
CANONICAL_EXPOSURES = frozenset(
    {"loopback", "lan", "vpn", "internal", "public", "unknown"}
)
CANONICAL_TRANSPORTS = frozenset({"tcp", "udp"})
SERVICE_INTERFACE_STATES = frozenset({"available", "not_applicable", "incomplete"})

_CUSTOM_ENDPOINT_TYPE = re.compile(r"^x-[a-z0-9][a-z0-9-]*$")
_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
_PROTOCOL = re.compile(r"^[a-z][a-z0-9+.-]*$")
_TYPE_ALIASES = {
    "web": "Web",
    "rest api": "REST API",
    "rest_api": "REST API",
    "api": "REST API",
    "mcp": "MCP",
    "hec": "HEC",
    "ssh": "SSH",
    "smb": "SMB",
    "database": "Database",
    "db": "Database",
    "s2s": "S2S",
    "splunk s2s": "S2S",
    "metrics": "Metrics",
    "webhook": "Webhook",
    "http": "HTTP",
    "https": "HTTP",
    "tcp": "TCP",
    "udp": "UDP",
}
_ACCESS_TYPE_ALIASES = {
    "web": "admin_web",
    "api": "admin_api",
}
_TYPE_PROTOCOLS = {
    "Web": "http",
    "REST API": "http",
    "MCP": "mcp",
    "HEC": "http",
    "SSH": "ssh",
    "SMB": "smb",
    "Database": "database",
    "S2S": "splunk-s2s",
    "Metrics": "http",
    "Webhook": "http",
    "HTTP": "http",
    "TCP": "tcp",
    "UDP": "udp",
}
_DEFAULT_PORTS = {
    "http": 80,
    "https": 443,
    "ssh": 22,
    "smb": 445,
}


class InterfaceContractError(ValueError):
    pass


@dataclass(frozen=True, order=True)
class InterfaceDiagnostic:
    code: str
    location: str
    message: str


@dataclass(frozen=True)
class InterfaceNormalization:
    data: dict[str, Any]
    diagnostics: tuple[InterfaceDiagnostic, ...]

    @property
    def changed(self) -> bool:
        return bool(self.diagnostics)


def normalize_interface_data(
    data: dict[str, Any],
    *,
    kind: str,
    object_id: str = "<new>",
    allow_legacy: bool = False,
) -> InterfaceNormalization:
    normalized = deepcopy(data)
    diagnostics: list[InterfaceDiagnostic] = []
    endpoints: list[dict[str, Any]] = []
    endpoint_by_url: dict[str, dict[str, Any]] = {}
    endpoint_ids: set[str] = set()

    raw_endpoints = _optional_list(normalized, "endpoints")
    for index, raw_endpoint in enumerate(raw_endpoints):
        location = f"catalog_objects[{object_id}].data.endpoints[{index}]"
        endpoint = normalize_endpoint(
            _require_mapping(raw_endpoint, location),
            used_ids=endpoint_ids,
            location=location,
        )
        fingerprint = endpoint_url_fingerprint(endpoint)
        if fingerprint and fingerprint in endpoint_by_url:
            existing = endpoint_by_url[fingerprint]
            diagnostics.append(
                InterfaceDiagnostic(
                    "duplicate_endpoint_url",
                    location,
                    f"duplicates endpoint {existing['id']}",
                )
            )
            continue
        endpoints.append(endpoint)
        endpoint_ids.add(endpoint["id"])
        if fingerprint:
            endpoint_by_url[fingerprint] = endpoint

    raw_access_methods = _optional_list(normalized, "access_methods")
    access_methods: list[dict[str, Any]] = []
    access_ids: set[str] = set()
    for index, raw_access_method in enumerate(raw_access_methods):
        location = f"catalog_objects[{object_id}].data.access_methods[{index}]"
        access_method = _require_mapping(raw_access_method, location)
        endpoint_url = access_method.get("endpoint")
        endpoint_id = access_method.get("endpoint_id")
        remove_empty_endpoint = (
            allow_legacy
            and isinstance(endpoint_url, str)
            and not endpoint_url.strip()
        )
        if remove_empty_endpoint:
            endpoint_url = None
            diagnostics.append(
                InterfaceDiagnostic(
                    "empty_access_endpoint_removed",
                    f"{location}.endpoint",
                    "removed an empty legacy access endpoint",
                )
            )
        elif endpoint_url is not None:
            endpoint_url = _require_nonempty_string(
                endpoint_url,
                f"{location}.endpoint",
            )
            fingerprint = _url_fingerprint(endpoint_url)
            endpoint = endpoint_by_url.get(fingerprint)
            if endpoint is None:
                endpoint = normalize_endpoint(
                    {
                        "type": _endpoint_type_for_access(access_method.get("type")),
                        "url": endpoint_url,
                        "exposure": access_method.get("exposure", "unknown"),
                        "label": access_method.get("purpose"),
                    },
                    used_ids=endpoint_ids,
                    location=f"{location}.endpoint",
                )
                endpoints.append(endpoint)
                endpoint_ids.add(endpoint["id"])
                endpoint_by_url[fingerprint] = endpoint
                diagnostics.append(
                    InterfaceDiagnostic(
                        "access_endpoint_promoted",
                        location,
                        f"promoted access endpoint to {endpoint['id']}",
                    )
                )
            elif endpoint_id not in {None, endpoint["id"]}:
                raise InterfaceContractError(
                    f"{location}.endpoint_id does not match data.endpoints"
                )
            else:
                diagnostics.append(
                    InterfaceDiagnostic(
                        "access_endpoint_deduplicated",
                        location,
                        f"reuses endpoint {endpoint['id']}",
                    )
                )
            endpoint_id = endpoint["id"]
        elif endpoint_id is not None:
            endpoint_id = _require_identifier(endpoint_id, f"{location}.endpoint_id")
            if endpoint_id not in endpoint_ids:
                raise InterfaceContractError(
                    f"{location}.endpoint_id references a missing endpoint"
                )

        access_type = _normalize_access_type(access_method.get("type"), location)
        access_id = access_method.get("id")
        if access_id is None:
            access_id = _unique_identifier(
                "-".join(part for part in (access_type, endpoint_id) if part),
                access_ids,
                fallback="access",
            )
            diagnostics.append(
                InterfaceDiagnostic(
                    "access_id_added",
                    location,
                    f"added stable access id {access_id}",
                )
            )
        else:
            access_id = _require_identifier(access_id, f"{location}.id")
            if access_id in access_ids:
                raise InterfaceContractError(f"{location}.id must be unique")

        normalized_access = dict(access_method)
        if remove_empty_endpoint:
            normalized_access.pop("endpoint", None)
        normalized_access["id"] = access_id
        normalized_access["type"] = access_type
        if endpoint_id is not None:
            normalized_access["endpoint_id"] = endpoint_id
            # Compatibility alias for the existing UI. endpoint_id is canonical.
            normalized_access["endpoint"] = endpoint_url or _endpoint_url(
                next(item for item in endpoints if item["id"] == endpoint_id)
            )
        _validate_credential_references(normalized_access, location)
        access_ids.add(access_id)
        access_methods.append(normalized_access)

    raw_ports = _optional_list(normalized, "ports")
    ports: list[dict[str, Any]] = []
    endpoint_ports = {
        (endpoint.get("port"), endpoint["transport"])
        for endpoint in endpoints
        if endpoint.get("port") is not None
    }
    seen_ports: set[tuple[int, str]] = set()
    for index, raw_port in enumerate(raw_ports):
        location = f"catalog_objects[{object_id}].data.ports[{index}]"
        port = normalize_port(_require_mapping(raw_port, location), location=location)
        fingerprint = (port["port"], port["transport"])
        if fingerprint in endpoint_ports:
            diagnostics.append(
                InterfaceDiagnostic(
                    "endpoint_port_duplicate",
                    location,
                    "technical port is already represented by an endpoint",
                )
            )
            continue
        if fingerprint in seen_ports:
            diagnostics.append(
                InterfaceDiagnostic(
                    "duplicate_port",
                    location,
                    "duplicate technical port declaration",
                )
            )
            continue
        seen_ports.add(fingerprint)
        ports.append(port)

    if raw_endpoints or raw_access_methods or "endpoints" in normalized:
        normalized["endpoints"] = endpoints
    if "access_methods" in normalized:
        normalized["access_methods"] = access_methods
    if "ports" in normalized:
        normalized["ports"] = ports
    if kind == "service":
        normalized["interface"] = _normalize_service_interface(
            normalized,
            endpoints=endpoints,
            object_id=object_id,
            diagnostics=diagnostics,
        )

    if normalized == data:
        diagnostics = []
    elif not diagnostics:
        diagnostics.append(
            InterfaceDiagnostic(
                "interface_normalized",
                f"catalog_objects[{object_id}].data",
                "normalized interface data to the canonical contract",
            )
        )
    return InterfaceNormalization(normalized, tuple(sorted(diagnostics)))


def normalize_endpoint(
    raw_endpoint: dict[str, Any],
    *,
    used_ids: set[str] | None = None,
    location: str = "endpoint",
) -> dict[str, Any]:
    endpoint = dict(raw_endpoint)
    endpoint_url = endpoint.get("url")
    host = endpoint.get("host")
    if endpoint_url is not None:
        endpoint_url = _require_nonempty_string(endpoint_url, f"{location}.url").strip()
        endpoint["url"] = endpoint_url
    if host is not None:
        host = _require_nonempty_string(host, f"{location}.host").strip()

    parsed = _parse_url(endpoint_url)
    if host is None and parsed is not None and parsed.hostname:
        host = parsed.hostname
    if host is None and endpoint_url and parsed is None and "/" not in endpoint_url:
        host = endpoint_url
    if host is None and endpoint_url is None:
        raise InterfaceContractError(f"{location} requires url or host")

    raw_protocol = endpoint.get("protocol")
    url_protocol = parsed.scheme.lower() if parsed is not None and parsed.scheme else None
    endpoint_type = _normalize_endpoint_type(
        endpoint.get("type"),
        protocol=url_protocol or (raw_protocol if isinstance(raw_protocol, str) else None),
        location=location,
    )
    transport = endpoint.get("transport")
    if transport is None and raw_protocol in CANONICAL_TRANSPORTS:
        transport = raw_protocol
    if transport is None:
        transport = "udp" if url_protocol == "udp" or endpoint_type == "UDP" else "tcp"
    if transport not in CANONICAL_TRANSPORTS:
        raise InterfaceContractError(f"{location}.transport must be tcp or udp")

    protocol = url_protocol
    if protocol is None and isinstance(raw_protocol, str) and raw_protocol not in {"tcp", "udp"}:
        protocol = raw_protocol.lower()
    protocol = protocol or _TYPE_PROTOCOLS.get(endpoint_type)
    if protocol is None:
        raise InterfaceContractError(
            f"{location}.protocol is required for custom endpoint types"
        )
    if not _PROTOCOL.fullmatch(protocol):
        raise InterfaceContractError(f"{location}.protocol is invalid")

    port = endpoint.get("port")
    if port is None and parsed is not None:
        try:
            port = parsed.port
        except ValueError as exc:
            raise InterfaceContractError(f"{location}.url contains an invalid port") from exc
    if port is None:
        port = _DEFAULT_PORTS.get(protocol)
    if port is not None:
        port = _require_port(port, f"{location}.port")

    path = endpoint.get("path")
    if path is None and parsed is not None and parsed.path not in {"", "/"}:
        path = parsed.path
    if path == "":
        path = None
    elif path is not None:
        path = _require_nonempty_string(path, f"{location}.path")

    exposure = endpoint.get("exposure", "unknown")
    if exposure not in CANONICAL_EXPOSURES:
        raise InterfaceContractError(
            f"{location}.exposure must be one of: {', '.join(sorted(CANONICAL_EXPOSURES))}"
        )

    endpoint_id = endpoint.get("id")
    known_ids = used_ids or set()
    if endpoint_id is None:
        endpoint_id = _unique_identifier(
            "-".join(
                part
                for part in (
                    _slug(endpoint_type),
                    str(port) if port is not None else None,
                    _slug(host) if host else None,
                )
                if part
            ),
            known_ids,
            fallback="endpoint",
        )
    else:
        endpoint_id = _require_identifier(endpoint_id, f"{location}.id")
        if endpoint_id in known_ids:
            raise InterfaceContractError(f"{location}.id must be unique")

    normalized = dict(endpoint)
    normalized["id"] = endpoint_id
    normalized["type"] = endpoint_type
    normalized["protocol"] = protocol
    normalized["transport"] = transport
    normalized["exposure"] = exposure
    if host is not None:
        normalized["host"] = host
    if port is not None:
        normalized["port"] = port
    if path is not None:
        normalized["path"] = path
    else:
        normalized.pop("path", None)
    if "name" in normalized and "label" not in normalized:
        normalized["label"] = normalized["name"]
    if "health_url" in normalized:
        _require_nonempty_string(normalized["health_url"], f"{location}.health_url")
    return normalized


def normalize_port(raw_port: dict[str, Any], *, location: str = "port") -> dict[str, Any]:
    if "port" not in raw_port:
        raise InterfaceContractError(f"{location}.port is required")
    port = _require_port(raw_port["port"], f"{location}.port")
    transport = raw_port.get("transport", raw_port.get("protocol", "tcp"))
    if transport not in CANONICAL_TRANSPORTS:
        raise InterfaceContractError(f"{location}.transport must be tcp or udp")
    exposure = raw_port.get("exposure", "unknown")
    if exposure not in CANONICAL_EXPOSURES:
        raise InterfaceContractError(
            f"{location}.exposure must be one of: {', '.join(sorted(CANONICAL_EXPOSURES))}"
        )
    normalized = dict(raw_port)
    normalized.pop("protocol", None)
    normalized.update(port=port, transport=transport, exposure=exposure)
    return normalized


def endpoint_url_fingerprint(endpoint: dict[str, Any]) -> str | None:
    url = endpoint.get("url")
    return _url_fingerprint(url) if isinstance(url, str) and url else None


def _normalize_endpoint_type(
    value: Any,
    *,
    protocol: str | None,
    location: str,
) -> str:
    if value is None:
        return _TYPE_ALIASES.get((protocol or "").casefold(), "TCP")
    text = _require_nonempty_string(value, f"{location}.type").strip()
    canonical = _TYPE_ALIASES.get(text.casefold())
    if canonical is not None:
        return canonical
    if text in CANONICAL_ENDPOINT_TYPES or _CUSTOM_ENDPOINT_TYPE.fullmatch(text):
        return text
    raise InterfaceContractError(
        "endpoint type must be one of: "
        f"{', '.join(CANONICAL_ENDPOINT_TYPES)} or an x- extension"
    )


def _normalize_access_type(value: Any, location: str) -> str:
    if value is None:
        return "other"
    text = _require_nonempty_string(value, f"{location}.type").strip().lower()
    text = _ACCESS_TYPE_ALIASES.get(text, text)
    if text not in CANONICAL_ACCESS_TYPES:
        raise InterfaceContractError(
            f"{location}.type must be one of: {', '.join(CANONICAL_ACCESS_TYPES)}"
        )
    return text


def _endpoint_type_for_access(value: Any) -> str:
    access_type = _ACCESS_TYPE_ALIASES.get(str(value or "other").lower(), str(value or "other"))
    return {
        "ssh": "SSH",
        "admin_web": "Web",
        "admin_api": "REST API",
        "database": "Database",
        "smb": "SMB",
    }.get(access_type, "TCP")


def _normalize_service_interface(
    data: dict[str, Any],
    *,
    endpoints: list[dict[str, Any]],
    object_id: str,
    diagnostics: list[InterfaceDiagnostic],
) -> dict[str, Any]:
    existing = data.get("interface")
    if existing is not None:
        existing = _require_mapping(
            existing,
            f"catalog_objects[{object_id}].data.interface",
        )
        state = existing.get("state")
        if state not in SERVICE_INTERFACE_STATES:
            raise InterfaceContractError(
                f"catalog_objects[{object_id}].data.interface.state is invalid"
            )
        if endpoints and state != "available":
            raise InterfaceContractError(
                f"catalog_objects[{object_id}].data.interface must be available "
                "when endpoints exist"
            )
        if not endpoints and state == "available":
            raise InterfaceContractError(
                f"catalog_objects[{object_id}].data.interface cannot be available without endpoints"
            )
        return dict(existing)

    legacy = data.get("service_interface")
    if endpoints:
        state = {"state": "available"}
    elif isinstance(legacy, dict) and legacy.get("endpoint_required") is False:
        state = {
            "state": "not_applicable",
            "reason": str(legacy.get("type") or "internal service"),
        }
    else:
        state = {"state": "incomplete"}
        diagnostics.append(
            InterfaceDiagnostic(
                "service_interface_incomplete",
                f"catalog_objects[{object_id}].data.interface",
                "service has no endpoint classification",
            )
        )
    return state


def _optional_list(data: dict[str, Any], field: str) -> list[Any]:
    value = data.get(field, [])
    if not isinstance(value, list):
        raise InterfaceContractError(f"data.{field} must be a list")
    return value


def _validate_credential_references(access_method: dict[str, Any], location: str) -> None:
    references = access_method.get("credential_references")
    if references is None:
        return
    if not isinstance(references, list):
        raise InterfaceContractError(f"{location}.credential_references must be a list")
    if not all(
        isinstance(reference, str)
        and reference.startswith("credential_reference:")
        and len(reference) > len("credential_reference:")
        for reference in references
    ):
        raise InterfaceContractError(
            f"{location}.credential_references must reference one of: credential_reference"
        )


def _require_mapping(value: Any, location: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise InterfaceContractError(f"{location} must be an object")
    return value


def _require_nonempty_string(value: Any, location: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InterfaceContractError(f"{location} must be a non-empty string")
    return value


def _require_port(value: Any, location: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 65535:
        raise InterfaceContractError(f"{location} must be an integer from 1 to 65535")
    return value


def _require_identifier(value: Any, location: str) -> str:
    text = _require_nonempty_string(value, location)
    if not _IDENTIFIER.fullmatch(text):
        raise InterfaceContractError(f"{location} is not a stable identifier")
    return text


def _unique_identifier(candidate: str, used_ids: set[str], *, fallback: str) -> str:
    base = _slug(candidate) or fallback
    identifier = base
    counter = 2
    while identifier in used_ids:
        identifier = f"{base}-{counter}"
        counter += 1
    return identifier


def _slug(value: Any) -> str:
    text = str(value or "").strip().lower()
    text = re.sub(r"[^a-z0-9_-]+", "-", text)
    return text.strip("-_")


def _parse_url(value: str | None):
    if not value or "://" not in value:
        return None
    try:
        return urlsplit(value)
    except ValueError as exc:
        raise InterfaceContractError("endpoint URL is invalid") from exc


def _url_fingerprint(value: str) -> str:
    return value.strip()


def _endpoint_url(endpoint: dict[str, Any]) -> str:
    url = endpoint.get("url")
    if isinstance(url, str):
        return url
    protocol = endpoint["protocol"]
    host = endpoint.get("host", "")
    port = endpoint.get("port")
    return f"{protocol}://{host}{f':{port}' if port is not None else ''}"
