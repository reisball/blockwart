import re
from collections.abc import Mapping
from typing import Any

FORBIDDEN_SECRET_KEYS = {
    "api_key",
    "apikey",
    "bearer",
    "client_secret",
    "cookie",
    "password",
    "private_key",
    "secret",
    "session",
    "token",
}
FORBIDDEN_ACL_DATA_KEYS = {
    "acl",
    "access_control",
    "access_grants",
    "object_grants",
    "permissions",
}

SECRET_VALUE_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"Bearer\s+[A-Za-z0-9._~+/=-]{20,}", re.IGNORECASE),
    re.compile(r"ghp_[A-Za-z0-9_]{20,}"),
    re.compile(r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}"),
]
REDACTED_SECRET_VALUE = "[redacted-secret-field]"


def looks_like_secret(value: str) -> bool:
    return any(pattern.search(value) for pattern in SECRET_VALUE_PATTERNS)


def find_secret_violations(data: Any, path: str = "$") -> list[str]:
    violations: list[str] = []

    if isinstance(data, Mapping):
        for key, value in data.items():
            key_text = str(key).lower()
            child_path = f"{path}.{key}"
            if key_text in FORBIDDEN_SECRET_KEYS:
                violations.append(f"{child_path}: forbidden secret-shaped key")
            violations.extend(find_secret_violations(value, child_path))
        return violations

    if isinstance(data, list):
        for index, value in enumerate(data):
            violations.extend(find_secret_violations(value, f"{path}[{index}]"))
        return violations

    if isinstance(data, str) and looks_like_secret(data):
        violations.append(f"{path}: value looks like a raw secret")

    return violations


def find_acl_data_violations(data: Any, path: str = "data") -> list[str]:
    """Reject ACL-shaped fields from the catalog data security domain."""
    violations: list[str] = []
    if isinstance(data, Mapping):
        for key, value in data.items():
            key_text = str(key)
            child_path = f"{path}.{key_text}"
            if key_text.casefold() in FORBIDDEN_ACL_DATA_KEYS:
                violations.append(
                    f"{child_path}: access control belongs to the object grant API"
                )
            violations.extend(find_acl_data_violations(value, child_path))
        return violations
    if isinstance(data, list):
        for index, value in enumerate(data):
            violations.extend(find_acl_data_violations(value, f"{path}[{index}]"))
    return violations


def redact_secret_values(data: Any) -> Any:
    if isinstance(data, Mapping):
        safe: dict[str, Any] = {}
        for key, value in data.items():
            key_text = str(key)
            if key_text.lower() in FORBIDDEN_SECRET_KEYS:
                safe[key_text] = REDACTED_SECRET_VALUE
            else:
                safe[key_text] = redact_secret_values(value)
        return safe
    if isinstance(data, list):
        return [redact_secret_values(value) for value in data]
    if isinstance(data, str) and looks_like_secret(data):
        return REDACTED_SECRET_VALUE
    return data
