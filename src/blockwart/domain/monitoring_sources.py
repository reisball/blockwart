"""Deployment-bound monitoring pull sources.

A pull provider reads evidence from a third-party status service. That service
is infrastructure, not catalog content: which host answers, and which
credential is presented to it, is a deployment decision an operator makes once.
Catalog data may only *name* a source.

This module is the whole binding:

- an operator declares a small, bounded registry of ``name=status-url`` pairs;
- each name may bind exactly one credential **file** whose contents are read at
  check time and never stored, projected, or logged;
- every URL passes the same bounded admission rule as a catalog ``health_url``;
- an unparseable, duplicated, over-long, or unmatched declaration is a hard
  configuration error, so a deployment fails closed at startup instead of
  silently monitoring nothing or, worse, the wrong host.

Nothing here performs I/O; reading a credential file happens in the adapter at
check time, so a rotated secret takes effect without a restart and its value
never lives in a settings object.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from blockwart.domain.monitoring import (
    MAX_GATUS_SOURCE_NAME_LENGTH,
    ParsedHttpUrl,
    parse_bounded_http_url,
    valid_gatus_source_name,
)

# The registry is a deployment contract, not a catalog. Keeping it small keeps
# the blast radius of one misconfigured entry small and makes the whole binding
# reviewable in a single glance.
MAX_MONITORING_PULL_SOURCES = 8
MAX_CREDENTIAL_FILE_PATH_LENGTH = 512


class MonitoringSourceError(ValueError):
    """A pull-source binding this deployment cannot use.

    The message names the offending source identity and the broken rule only.
    It never contains a URL, a host, a file path, or any credential material,
    because it reaches operator-visible startup output.
    """


@dataclass(frozen=True, slots=True)
class MonitoringPullSource:
    """One immutable, validated status source bound to one identity.

    ``credential_file`` is a path, never a secret. It is optional: a status API
    that needs no credential simply has none, and a source that declares one
    fails closed when the file cannot be read.
    """

    name: str
    url: str
    scheme: str
    host: str
    port: int
    path: str
    credential_file: str | None = None


def parse_monitoring_pull_sources(
    *,
    sources: str,
    credential_files: str = "",
) -> Mapping[str, MonitoringPullSource]:
    """Bind a bounded set of source identities to immutable status URLs.

    Args:
        sources: Comma-separated ``name=url`` declarations. Empty declares no
            source at all, which denies every pull check by default.
        credential_files: Comma-separated ``name=path`` declarations. Each name
            must be one of the declared sources, so a credential can never be
            attached to a source that does not exist — and therefore can never
            follow a later, differently-bound source of the same name.

    Returns:
        A read-only mapping from source identity to its immutable binding.

    Raises:
        MonitoringSourceError: When a declaration is malformed, duplicated,
            unmatched, or exceeds the published bounds.
    """

    bindings: dict[str, ParsedHttpUrl] = {}
    for entry in _entries(sources):
        name, url = _split(entry, kind="source")
        if not valid_gatus_source_name(name):
            raise MonitoringSourceError(
                "monitoring pull source name must be lowercase, bounded to "
                f"{MAX_GATUS_SOURCE_NAME_LENGTH} characters, and free of URL syntax"
            )
        if name in bindings:
            raise MonitoringSourceError(
                f"monitoring pull source '{name}' is declared more than once"
            )
        parsed = parse_bounded_http_url(url)
        if parsed is None:
            raise MonitoringSourceError(
                f"monitoring pull source '{name}' does not declare one usable "
                "http(s) status URL"
            )
        bindings[name] = parsed
    if len(bindings) > MAX_MONITORING_PULL_SOURCES:
        raise MonitoringSourceError(
            f"at most {MAX_MONITORING_PULL_SOURCES} monitoring pull sources may be declared"
        )

    credentials: dict[str, str] = {}
    for entry in _entries(credential_files):
        name, path = _split(entry, kind="credential")
        if name not in bindings:
            raise MonitoringSourceError(
                f"monitoring pull credential names undeclared source '{name}'"
            )
        if name in credentials:
            raise MonitoringSourceError(
                f"monitoring pull credential for source '{name}' is declared more than once"
            )
        if not _valid_credential_path(path):
            raise MonitoringSourceError(
                f"monitoring pull credential for source '{name}' must be one "
                "absolute file path"
            )
        credentials[name] = path

    return MappingProxyType(
        {
            name: MonitoringPullSource(
                name=name,
                url=parsed.url,
                scheme=parsed.scheme,
                host=parsed.host,
                port=parsed.port,
                path=parsed.path,
                credential_file=credentials.get(name),
            )
            for name, parsed in bindings.items()
        }
    )


def _entries(value: str) -> list[str]:
    return [entry.strip() for entry in value.split(",") if entry.strip()]


def _split(entry: str, *, kind: str) -> tuple[str, str]:
    name, separator, remainder = entry.partition("=")
    if not separator:
        raise MonitoringSourceError(
            f"monitoring pull {kind} declarations use name=value"
        )
    return name.strip(), remainder.strip()


def _valid_credential_path(path: str) -> bool:
    return (
        path.startswith("/")
        and 1 < len(path) <= MAX_CREDENTIAL_FILE_PATH_LENGTH
        and not path.endswith("/")
        and all(ord(character) >= 32 and ord(character) != 127 for character in path)
    )
