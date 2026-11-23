"""Deny-by-default target policy for outbound monitoring probes.

Blockwart is an infrastructure catalog: a monitoring target is operator-supplied
catalog data, so an unrestricted outbound fetch would be a server-side request
forgery primitive against the deployment's own network. This module is the one
place that decides whether a concrete connection target is permitted.

The rules are intentionally blunt:

- Only ``http`` and ``https`` are supported. A deployment can allow a
  network on configured ports, or an exact DNS hostname and port for the
  built-in probe if every answer is public unicast.
- Loopback, link-local (including the cloud metadata address), private,
  unique-local, reserved, multicast, and unspecified addresses are blocked
  unless an allowlist entry names that special-purpose range or a subnet of it.
  A broad supernet such as ``0.0.0.0/0`` therefore never unlocks them.
- Every address a hostname resolves to is validated, not just the one that
  happens to be used. The caller then pins the validated address for the
  connection, so re-resolving cannot substitute a different target.

The module is pure: it performs no DNS lookup and opens no socket.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from ipaddress import (
    IPv4Address,
    IPv4Network,
    IPv6Address,
    IPv6Network,
    ip_address,
    ip_network,
)

IPAddress = IPv4Address | IPv6Address
IPNetwork = IPv4Network | IPv6Network

# Redacted denial reasons. They are never rendered to a caller on their own;
# the boundary maps every denial to the single stable ``policy_denied`` error
# code, and these values exist for deterministic tests and operator logs.
POLICY_DENIAL_REASONS: tuple[str, ...] = (
    "allowlist_empty",
    "not_allowlisted",
    "port_not_allowed",
    "scheme_not_allowed",
    "special_purpose_address",
    "unresolvable_address",
)

DEFAULT_ALLOWED_PORTS: tuple[int, ...] = (80, 443)
_ALLOWED_SCHEMES = frozenset({"http", "https"})

# Special-purpose ranges that require an explicit, specific allowlist entry.
# The prefix length of each range is the minimum specificity an entry must have
# before it counts as deliberately naming that range.
_SPECIAL_PURPOSE_RANGES: tuple[IPNetwork, ...] = (
    ip_network("0.0.0.0/8"),
    ip_network("10.0.0.0/8"),
    ip_network("100.64.0.0/10"),
    ip_network("127.0.0.0/8"),
    ip_network("169.254.0.0/16"),
    ip_network("172.16.0.0/12"),
    ip_network("192.0.0.0/24"),
    ip_network("192.0.2.0/24"),
    ip_network("192.168.0.0/16"),
    ip_network("198.18.0.0/15"),
    ip_network("198.51.100.0/24"),
    ip_network("203.0.113.0/24"),
    ip_network("224.0.0.0/4"),
    ip_network("240.0.0.0/4"),
    ip_network("::/128"),
    ip_network("::1/128"),
    ip_network("::ffff:0:0/96"),
    ip_network("64:ff9b::/96"),
    ip_network("100::/64"),
    ip_network("2001::/32"),
    ip_network("2001:db8::/32"),
    ip_network("fc00::/7"),
    ip_network("fe80::/10"),
    ip_network("ff00::/8"),
)

# Additional IANA special-purpose ranges that older ipaddress registries
# may classify as global. Exact hostname rules never authorize these;
# the existing CIDR policy and its explicit exceptions are unchanged.
_HOST_RULE_SPECIAL_RANGES: tuple[IPNetwork, ...] = (
    ip_network("192.88.99.0/24"),
    ip_network("64:ff9b:1::/48"),
    ip_network("100:0:0:1::/64"),
    ip_network("2001::/23"),
    ip_network("2002::/16"),
    ip_network("3fff::/20"),
    ip_network("5f00::/16"),
)


class MonitoringPolicyError(ValueError):
    """The configured monitoring policy itself is invalid."""


@dataclass(frozen=True, slots=True)
class TargetPolicy:
    """An immutable, deny-by-default outbound probe policy."""

    allowed_networks: tuple[IPNetwork, ...] = ()
    allowed_ports: tuple[int, ...] = DEFAULT_ALLOWED_PORTS
    allowed_schemes: frozenset[str] = field(default=_ALLOWED_SCHEMES)
    allowed_hosts: frozenset[tuple[str, int]] = frozenset()

    @property
    def enabled(self) -> bool:
        """Whether any target can be reached at all."""

        return bool(self.allowed_networks or self.allowed_hosts)

    def check_scheme(self, scheme: str) -> str | None:
        if scheme.lower() not in self.allowed_schemes:
            return "scheme_not_allowed"
        return None

    def check_port(self, port: int) -> str | None:
        if port not in self.allowed_ports:
            return "port_not_allowed"
        return None

    def allows_hostname(self, hostname: str | None, port: int) -> bool:
        """Match a canonical target hostname and port, never a suffix or IP."""

        return hostname is not None and (hostname, port) in self.allowed_hosts

    def check_destination(
        self, *, scheme: str, port: int, hostname: str | None = None
    ) -> str | None:
        """Reject a destination before DNS when neither rule could allow it."""

        reason = self.check_scheme(scheme)
        if reason is not None or self.allows_hostname(hostname, port):
            return reason
        reason = self.check_port(port)
        if reason is not None:
            return reason
        return None if self.allowed_networks else "allowlist_empty"

    def check_address(self, address: IPAddress) -> str | None:
        """Return a denial reason for one concrete address, or ``None``."""

        if not self.allowed_networks:
            return "allowlist_empty"
        matching = [
            network
            for network in self.allowed_networks
            if address.version == network.version and address in network
        ]
        if not matching:
            return "not_allowlisted"
        special = _special_purpose_range(address)
        if special is None and not _is_special_purpose(address):
            return None
        if special is not None and any(
            network.prefixlen >= special.prefixlen and network.subnet_of(special)  # type: ignore[arg-type]
            for network in matching
            if network.version == special.version
        ):
            return None
        # Python's address registry can learn a newly reserved range before
        # this module's controlled list does. Such an address stays blocked by
        # default and can only be unlocked by naming the exact IP address.
        if special is None and any(
            network.prefixlen == network.max_prefixlen
            and network.network_address == address
            for network in matching
        ):
            return None
        return "special_purpose_address"

    def check_target(
        self,
        *,
        scheme: str,
        port: int,
        addresses: Sequence[IPAddress],
        hostname: str | None = None,
    ) -> str | None:
        """Validate a whole resolved target.

        Every resolved address must pass. A hostname that resolves to one
        allowed and one denied address is rejected as a whole, so a rebinding
        answer cannot be narrowed down to the permitted record.
        """

        reason = self.check_destination(scheme=scheme, port=port, hostname=hostname)
        if reason is not None:
            return reason
        if not addresses:
            return "unresolvable_address"
        if self.allows_hostname(hostname, port):
            if all(_is_public_unicast(address) for address in addresses):
                return None
            # A hostname rule cannot combine with a CIDR rule to authorize
            # different answers. The network rule must pass independently.
            if not self.allowed_networks or self.check_port(port) is not None:
                return "special_purpose_address"
        for address in addresses:
            address_reason = self.check_address(address)
            if address_reason is not None:
                return address_reason
        return None


def parse_target_policy(
    *,
    allowed_networks: str,
    allowed_ports: str,
    allowed_hosts: str = "",
) -> TargetPolicy:
    """Build a policy from configuration strings, failing closed on nonsense."""

    return TargetPolicy(
        allowed_networks=_parse_networks(allowed_networks),
        allowed_ports=_parse_ports(allowed_ports),
        allowed_hosts=_parse_hosts(allowed_hosts),
    )


def pin_address(addresses: Iterable[IPAddress]) -> IPAddress | None:
    """Choose the one validated address the connection is pinned to.

    The choice is deterministic so a probe cannot silently alternate between
    hosts, and so the audited target matches the connected target.
    """

    ordered = sorted(addresses, key=lambda address: (address.version, address.packed))
    return ordered[0] if ordered else None


def canonical_target_host(value: str) -> str | None:
    """Return an ASCII DNS name or normalized IP literal for socket/TLS use."""

    try:
        return ip_address(value).compressed
    except ValueError:
        pass
    try:
        host = value.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    if not host or len(host) > 253:
        return None
    labels = host.split(".")
    if any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or any(not (character.isalnum() or character == "-") for character in label)
        for label in labels
    ):
        return None
    return host


def _parse_hosts(raw: str) -> frozenset[tuple[str, int]]:
    hosts: set[tuple[str, int]] = set()
    for entry in _entries(raw):
        name, _, port = entry.rpartition(":")
        # Require ASCII configuration so IDNA mappings cannot change the
        # domain the operator intended to authorize.
        hostname = canonical_target_host(name) if name.isascii() else None
        if (
            hostname is None
            or "." not in hostname
            or ":" in hostname
            or name.endswith("..")
            or not hostname.rsplit(".", 1)[1][0].isalpha()
            or not 1 <= len(port) <= 5
            or not port.isascii()
            or not port.isdecimal()
            or not 1 <= int(port) <= 65535
        ):
            raise MonitoringPolicyError(
                "monitoring host rules must be exact ASCII DNS hostname:port pairs (port 1..65535)"
            )
        hosts.add((hostname, int(port)))
    return frozenset(hosts)


def _parse_networks(raw: str) -> tuple[IPNetwork, ...]:
    networks: list[IPNetwork] = []
    for entry in _entries(raw):
        try:
            network = ip_network(entry, strict=False)
        except ValueError as exc:
            raise MonitoringPolicyError(
                "monitoring target allowlist entries must be IP networks"
            ) from exc
        networks.append(network)
    return tuple(networks)


def _parse_ports(raw: str) -> tuple[int, ...]:
    entries = _entries(raw)
    if not entries:
        return ()
    ports: list[int] = []
    for entry in entries:
        if not entry.isdigit():
            raise MonitoringPolicyError("monitoring target ports must be integers")
        port = int(entry)
        if not 1 <= port <= 65535:
            raise MonitoringPolicyError("monitoring target ports must be 1..65535")
        ports.append(port)
    return tuple(sorted(set(ports)))


def _entries(raw: str) -> list[str]:
    return [entry.strip() for entry in raw.split(",") if entry.strip()]


def _special_purpose_range(address: IPAddress) -> IPNetwork | None:
    for network in _SPECIAL_PURPOSE_RANGES:
        if address.version == network.version and address in network:
            return network
    return None


def _is_special_purpose(address: IPAddress) -> bool:
    return bool(
        address.is_loopback
        or address.is_link_local
        or address.is_private
        or address.is_reserved
        or address.is_multicast
        or address.is_unspecified
    )


def _is_public_unicast(address: IPAddress) -> bool:
    if not address.is_global or _is_special_purpose(address):
        return False
    if isinstance(address, IPv6Address) and (address.is_site_local or address.scope_id):
        return False
    return _special_purpose_range(address) is None and not any(
        address in network for network in _HOST_RULE_SPECIAL_RANGES
    )
