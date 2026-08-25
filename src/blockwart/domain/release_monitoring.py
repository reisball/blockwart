"""Public release monitoring for services (#105).

Blockwart already knows which version of a service an operator documented by
hand at ``data.service_information.running_version``.  This module adds the one
missing half: what the upstream project currently publishes as its newest
stable release, and whether the two differ.

Three concerns stay strictly separate, mirroring the health-monitoring contract
in :mod:`blockwart.domain.monitoring`:

- **Configuration** is embedded business data of one ``service`` catalog object
  at ``data.release_monitoring``.  It is opt-in, closed, and typed.  An absent
  document is exactly ``enabled=false``, so every existing service stays
  unmonitored after an upgrade.
- **Target resolution** is a pure function of that document.  It admits exactly
  one canonical *public* GitHub ``owner/repo`` identity.  There is deliberately
  no field for a host, a scheme, a port, an API path, a token, or a URL, so
  catalog data can never choose where a release check connects.
- **Observation** is the bounded, redacted result of one check.  It is stored
  beside the catalog row, never inside it, so a check can never advance an
  object revision, a business ``updated_at``, or the object audit timeline.

Release status is deliberately *not* health.  A pending update is not an
incident, an unreachable GitHub API is not a service outage, and nothing in
this module feeds ``effective_health`` or the health observation tables.  The
derived attention view may point at a proven update, but it does not reinterpret
that signal as availability.  The two acquisition contracts share bounded
transport and leased-scheduling primitives and nothing else.

Nothing in this module performs I/O.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Any, Literal
from urllib.parse import quote

from blockwart.domain.timestamps import format_rfc3339_utc

ReleaseProvider = Literal["github_releases"]
ReleaseStatus = Literal["unknown", "current", "update_available", "error"]
ReleaseComparison = Literal["unknown", "current", "update_available"]
ReleaseFreshness = Literal["pending", "fresh", "stale"]
ReleaseDiagnostic = Literal[
    "invalid_release_monitoring_config",
    "missing_github_repository",
]
ReleaseErrorCode = Literal[
    "connect_failed",
    "dns_failed",
    "http_client_error",
    "http_server_error",
    "invalid_release_version",
    "invalid_target",
    "not_a_stable_release",
    "not_found",
    "policy_denied",
    "provider_failed",
    "rate_limited",
    "redirect_not_supported",
    "response_too_large",
    "timeout",
    "tls_failed",
    "unreadable_release",
]

# The provider identity is explicit and closed.  v1 ships exactly one: the
# official "latest stable full release" contract of a *public* GitHub
# repository.  Private repositories, tokens, prereleases, raw tags, GitLab,
# Gitea, OCI registries, and free-form URL scrapers are out of scope, and none
# of them is expressible in this vocabulary.
RELEASE_PROVIDER_VALUES: tuple[str, ...] = ("github_releases",)
RELEASE_PROVIDERS = frozenset(RELEASE_PROVIDER_VALUES)
DEFAULT_RELEASE_PROVIDER = "github_releases"

RELEASE_STATUS_VALUES: tuple[str, ...] = (
    "unknown",
    "current",
    "update_available",
    "error",
)
RELEASE_STATUSES = frozenset(RELEASE_STATUS_VALUES)
RELEASE_FRESHNESS_VALUES: tuple[str, ...] = ("pending", "fresh", "stale")

RELEASE_DIAGNOSTIC_VALUES: tuple[str, ...] = (
    "invalid_release_monitoring_config",
    "missing_github_repository",
)
RELEASE_DIAGNOSTICS = frozenset(RELEASE_DIAGNOSTIC_VALUES)

# Stable, redacted acquisition error codes.  An adapter may report only one of
# these; no upstream body, header, hostname, or exception text ever becomes a
# published or logged value.
RELEASE_ERROR_CODE_VALUES: tuple[str, ...] = (
    "connect_failed",
    "dns_failed",
    "http_client_error",
    "http_server_error",
    "invalid_release_version",
    "invalid_target",
    "not_a_stable_release",
    "not_found",
    "policy_denied",
    "provider_failed",
    "rate_limited",
    "redirect_not_supported",
    "response_too_large",
    "timeout",
    "tls_failed",
    "unreadable_release",
)
RELEASE_ERROR_CODES = frozenset(RELEASE_ERROR_CODE_VALUES)

# Public GitHub answers 60 unauthenticated requests per hour and IP.  The
# defaults are therefore deliberately far slower than health monitoring: a
# release appears once in a while, and a catalog is not a mirror.
DEFAULT_RELEASE_INTERVAL_SECONDS = 86400
MIN_RELEASE_INTERVAL_SECONDS = 3600
MAX_RELEASE_INTERVAL_SECONDS = 604800

# The smallest gap between two outbound checks for one service, whoever asked.
# It bounds how often a manual "check now" can spend the deployment's shared
# rate-limit budget.
MIN_RELEASE_CHECK_COOLDOWN_SECONDS = 300

# Consecutive failures multiply the next due interval by 2**failures, capped
# here, so an outage or a rate limit can never become a tight retry loop.
MAX_RELEASE_BACKOFF_FACTOR = 8

RELEASE_DOCUMENT_KEYS = frozenset({"enabled", "provider", "interval_seconds", "github"})
GITHUB_DOCUMENT_KEYS = frozenset({"owner", "repo"})

MAX_GITHUB_OWNER_LENGTH = 39
MAX_GITHUB_REPO_LENGTH = 100
MAX_RELEASE_TAG_LENGTH = 128
MAX_RELEASE_VERSION_LENGTH = 64
MAX_RELEASE_ETAG_LENGTH = 128

# GitHub's own account-name rule: alphanumeric plus single inner hyphens.
_GITHUB_OWNER = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$")
# GitHub's own repository-name rule, minus the "." and ".." reserved names.
_GITHUB_REPO = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
# A tag becomes part of a link we render, so its charset is restricted to
# characters that are already safe in a URL path segment.
_RELEASE_TAG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+/-]{0,127}$")
# A conservative, strictly numeric dotted version.  Anything else — a
# prerelease suffix, a build tag, a date-with-words CalVer, a channel name — is
# deliberately *not* forced into an order.
_NUMERIC_VERSION = re.compile(r"^\d{1,9}(?:\.\d{1,9}){0,3}$")
_ETAG = re.compile(r'^(?:W/)?"[!#-~]*"$')

GITHUB_API_HOST = "api.github.com"
GITHUB_API_SCHEME = "https"
GITHUB_API_PORT = 443
GITHUB_WEB_ORIGIN = "https://github.com"


@dataclass(frozen=True, slots=True)
class ReleaseMonitoringConfig:
    """The effective release-monitoring configuration of one service."""

    enabled: bool = False
    provider: str | None = DEFAULT_RELEASE_PROVIDER
    interval_seconds: int | None = DEFAULT_RELEASE_INTERVAL_SECONDS
    # True when the service stores an explicit interval override.  The server
    # default applies otherwise, so changing it moves every non-overriding
    # service without a catalog write.
    interval_overridden: bool = False
    valid: bool = True


@dataclass(frozen=True, slots=True)
class GithubReleaseTarget:
    """One canonical public GitHub repository identity.

    It is an *identity*, never a location.  The API origin and the API path are
    compiled in; catalog data supplies only the two path segments, and both are
    validated against GitHub's own naming rules before they are used.
    """

    owner: str
    repo: str

    @property
    def slug(self) -> str:
        return f"{self.owner}/{self.repo}"

    @property
    def cache_key(self) -> str:
        """Opaque identity binding for observations and conditional requests."""

        canonical = f"{self.owner.casefold()}/{self.repo.casefold()}"
        return sha256(canonical.encode("utf-8")).hexdigest()

    @property
    def api_path(self) -> str:
        return f"/repos/{quote(self.owner, safe='')}/{quote(self.repo, safe='')}/releases/latest"

    @property
    def api_url(self) -> str:
        return f"{GITHUB_API_SCHEME}://{GITHUB_API_HOST}{self.api_path}"

    @property
    def repository_url(self) -> str:
        return f"{GITHUB_WEB_ORIGIN}/{quote(self.owner, safe='')}/{quote(self.repo, safe='')}"

    def release_url(self, tag: str | None) -> str | None:
        """Derive the canonical release link from validated parts only.

        The upstream ``html_url`` is never used: it is attacker-controlled data
        from the perspective of this deployment.  The link is rebuilt from the
        validated owner, the validated repository, and the validated tag, so a
        hostile payload cannot redirect a reader anywhere.
        """

        if tag is None or not valid_release_tag(tag):
            return None
        return f"{self.repository_url}/releases/tag/{quote(tag, safe='')}"

    def as_dict(self) -> dict[str, Any]:
        return {
            "owner": self.owner,
            "repo": self.repo,
            "slug": self.slug,
            "repository_url": self.repository_url,
            "api_url": self.api_url,
        }


@dataclass(frozen=True, slots=True)
class GithubTargetResolution:
    target: GithubReleaseTarget | None
    diagnostic: ReleaseDiagnostic | None = None


@dataclass(frozen=True, slots=True)
class ReleaseObservation:
    """One bounded, canonical result of a single release check.

    ``outcome`` distinguishes the three deterministic shapes an adapter may
    return:

    - ``observed``: the provider answered with one usable stable release;
    - ``not_modified``: the provider confirmed the cached release is still the
      newest one (HTTP 304).  It refreshes the evidence instant and clears the
      error state without touching the stored release;
    - ``error``: the check could not obtain usable evidence.  It never claims
      anything about the upstream project or about the service.
    """

    provider: str
    outcome: Literal["observed", "not_modified", "error"]
    checked_at: datetime
    latest_tag: str | None = None
    latest_version: str | None = None
    released_at: datetime | None = None
    etag: str | None = None
    http_status: int | None = None
    error_code: ReleaseErrorCode | None = None
    # Seconds the provider explicitly asked this deployment to wait, derived
    # from Retry-After or the rate-limit reset instant.  It only ever delays a
    # check; it can never make one happen sooner.
    retry_after_seconds: int | None = None

    def __post_init__(self) -> None:
        if self.provider not in RELEASE_PROVIDERS:
            raise ValueError("unknown release provider")
        if self.outcome not in {"observed", "not_modified", "error"}:
            raise ValueError("unknown release observation outcome")
        if self.error_code is not None and self.error_code not in RELEASE_ERROR_CODES:
            raise ValueError("unknown release error code")
        if self.outcome == "error" and self.error_code is None:
            raise ValueError("a failed release check requires an error code")
        if self.outcome != "error" and self.error_code is not None:
            raise ValueError("a successful release check cannot carry an error code")
        if self.outcome == "observed" and not self.latest_tag:
            raise ValueError("an observed release requires a tag")
        if self.http_status is not None and not 100 <= self.http_status <= 599:
            raise ValueError("http status is out of range")
        if self.retry_after_seconds is not None and self.retry_after_seconds < 0:
            raise ValueError("retry after must not be negative")


@dataclass(frozen=True, slots=True)
class ReleaseRecord:
    """The persisted release-observation state of one service/provider pair."""

    provider: str
    target_key: str | None = None
    latest_tag: str | None = None
    latest_version: str | None = None
    released_at: datetime | None = None
    etag: str | None = None
    http_status: int | None = None
    error_code: str | None = None
    consecutive_failures: int = 0
    last_checked_at: datetime | None = None
    last_success_at: datetime | None = None
    next_due_at: datetime | None = None
    object_instance_id: str | None = None


def valid_github_owner(value: str) -> bool:
    """Whether ``value`` is one canonical GitHub account name."""

    return (
        1 <= len(value) <= MAX_GITHUB_OWNER_LENGTH
        and _GITHUB_OWNER.match(value) is not None
    )


def valid_github_repo(value: str) -> bool:
    """Whether ``value`` is one canonical GitHub repository name."""

    return (
        1 <= len(value) <= MAX_GITHUB_REPO_LENGTH
        and value not in {".", ".."}
        and _GITHUB_REPO.match(value) is not None
    )


def valid_release_tag(value: str) -> bool:
    """Whether an upstream tag may be stored and rendered as a link segment.

    The rule is deliberately narrower than Git's: a tag reaches a URL and a
    template, so anything outside an already URL-safe charset is refused rather
    than escaped into something a reader cannot verify.
    """

    return (
        1 <= len(value) <= MAX_RELEASE_TAG_LENGTH
        and ".." not in value
        and "//" not in value
        and not value.endswith("/")
        and _RELEASE_TAG.match(value) is not None
    )


def valid_release_etag(value: str) -> bool:
    """Whether an upstream ETag may be stored and replayed as If-None-Match."""

    return 1 <= len(value) <= MAX_RELEASE_ETAG_LENGTH and _ETAG.match(value) is not None


def normalize_version(value: Any) -> str | None:
    """Return the comparable form of one version string, or ``None``.

    The only agreed normalization is the common leading ``v`` prefix, which
    upstream projects add to a tag but operators rarely type into a running
    version.  It is removed only when a digit follows, so ``vault`` stays
    ``vault`` and ``v2.4.1`` becomes ``2.4.1``.

    Everything else is left exactly as written.  A value that is empty,
    over-long, or contains whitespace or control characters is not comparable
    at all and returns ``None``, which keeps the status ``unknown`` instead of
    inventing an order.
    """

    if not isinstance(value, str):
        return None
    text = value.strip()
    if not 1 <= len(text) <= MAX_RELEASE_VERSION_LENGTH:
        return None
    if any(
        character.isspace() or ord(character) < 32 or ord(character) == 127
        for character in text
    ):
        return None
    if len(text) >= 2 and text[0] in {"v", "V"} and text[1].isdigit():
        text = text[1:]
    return text or None


def compare_versions(running: Any, latest: Any) -> ReleaseComparison:
    """Compare a documented running version against an observed release.

    The rule is deliberately conservative and has exactly three outcomes:

    - equal after normalization, compared case-insensitively: ``current``;
    - both sides are strictly numeric dotted versions (``1``, ``1.2``,
      ``1.2.3``, ``1.2.3.4``) and the observed one sorts higher:
      ``update_available``.  A running version that sorts higher than the
      published release is ``current``: there is no update to offer;
    - anything else — an unknown, empty, or unparsable value on either side, a
      prerelease or build suffix, a named CalVer form, a channel name, or two
      differently shaped schemes — is ``unknown``.

    SemVer prerelease precedence, named CalVer conventions, and other tag
    conventions are **not** reimplemented here.  Plain numeric dotted values
    (including an unambiguous numeric date such as ``2026.08``) use the same
    component-wise rule; guessing between ``2.0.0-rc1`` and ``2.0.0`` or
    between ``2026-Q3`` and ``2026-Q4`` instead abstains.
    """

    normalized_running = normalize_version(running)
    normalized_latest = normalize_version(latest)
    if normalized_running is None or normalized_latest is None:
        return "unknown"
    if normalized_running.casefold() == normalized_latest.casefold():
        return "current"
    if (
        _NUMERIC_VERSION.match(normalized_running) is None
        or _NUMERIC_VERSION.match(normalized_latest) is None
    ):
        return "unknown"
    return (
        "update_available"
        if _numeric_key(normalized_latest) > _numeric_key(normalized_running)
        else "current"
    )


def read_release_monitoring_config(
    data: Mapping[str, Any],
    *,
    default_interval_seconds: int = DEFAULT_RELEASE_INTERVAL_SECONDS,
) -> ReleaseMonitoringConfig:
    """Read one service's effective release-monitoring configuration.

    An absent document is the backward-compatible disabled configuration.  A
    present malformed document is instead an explicit invalid configuration: it
    receives no provider or interval fallback and can never become check work.
    Reads stay total for legacy or hand-edited database rows.
    """

    if not isinstance(data, Mapping) or "release_monitoring" not in data:
        return ReleaseMonitoringConfig(
            interval_seconds=_bounded_interval(default_interval_seconds),
        )
    document = data.get("release_monitoring")
    enabled = isinstance(document, Mapping) and document.get("enabled") is True
    if not isinstance(document, Mapping) or not _valid_release_document(document):
        return ReleaseMonitoringConfig(
            enabled=enabled,
            provider=None,
            interval_seconds=None,
            valid=False,
        )
    provider = document.get("provider", DEFAULT_RELEASE_PROVIDER)
    assert isinstance(provider, str)
    raw_interval = document.get("interval_seconds")
    overridden = raw_interval is not None
    interval = (
        int(raw_interval) if overridden else _bounded_interval(default_interval_seconds)
    )
    return ReleaseMonitoringConfig(
        enabled=enabled,
        provider=provider,
        interval_seconds=interval,
        interval_overridden=overridden,
    )


def normalize_service_release_monitoring(data: Mapping[str, Any]) -> dict[str, Any]:
    """Return data with a canonical release-monitoring document.

    An absent document stays absent, so every existing service record remains
    byte-for-byte identical after an upgrade.  A present document is left
    structurally intact for the schema validator to reject with an exact field
    path; only surrounding whitespace is trimmed.
    """

    normalized = deepcopy(dict(data))
    document = normalized.get("release_monitoring")
    if not isinstance(document, dict):
        return normalized
    provider = document.get("provider")
    if isinstance(provider, str):
        document["provider"] = provider.strip()
    github = document.get("github")
    if isinstance(github, dict):
        for key in ("owner", "repo"):
            value = github.get(key)
            if isinstance(value, str):
                github[key] = value.strip()
    return normalized


def service_release_monitoring_violations(
    data: Mapping[str, Any],
) -> tuple[tuple[str, str], ...]:
    """Return ``(path, message)`` violations after declarative field checks."""

    document = data.get("release_monitoring")
    if document is None or not isinstance(document, Mapping):
        return ()
    if "enabled" not in document:
        return (
            (
                "data.release_monitoring.enabled",
                "is required when data.release_monitoring is present",
            ),
        )
    github = document.get("github")
    if document.get("enabled") is True and not isinstance(github, Mapping):
        return (
            (
                "data.release_monitoring.github",
                "is required when data.release_monitoring.enabled is true",
            ),
        )
    if isinstance(github, Mapping):
        for key in sorted(GITHUB_DOCUMENT_KEYS):
            if key not in github:
                return (
                    (
                        f"data.release_monitoring.github.{key}",
                        "is required when data.release_monitoring.github is present",
                    ),
                )
    return ()


def read_github_release_target(
    data: Mapping[str, Any],
    *,
    object_id: str = "<service>",
) -> GithubTargetResolution:
    """Read the canonical public GitHub identity one service declares.

    This is the release-monitoring counterpart to health monitoring's target
    resolution, and it is deliberately *not* a URL: catalog data names an owner
    and a repository, and this module compiles in the only origin and the only
    API path a check may ever use.

    Args:
        data: The service's catalog data document.
        object_id: The service id, accepted for signature symmetry; it never
            appears in a diagnostic.

    Returns:
        The validated identity, or ``missing_github_repository`` when the
        document is absent, incomplete, or not a canonical public
        ``owner/repo``.  Every unusable identity fails closed.
    """

    del object_id
    document = data.get("release_monitoring") if isinstance(data, Mapping) else None
    github = document.get("github") if isinstance(document, Mapping) else None
    if not isinstance(github, Mapping) or set(github) != GITHUB_DOCUMENT_KEYS:
        return GithubTargetResolution(None, "missing_github_repository")
    owner = github.get("owner")
    repo = github.get("repo")
    if not isinstance(owner, str) or not isinstance(repo, str):
        return GithubTargetResolution(None, "missing_github_repository")
    owner = owner.strip()
    repo = repo.strip()
    if not valid_github_owner(owner) or not valid_github_repo(repo):
        return GithubTargetResolution(None, "missing_github_repository")
    return GithubTargetResolution(GithubReleaseTarget(owner=owner, repo=repo))


def release_freshness_for(
    record: ReleaseRecord | None,
    *,
    interval_seconds: int,
    now: datetime,
) -> ReleaseFreshness:
    """Classify how current the stored release evidence is.

    Freshness follows the last **successful** check, because that is the
    instant this deployment last confirmed what upstream publishes.  A run of
    failing checks therefore ages the evidence normally instead of pretending
    that a fresh attempt is fresh knowledge.
    """

    if record is None or record.last_success_at is None:
        return "pending"
    expires_at = (
        _aware(record.next_due_at)
        if record.next_due_at is not None
        else _aware(record.last_success_at) + timedelta(seconds=interval_seconds)
    )
    return "stale" if _aware(now) > expires_at else "fresh"


def release_status(
    *,
    record: ReleaseRecord | None,
    running_version: Any,
    freshness: ReleaseFreshness,
    config_valid: bool = True,
    diagnostic: ReleaseDiagnostic | None = None,
) -> ReleaseStatus:
    """Return the one release state a reader may act on.

    The precedence is fixed and total:

    1. an invalid configuration or an unusable repository identity is
       ``error``: no check can ever run;
    2. a stored failing check is ``error``, so a controlled failure stays
       visible instead of being hidden behind older evidence;
    3. evidence that is pending or stale is ``unknown``: an old release claim
       must never be published as a current one;
    4. otherwise the conservative comparison decides, and abstains with
       ``unknown`` whenever it cannot prove the relation.
    """

    if not config_valid or diagnostic is not None:
        return "error"
    if record is not None and record.error_code is not None:
        return "error"
    if record is None or freshness in {"pending", "stale"}:
        return "unknown"
    return compare_versions(running_version, record.latest_version)


def scheduled_release_due(
    checked_at: datetime,
    *,
    object_id: str,
    object_instance_id: str | None,
    provider: str,
    interval_seconds: int,
    jitter_seconds: int,
    consecutive_failures: int = 0,
    retry_after_seconds: int | None = None,
) -> datetime:
    """Return the stable due time for one release observation.

    Three bounded rules combine, and every one of them can only ever *delay* a
    check:

    - the effective interval, multiplied by ``2**consecutive_failures`` and
      capped at :data:`MAX_RELEASE_BACKOFF_FACTOR`;
    - an explicit provider request (``Retry-After`` or the rate-limit reset),
      which raises the delay when it is longer than the backed-off interval;
    - deterministic jitter derived from immutable observation identity rather
      than process randomness, so every process reconciles an interval change
      to the same value, including after a restart.
    """

    checked = _aware(checked_at)
    factor = min(2 ** max(0, consecutive_failures), MAX_RELEASE_BACKOFF_FACTOR)
    delay = interval_seconds * factor
    if retry_after_seconds is not None:
        delay = max(delay, retry_after_seconds)
    delay = min(delay, MAX_RELEASE_INTERVAL_SECONDS * MAX_RELEASE_BACKOFF_FACTOR)
    key = "\x1f".join(
        (
            object_id,
            object_instance_id or "",
            provider,
            checked.astimezone(UTC).isoformat(timespec="microseconds"),
        )
    )
    return checked + timedelta(seconds=delay + _stable_jitter(key, jitter_seconds))


def release_monitoring_view(
    *,
    data: Mapping[str, Any],
    object_id: str,
    record: ReleaseRecord | None,
    now: datetime,
    default_interval_seconds: int = DEFAULT_RELEASE_INTERVAL_SECONDS,
    jitter_seconds: int = 0,
) -> dict[str, Any]:
    """Build the one authorized release projection every surface shares.

    The result contains only bounded, validated, provider-neutral fields.  No
    upstream text — release notes, titles, author names, asset names, error
    strings — ever reaches it, and the release link is rebuilt from validated
    parts rather than copied from the payload.
    """

    config = read_release_monitoring_config(
        data,
        default_interval_seconds=default_interval_seconds,
    )
    running_version = _running_version(data)
    if not config.valid:
        return {
            "enabled": config.enabled,
            "provider": None,
            "interval_seconds": None,
            "interval_overridden": False,
            "target": None,
            "diagnostic": "invalid_release_monitoring_config",
            "status": "error",
            "observed_status": "unknown",
            "freshness": "pending",
            "running_version": running_version,
            "latest_version": None,
            "latest_tag": None,
            "release_url": None,
            "released_at": None,
            "http_status": None,
            "error_code": None,
            "consecutive_failures": 0,
            "last_checked_at": None,
            "last_success_at": None,
            "next_due_at": None,
        }
    assert config.provider is not None
    assert config.interval_seconds is not None
    resolution = read_github_release_target(data, object_id=object_id)
    target = resolution.target
    diagnostic = resolution.diagnostic if config.enabled else None
    matching = (
        record
        if record is not None
        and record.provider == config.provider
        and target is not None
        and record.target_key == target.cache_key
        else None
    )
    freshness = release_freshness_for(
        matching,
        interval_seconds=config.interval_seconds,
        now=now,
    )
    status = release_status(
        record=matching,
        running_version=running_version,
        freshness=freshness,
        config_valid=True,
        diagnostic=diagnostic,
    )
    next_due_at = (
        _aware(matching.next_due_at)
        if matching is not None and matching.next_due_at is not None
        else (
            scheduled_release_due(
                matching.last_checked_at,
                object_id=object_id,
                object_instance_id=matching.object_instance_id,
                provider=config.provider,
                interval_seconds=config.interval_seconds,
                jitter_seconds=jitter_seconds,
                consecutive_failures=matching.consecutive_failures,
            )
            if matching is not None and matching.last_checked_at is not None
            else None
        )
    )
    return {
        "enabled": config.enabled,
        "provider": config.provider,
        "interval_seconds": config.interval_seconds,
        "interval_overridden": config.interval_overridden,
        "target": target.as_dict() if target is not None else None,
        "diagnostic": diagnostic,
        "status": status,
        "observed_status": compare_versions(
            running_version,
            matching.latest_version if matching is not None else None,
        ),
        "freshness": freshness,
        "running_version": running_version,
        "latest_version": matching.latest_version if matching is not None else None,
        "latest_tag": matching.latest_tag if matching is not None else None,
        "release_url": (
            target.release_url(matching.latest_tag)
            if target is not None and matching is not None
            else None
        ),
        "released_at": format_rfc3339_utc(
            matching.released_at if matching is not None else None
        ),
        "http_status": matching.http_status if matching is not None else None,
        "error_code": matching.error_code if matching is not None else None,
        "consecutive_failures": (
            matching.consecutive_failures if matching is not None else 0
        ),
        "last_checked_at": format_rfc3339_utc(
            matching.last_checked_at if matching is not None else None
        ),
        "last_success_at": format_rfc3339_utc(
            matching.last_success_at if matching is not None else None
        ),
        "next_due_at": format_rfc3339_utc(next_due_at),
    }


def service_release_monitoring_contract_projection() -> dict[str, Any]:
    """Publish the machine-readable release-monitoring contract."""

    return {
        "storage_path": "data.release_monitoring",
        "absent_configuration": "disabled",
        "providers": list(RELEASE_PROVIDER_VALUES),
        "default_provider": DEFAULT_RELEASE_PROVIDER,
        "statuses": list(RELEASE_STATUS_VALUES),
        "freshness": list(RELEASE_FRESHNESS_VALUES),
        "diagnostics": list(RELEASE_DIAGNOSTIC_VALUES),
        "error_codes": list(RELEASE_ERROR_CODE_VALUES),
        "interval_seconds": {
            "default": DEFAULT_RELEASE_INTERVAL_SECONDS,
            "minimum": MIN_RELEASE_INTERVAL_SECONDS,
            "maximum": MAX_RELEASE_INTERVAL_SECONDS,
            "server_default_configurable": True,
            "min_check_cooldown_seconds": MIN_RELEASE_CHECK_COOLDOWN_SECONDS,
            "max_backoff_factor": MAX_RELEASE_BACKOFF_FACTOR,
        },
        "target": {
            "identity_path": "data.release_monitoring.github",
            "identity_fields": sorted(GITHUB_DOCUMENT_KEYS),
            "api_origin": f"{GITHUB_API_SCHEME}://{GITHUB_API_HOST}",
            "api_path_template": "/repos/{owner}/{repo}/releases/latest",
            "host_configurable": False,
            "scheme_configurable": False,
            "port_configurable": False,
            "path_configurable": False,
            "authenticated": False,
            "private_repositories": False,
            "prereleases": False,
            "drafts": False,
            "raw_tags": False,
            "redirects_followed": False,
            "release_notes_stored": False,
        },
        "comparison": {
            "normalizes_leading_v_prefix": True,
            "case_insensitive_equality": True,
            "numeric_dotted_ordering": True,
            "semver_precedence": False,
            "named_calver_conventions": False,
            "prerelease_ordering": False,
            "unresolved_comparison": "unknown",
        },
        "running_version_source": "data.service_information.running_version",
        "writes_running_version": False,
        "inheritance": {
            "visibility": True,
            "rbac": True,
            "advances_object_revision": False,
            "advances_business_updated_at": False,
            "object_audit_per_check": False,
        },
        "affects_health": False,
        "external_delivery": False,
    }


def _running_version(data: Mapping[str, Any]) -> str | None:
    """Read the manually documented running version, or ``None``.

    v1 monitors exactly this one manually curated field.  ``installed_software``
    is deliberately not consulted: it is a different contract with a different
    meaning, and silently treating it as a second source would make the
    published status depend on data an operator never reviewed for this
    purpose.
    """

    if not isinstance(data, Mapping):
        return None
    information = data.get("service_information")
    if not isinstance(information, Mapping):
        return None
    value = information.get("running_version")
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text if 1 <= len(text) <= MAX_RELEASE_VERSION_LENGTH else None


def _numeric_key(value: str) -> tuple[int, ...]:
    parts = [int(part) for part in value.split(".")]
    return tuple(parts + [0] * (4 - len(parts)))


def _bounded_interval(value: int) -> int:
    return max(
        MIN_RELEASE_INTERVAL_SECONDS,
        min(MAX_RELEASE_INTERVAL_SECONDS, int(value)),
    )


def _valid_release_document(document: Mapping[str, Any]) -> bool:
    if not set(document).issubset(RELEASE_DOCUMENT_KEYS):
        return False
    if not isinstance(document.get("enabled"), bool):
        return False
    provider = document.get("provider", DEFAULT_RELEASE_PROVIDER)
    if not isinstance(provider, str) or provider not in RELEASE_PROVIDERS:
        return False
    if document.get("enabled") is True and "github" not in document:
        return False
    if "github" in document and not _valid_github_document(document["github"]):
        return False
    if "interval_seconds" not in document:
        return True
    interval = document.get("interval_seconds")
    return (
        isinstance(interval, int)
        and not isinstance(interval, bool)
        and MIN_RELEASE_INTERVAL_SECONDS <= interval <= MAX_RELEASE_INTERVAL_SECONDS
    )


def _valid_github_document(value: Any) -> bool:
    """Whether a stored GitHub sub-document is complete and in bounds.

    A hand-edited or legacy row with a malformed sub-document is an explicit
    invalid configuration rather than a partially usable one, so it can never
    become check work.
    """

    if not isinstance(value, Mapping) or set(value) != GITHUB_DOCUMENT_KEYS:
        return False
    owner = value.get("owner")
    repo = value.get("repo")
    if not isinstance(owner, str) or not isinstance(repo, str):
        return False
    return valid_github_owner(owner.strip()) and valid_github_repo(repo.strip())


def _stable_jitter(key: str, jitter_seconds: int) -> int:
    if jitter_seconds <= 0:
        return 0
    digest = sha256(key.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") % (jitter_seconds + 1)


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)
