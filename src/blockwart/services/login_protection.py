from __future__ import annotations

import hashlib
import time
from collections import deque
from collections.abc import Callable
from threading import BoundedSemaphore, Lock
from types import TracebackType


class LoginAttemptLease:
    def __init__(
        self,
        *,
        allowed: bool,
        event_due: bool,
        reason: str,
        semaphore: BoundedSemaphore | None = None,
    ) -> None:
        self.allowed = allowed
        self.event_due = event_due
        self.reason = reason
        self._semaphore = semaphore

    def __enter__(self) -> LoginAttemptLease:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if self._semaphore is not None:
            self._semaphore.release()
            self._semaphore = None


class LoginProtector:
    """Bound password work and unauthenticated login writes per app process."""

    def __init__(
        self,
        *,
        window_seconds: int,
        source_attempt_limit: int,
        account_attempt_limit: int,
        global_attempt_limit: int,
        source_challenge_limit: int,
        global_challenge_limit: int,
        max_password_concurrency: int,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._window_seconds = window_seconds
        self._source_attempt_limit = source_attempt_limit
        self._account_attempt_limit = account_attempt_limit
        self._global_attempt_limit = global_attempt_limit
        self._source_challenge_limit = source_challenge_limit
        self._global_challenge_limit = global_challenge_limit
        self._clock = clock
        self._lock = Lock()
        self._password_slots = BoundedSemaphore(max_password_concurrency)
        self._attempt_global: deque[float] = deque()
        self._attempt_sources: dict[str, deque[float]] = {}
        self._attempt_accounts: dict[str, deque[float]] = {}
        self._challenge_global: deque[float] = deque()
        self._challenge_sources: dict[str, deque[float]] = {}
        self._event_until: dict[tuple[str, str], float] = {}
        self._next_security_event_prune = 0.0

    def allow_challenge(self, *, source: str) -> bool:
        now = self._clock()
        source_key = _fingerprint(source)
        with self._lock:
            self._purge(now)
            source_bucket = self._challenge_sources.setdefault(source_key, deque())
            if (
                len(self._challenge_global) >= self._global_challenge_limit
                or len(source_bucket) >= self._source_challenge_limit
            ):
                return False
            self._challenge_global.append(now)
            source_bucket.append(now)
            return True

    def acquire_password_attempt(
        self,
        *,
        source: str,
        login: str,
    ) -> LoginAttemptLease:
        now = self._clock()
        source_key = _fingerprint(source)
        account_key = _fingerprint(login.strip().casefold())
        with self._lock:
            self._purge(now)
            source_bucket = self._attempt_sources.setdefault(source_key, deque())
            account_bucket = self._attempt_accounts.setdefault(account_key, deque())
            if len(self._attempt_global) >= self._global_attempt_limit:
                return self._denied(now, "global_rate", "global")
            if len(source_bucket) >= self._source_attempt_limit:
                return self._denied(now, "source_rate", source_key)
            if len(account_bucket) >= self._account_attempt_limit:
                return self._denied(now, "account_rate", account_key)
            self._attempt_global.append(now)
            source_bucket.append(now)
            account_bucket.append(now)

        if not self._password_slots.acquire(blocking=False):
            with self._lock:
                return self._denied(now, "password_capacity", "global")
        return LoginAttemptLease(
            allowed=True,
            event_due=False,
            reason="allowed",
            semaphore=self._password_slots,
        )

    def security_event_prune_due(self, *, interval_seconds: int = 3600) -> bool:
        now = self._clock()
        with self._lock:
            if now < self._next_security_event_prune:
                return False
            self._next_security_event_prune = now + interval_seconds
            return True

    def _denied(self, now: float, reason: str, key: str) -> LoginAttemptLease:
        event_key = (reason, key)
        event_due = now >= self._event_until.get(event_key, 0.0)
        if event_due:
            self._event_until[event_key] = now + self._window_seconds
        return LoginAttemptLease(
            allowed=False,
            event_due=event_due,
            reason=reason,
        )

    def _purge(self, now: float) -> None:
        cutoff = now - self._window_seconds
        _purge_times(self._attempt_global, cutoff)
        _purge_times(self._challenge_global, cutoff)
        _purge_bucket_map(self._attempt_sources, cutoff)
        _purge_bucket_map(self._attempt_accounts, cutoff)
        _purge_bucket_map(self._challenge_sources, cutoff)
        self._event_until = {
            key: expires_at
            for key, expires_at in self._event_until.items()
            if expires_at > now
        }


def _purge_bucket_map(
    buckets: dict[str, deque[float]],
    cutoff: float,
) -> None:
    for key, bucket in list(buckets.items()):
        _purge_times(bucket, cutoff)
        if not bucket:
            del buckets[key]


def _purge_times(values: deque[float], cutoff: float) -> None:
    while values and values[0] <= cutoff:
        values.popleft()


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()
