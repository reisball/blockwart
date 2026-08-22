from __future__ import annotations

RELEASE_ERROR_SCHEMA_VERSION = 1


class ReleaseError(RuntimeError):
    """Stable, redacted failure for the host-side release workflow.

    ``code`` is a stable machine identifier. ``gate`` names the bounded gate
    that failed. The message never carries a path, endpoint, environment
    value, database content, or credential; callers report the code only.
    """

    def __init__(
        self,
        code: str,
        *,
        gate: str = "preflight",
        service_mutated: bool = False,
    ) -> None:
        super().__init__(code)
        self.code = code
        self.gate = gate
        self.service_mutated = service_mutated


class ReleaseRollbackError(ReleaseError):
    """A failure raised while restoring the previous release.

    A rollback failure is always fail-closed: the workflow stops, preserves
    every artifact and backup, and reports the originating failure together
    with the rollback failure code.
    """

    def __init__(self, code: str, *, gate: str, original_code: str) -> None:
        super().__init__(code, gate=gate, service_mutated=True)
        self.original_code = original_code
