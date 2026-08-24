"""Host-side, rollback-safe release workflow for containerized Blockwart installations.

This package never runs inside the served application. It builds or registers
one immutable release bundle, proves it against a restored database copy, and
performs an atomic cutover with automatic verified rollback.
"""

from blockwart.release.errors import ReleaseError, ReleaseRollbackError
from blockwart.release.schemas import SCHEMA_NAMES, json_schema
from blockwart.release.spec import (
    MANIFEST_VERSION,
    REPORT_SCHEMA_VERSION,
    SPEC_VERSION,
    ReleaseSpec,
    load_spec,
    parse_spec,
    release_id,
)
from blockwart.release.workflow import (
    APPLY_MODE,
    EXIT_CODES,
    PLAN_MODE,
    ReleaseOutcome,
    ReleaseWorkflow,
)

__all__ = [
    "APPLY_MODE",
    "EXIT_CODES",
    "MANIFEST_VERSION",
    "PLAN_MODE",
    "REPORT_SCHEMA_VERSION",
    "SCHEMA_NAMES",
    "SPEC_VERSION",
    "ReleaseError",
    "ReleaseOutcome",
    "ReleaseRollbackError",
    "ReleaseSpec",
    "ReleaseWorkflow",
    "json_schema",
    "load_spec",
    "parse_spec",
    "release_id",
]
