"""Canonical, bounded, redacted projection of one proposed object update.

This module is pure: it never reads a session, a request, or a clock. It turns
two already redacted object snapshots into the closed public preview diff, and
turns the published safe preview contract into one stable, versioned,
domain-separated digest.

The digest deliberately covers exactly the safe published contract and nothing
else. Two proposals that differ only inside a redacted value therefore share a
digest, so the digest can never be used as an oracle over a concealed or
secret-shaped value.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal

from blockwart.domain.security import REDACTED_SECRET_VALUE

# Bump deliberately when the safe preview contract itself changes shape.
PREVIEW_CONTRACT_VERSION = "1"
# Domain separator for the preview digest. NUL bytes cannot occur in the
# ASCII-escaped canonical JSON body, so the prefix cannot be forged from
# content.
PREVIEW_DIGEST_DOMAIN = "blockwart/object-update-preview"
PREVIEW_DIFF_DIGEST_DOMAIN = "blockwart/object-update-preview/diff"
PREVIEW_DIGEST_PREFIX = "sha256:"

# Bounds of the published diff. A proposal that changes more paths than this is
# reported as truncated rather than as an unbounded document.
PREVIEW_DIFF_MAX_ENTRIES = 200
PREVIEW_DIFF_PATH_MAX_LENGTH = 512
PREVIEW_DIFF_VALUE_MAX_LENGTH = 120

PreviewValueState = Literal["absent", "value", "redacted", "truncated"]
PreviewValueType = Literal[
    "absent",
    "null",
    "boolean",
    "integer",
    "number",
    "string",
    "array",
    "object",
]
PreviewOperation = Literal["added", "removed", "changed"]
PreviewPathState = Literal["exact", "hashed"]

_ABSENT = object()
# Concealed typed references use a distinct internal marker. Neither marker is
# serialized: both become the same closed ``redacted`` value state.
REDACTED_PREVIEW_VALUE = "[redacted-preview-value]"


@dataclass(frozen=True, slots=True)
class PreviewValue:
    """One side of a diff entry in the closed published value representation."""

    state: PreviewValueState
    type: PreviewValueType
    text: str | None
    semantic_text: str | None

    def as_json(self) -> dict[str, object]:
        return {"state": self.state, "type": self.type, "text": self.text}


@dataclass(frozen=True, slots=True)
class PreviewDiffEntry:
    path: str
    path_state: PreviewPathState
    operation: PreviewOperation
    before: PreviewValue
    after: PreviewValue
    semantic_path: str

    def as_json(self) -> dict[str, object]:
        return {
            "path": self.path,
            "path_state": self.path_state,
            "operation": self.operation,
            "before": self.before.as_json(),
            "after": self.after.as_json(),
        }


def preview_diff(
    before: Mapping[str, object],
    after: Mapping[str, object],
) -> tuple[list[PreviewDiffEntry], bool, str]:
    """Project two redacted snapshots onto the canonical bounded diff.

    Both inputs must already have passed the shared secret redaction. Paths are
    RFC 6901 JSON Pointers, mappings are walked into leaf paths, and every other
    value is compared whole. The result is sorted by path and truncated to the
    published bound.
    """
    entries = sorted(
        _walk(before, after, ""),
        key=lambda entry: entry.semantic_path,
    )
    truncated = len(entries) > PREVIEW_DIFF_MAX_ENTRIES
    return (
        entries[:PREVIEW_DIFF_MAX_ENTRIES],
        truncated,
        _complete_diff_digest(entries),
    )


def _walk(
    before: Mapping[str, object],
    after: Mapping[str, object],
    path: str,
) -> list[PreviewDiffEntry]:
    entries: list[PreviewDiffEntry] = []
    for key in sorted({str(key) for key in before} | {str(key) for key in after}):
        field = f"{path}/{_pointer_segment(key)}"
        old_value = before.get(key, _ABSENT)
        new_value = after.get(key, _ABSENT)
        if old_value is not _ABSENT and new_value is not _ABSENT and old_value == new_value:
            continue
        if isinstance(old_value, Mapping) and (
            isinstance(new_value, Mapping) or new_value is _ABSENT
        ) and (old_value or isinstance(new_value, Mapping) and new_value):
            entries.extend(
                _walk(
                    old_value,
                    new_value if isinstance(new_value, Mapping) else {},
                    field,
                )
            )
            continue
        if (
            old_value is _ABSENT
            and isinstance(new_value, Mapping)
            and new_value
        ):
            entries.extend(_walk({}, new_value, field))
            continue
        published_path, path_state = _published_path(field)
        entries.append(
            PreviewDiffEntry(
                path=published_path,
                path_state=path_state,
                operation=_operation(old_value, new_value),
                before=preview_value(old_value),
                after=preview_value(new_value),
                semantic_path=field,
            )
        )
    return entries


def _pointer_segment(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _published_path(value: str) -> tuple[str, PreviewPathState]:
    if len(value) <= PREVIEW_DIFF_PATH_MAX_LENGTH:
        return value, "exact"
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return f"/@sha256:{digest}", "hashed"


def _operation(before: object, after: object) -> PreviewOperation:
    if before is _ABSENT:
        return "added"
    if after is _ABSENT:
        return "removed"
    return "changed"


def preview_value(value: object) -> PreviewValue:
    """Render one already redacted value in the closed bounded representation."""
    if value is _ABSENT:
        return PreviewValue(
            state="absent",
            type="absent",
            text=None,
            semantic_text=None,
        )
    value_type = _value_type(value)
    if _contains_redaction(value):
        return PreviewValue(
            state="redacted",
            type=value_type,
            text=None,
            semantic_text=None,
        )
    rendered = value if isinstance(value, str) else _canonical_json(value)
    if len(rendered) > PREVIEW_DIFF_VALUE_MAX_LENGTH:
        return PreviewValue(
            state="truncated",
            type=value_type,
            text=rendered[:PREVIEW_DIFF_VALUE_MAX_LENGTH],
            semantic_text=rendered,
        )
    return PreviewValue(
        state="value",
        type=value_type,
        text=rendered,
        semantic_text=rendered,
    )


def _value_type(value: object) -> PreviewValueType:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, Mapping):
        return "object"
    if isinstance(value, list | tuple):
        return "array"
    return "string"


def _contains_redaction(value: object) -> bool:
    """Whether the shared redaction replaced anything inside this value."""
    if isinstance(value, str):
        return value in {REDACTED_SECRET_VALUE, REDACTED_PREVIEW_VALUE}
    if isinstance(value, Mapping):
        return any(_contains_redaction(item) for item in value.values())
    if isinstance(value, list | tuple):
        return any(_contains_redaction(item) for item in value)
    return False


def preview_digest(body: Mapping[str, object]) -> str:
    """Hash the safe published preview contract under its own domain and version."""
    material = (
        PREVIEW_DIGEST_DOMAIN.encode("ascii")
        + b"\x00"
        + PREVIEW_CONTRACT_VERSION.encode("ascii")
        + b"\x00"
        + _canonical_json(body).encode("ascii")
    )
    return PREVIEW_DIGEST_PREFIX + hashlib.sha256(material).hexdigest()


def _complete_diff_digest(entries: list[PreviewDiffEntry]) -> str:
    """Fingerprint every safe semantic change, including omitted diff entries.

    The public diff truncates long values and caps its entry count. This second
    domain-separated digest is computed from the complete closed diff after
    secret and concealment redaction, so changing a safe suffix or an omitted
    path still changes the top-level preview digest. Deliberately redacted
    values all collapse to one marker and cannot become a digest oracle.
    """
    complete = [_semantic_entry(entry) for entry in entries]
    material = (
        PREVIEW_DIFF_DIGEST_DOMAIN.encode("ascii")
        + b"\x00"
        + PREVIEW_CONTRACT_VERSION.encode("ascii")
        + b"\x00"
        + _canonical_json(complete).encode("ascii")
    )
    return PREVIEW_DIGEST_PREFIX + hashlib.sha256(material).hexdigest()


def _semantic_entry(entry: PreviewDiffEntry) -> dict[str, object]:
    return {
        "path": entry.semantic_path,
        "operation": entry.operation,
        "before": _semantic_value(entry.before),
        "after": _semantic_value(entry.after),
    }


def _semantic_value(value: PreviewValue) -> dict[str, object]:
    return {
        "state": value.state,
        "type": value.type,
        "text": value.semantic_text,
    }


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
        default=str,
    )
