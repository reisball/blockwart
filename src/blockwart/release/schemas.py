from __future__ import annotations

from typing import Any

from blockwart.release.manifest import manifest_json_schema
from blockwart.release.spec import (
    MANIFEST_VERSION,
    POINTER_SCHEMA_VERSION,
    REPORT_SCHEMA_VERSION,
    ReleaseSpec,
)

SCHEMA_NAMES = ("spec", "manifest", "report", "pointer", "status", "error")

_DIGEST = {"pattern": "^[0-9a-f]{64}$", "type": "string"}
_IMAGE_DIGEST = {"pattern": "^sha256:[0-9a-f]{64}$", "type": "string"}
_COMMIT = {"pattern": "^[0-9a-f]{40}$", "type": "string"}


def spec_json_schema() -> dict[str, Any]:
    """The versioned release specification contract."""
    schema = ReleaseSpec.model_json_schema()
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["title"] = "BlockwartReleaseSpecV1"
    schema.setdefault("allOf", []).append(
        {
            "if": {
                "properties": {
                    "image": {
                        "properties": {"mode": {"const": "existing"}},
                        "required": ["mode"],
                    }
                },
                "required": ["image"],
            },
            "then": {
                "properties": {
                    "image": {
                        "properties": {"digest": dict(_IMAGE_DIGEST)},
                        "required": ["digest"],
                    }
                }
            },
        }
    )
    return schema


def pointer_json_schema() -> dict[str, Any]:
    properties = {
        "schema_version": {"const": POINTER_SCHEMA_VERSION, "type": "integer"},
        "release_id": {"minLength": 1, "type": "string"},
        "generation": {"minimum": 1, "type": "integer"},
        "manifest_digest": dict(_DIGEST),
        "image_digest": dict(_IMAGE_DIGEST),
        "source_commit": dict(_COMMIT),
        "schema_revision": {"minLength": 1, "type": "string"},
        "runtime_layout_digest": dict(_DIGEST),
        "updated_at": {"minLength": 1, "type": "string"},
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "additionalProperties": False,
        "properties": properties,
        "required": sorted(properties),
        "title": "BlockwartReleasePointerV1",
        "type": "object",
    }


def report_json_schema() -> dict[str, Any]:
    """The stable machine-readable plan/completion/failure report."""
    pointer_summary = {
        "additionalProperties": False,
        "properties": {
            "release_id": {"type": "string"},
            "generation": {"type": "integer"},
            "manifest_digest": dict(_DIGEST),
            "image_digest": dict(_IMAGE_DIGEST),
            "source_commit": dict(_COMMIT),
            "schema_revision": {"type": "string"},
            "runtime_layout_digest": dict(_DIGEST),
        },
        "required": [
            "generation",
            "image_digest",
            "manifest_digest",
            "release_id",
            "schema_revision",
            "source_commit",
            "runtime_layout_digest",
        ],
        "type": "object",
    }
    properties = {
        "schema_version": {"const": REPORT_SCHEMA_VERSION, "type": "integer"},
        "manifest_version": {"const": MANIFEST_VERSION, "type": "integer"},
        "mode": {"enum": ["plan", "apply"], "type": "string"},
        "outcome": {
            "enum": ["planned", "succeeded", "failed", "rolled_back", "rollback_failed"],
            "type": "string",
        },
        "changed": {"type": "boolean"},
        "replayed": {"type": "boolean"},
        "release_id": {"minLength": 1, "type": "string"},
        "spec_digest": dict(_DIGEST),
        "source": {
            "type": ["object", "null"],
            "additionalProperties": False,
            "properties": {
                "commit": dict(_COMMIT),
                "tree": dict(_COMMIT),
                "clean": {"type": "boolean"},
            },
            "required": ["clean", "commit", "tree"],
        },
        "image": {
            "additionalProperties": False,
            "properties": {
                "repository": {"type": "string"},
                "tag": {"type": "string"},
                "digest": {"oneOf": [dict(_IMAGE_DIGEST), {"type": "null"}]},
            },
            "required": ["digest", "repository", "tag"],
            "type": "object",
        },
        "schema": {
            "additionalProperties": False,
            "properties": {
                "expected_revision": {"type": "string"},
                "packaged_revision": {"type": ["string", "null"]},
            },
            "required": ["expected_revision", "packaged_revision"],
            "type": "object",
        },
        "manifest_digest": {"oneOf": [dict(_DIGEST), {"type": "null"}]},
        "artifacts": {
            "items": {
                "additionalProperties": False,
                "properties": {"name": {"type": "string"}, "sha256": dict(_DIGEST)},
                "required": ["name", "sha256"],
                "type": "object",
            },
            "type": "array",
        },
        "backup": {
            "type": ["object", "null"],
            "additionalProperties": False,
            "properties": {
                "backup_file": {"type": "string"},
                "backup_sha256": dict(_DIGEST),
                "receipt_sha256": dict(_DIGEST),
                "size_bytes": {"minimum": 0, "type": "integer"},
            },
            "required": ["backup_file", "backup_sha256", "receipt_sha256", "size_bytes"],
        },
        "gates": {
            "items": {
                "additionalProperties": False,
                "properties": {
                    "name": {"minLength": 1, "type": "string"},
                    "status": {
                        "enum": ["passed", "failed", "skipped", "planned"],
                        "type": "string",
                    },
                    "code": {"type": ["string", "null"]},
                },
                "required": ["code", "name", "status"],
                "type": "object",
            },
            "type": "array",
        },
        "pointers": {
            "additionalProperties": False,
            "properties": {
                "current": {"oneOf": [pointer_summary, {"type": "null"}]},
                "previous": {"oneOf": [pointer_summary, {"type": "null"}]},
            },
            "required": ["current", "previous"],
            "type": "object",
        },
        "retention": {
            "oneOf": [
                {
                    "additionalProperties": False,
                    "properties": {
                        "retained": {"minimum": 0, "type": "integer"},
                        "removed": {"items": {"type": "string"}, "type": "array"},
                        "backup_directories_removed": {
                            "items": {"type": "string"},
                            "type": "array",
                        },
                        "image_references_removed": {
                            "items": {"type": "string"},
                            "type": "array",
                        },
                    },
                    "required": [
                        "backup_directories_removed",
                        "image_references_removed",
                        "removed",
                        "retained",
                    ],
                    "type": "object",
                },
                {"type": "null"},
            ]
        },
        "hooks": {
            "items": {
                "additionalProperties": False,
                "properties": {
                    "name": {"type": "string"},
                    "status": {"enum": ["passed", "failed"], "type": "string"},
                    "code": {"type": ["string", "null"]},
                },
                "required": ["code", "name", "status"],
                "type": "object",
            },
            "type": "array",
        },
        "rollback": {
            "oneOf": [
                {
                    "additionalProperties": False,
                    "properties": {
                        "triggered_by": {
                            "additionalProperties": False,
                            "properties": {
                                "gate": {"type": "string"},
                                "code": {"type": "string"},
                            },
                            "required": ["code", "gate"],
                            "type": "object",
                        },
                        "previous_release_id": {"type": ["string", "null"]},
                        "previous_image_digest": {
                            "oneOf": [dict(_IMAGE_DIGEST), {"type": "null"}]
                        },
                        "restored_backup_sha256": {
                            "oneOf": [dict(_DIGEST), {"type": "null"}]
                        },
                        "database_restored": {"type": "boolean"},
                        "failed_database_preserved": {"type": "boolean"},
                        "pointers_restored": {"type": "boolean"},
                        "service_restored": {"type": "boolean"},
                        "service_contained": {"type": "boolean"},
                        "readiness_revision": {"type": ["string", "null"]},
                        "containment_error": {
                            "additionalProperties": False,
                            "properties": {
                                "gate": {"const": "rollback_containment", "type": "string"},
                                "code": {"type": "string"},
                            },
                            "required": ["code", "gate"],
                            "type": "object",
                        },
                        "rollback_error": {
                            "additionalProperties": False,
                            "properties": {
                                "gate": {"type": "string"},
                                "code": {"type": "string"},
                            },
                            "required": ["code", "gate"],
                            "type": "object",
                        },
                        "original_error": {"type": "string"},
                    },
                    "required": [
                        "database_restored",
                        "failed_database_preserved",
                        "pointers_restored",
                        "previous_image_digest",
                        "previous_release_id",
                        "restored_backup_sha256",
                        "service_contained",
                        "triggered_by",
                    ],
                    "type": "object",
                },
                {"type": "null"},
            ]
        },
        "diagnostics": {
            "items": {
                "additionalProperties": False,
                "properties": {"gate": {"type": "string"}, "code": {"type": "string"}},
                "required": ["code", "gate"],
                "type": "object",
            },
            "type": "array",
        },
        "error": {"type": ["string", "null"]},
        "started_at": {"minLength": 1, "type": "string"},
        "finished_at": {"minLength": 1, "type": "string"},
        "report_digest": dict(_DIGEST),
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "additionalProperties": False,
        "properties": properties,
        "required": sorted(properties),
        "title": "BlockwartReleaseReportV1",
        "type": "object",
    }


def status_json_schema() -> dict[str, Any]:
    pointer = pointer_json_schema()
    pointer_summary = {
        **pointer,
        "properties": {
            key: value
            for key, value in pointer["properties"].items()
            if key not in {"schema_version", "updated_at"}
        },
    }
    pointer_summary["required"] = sorted(pointer_summary["properties"])
    history_entry = {
        "additionalProperties": False,
        "properties": {
            "generation": {"type": ["integer", "null"]},
            "release_id": {"type": ["string", "null"]},
            "outcome": {"type": ["string", "null"]},
        },
        "required": ["generation", "outcome", "release_id"],
        "type": "object",
    }
    properties = {
        "schema_version": {"const": REPORT_SCHEMA_VERSION, "type": "integer"},
        "mode": {"const": "status", "type": "string"},
        "release_id": {"type": "string"},
        "current": {"oneOf": [pointer_summary, {"type": "null"}]},
        "previous": {"oneOf": [pointer_summary, {"type": "null"}]},
        "history": {"items": history_entry, "type": "array"},
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "additionalProperties": False,
        "properties": properties,
        "required": sorted(properties),
        "title": "BlockwartReleaseStatusV1",
        "type": "object",
    }


def error_json_schema() -> dict[str, Any]:
    properties = {
        "schema_version": {"const": REPORT_SCHEMA_VERSION, "type": "integer"},
        "mode": {"const": "error", "type": "string"},
        "outcome": {"const": "failed", "type": "string"},
        "error": {"minLength": 1, "type": "string"},
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "additionalProperties": False,
        "properties": properties,
        "required": sorted(properties),
        "title": "BlockwartReleaseErrorV1",
        "type": "object",
    }


def json_schema(name: str) -> dict[str, Any]:
    builders = {
        "spec": spec_json_schema,
        "manifest": manifest_json_schema,
        "report": report_json_schema,
        "pointer": pointer_json_schema,
        "status": status_json_schema,
        "error": error_json_schema,
    }
    return builders[name]()
