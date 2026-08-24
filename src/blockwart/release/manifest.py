from __future__ import annotations

from typing import Any

from blockwart.release.canonical import (
    canonical_json_bytes,
    is_image_digest,
    json_artifact_digest,
    require_secret_free,
)
from blockwart.release.errors import ReleaseError
from blockwart.release.source import SourceEvidence
from blockwart.release.spec import (
    MANIFEST_VERSION,
    ReleaseSpec,
    contract_digest,
    public_contract_payload,
)
from blockwart.release.spec import (
    release_id as compute_release_id,
)

ARTIFACT_NAMES = ("build", "contract", "source")


def build_artifacts(
    spec: ReleaseSpec,
    *,
    source: SourceEvidence,
    image_tag: str,
) -> dict[str, dict[str, Any]]:
    """Deterministic, secret-free bundle artifacts.

    Artifacts never carry an environment value, database content, bind/private
    endpoint, credential, hook, or host path.  Host runtime configuration stays
    outside the immutable release store.
    """
    build = {
        "mode": spec.image.mode,
        "runtime": spec.image.runtime,
        "containerfile": spec.image.containerfile,
        "build_revision": source.commit,
        "image_repository": spec.image.repository,
        "image_tag": image_tag,
    }
    artifacts = {
        "build": build,
        "contract": public_contract_payload(spec),
        "source": dict(source.summary()),
    }
    for payload in artifacts.values():
        require_secret_free(payload, code="unsafe_manifest_content")
    return artifacts


def build_manifest(
    spec: ReleaseSpec,
    *,
    source: SourceEvidence,
    image_digest: str,
    packaged_schema_revision: str,
    artifacts: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Build the canonical manifest binding source, image, schema, and artifacts.

    The manifest is a pure function of its inputs, so replaying the same
    specification produces byte-identical bundle content.
    """
    if not is_image_digest(image_digest):
        raise ReleaseError("invalid_image_digest", gate="bundle_written")
    if set(artifacts) != set(ARTIFACT_NAMES):
        raise ReleaseError("invalid_bundle_artifacts", gate="bundle_written")
    manifest = {
        "manifest_version": MANIFEST_VERSION,
        "release_id": compute_release_id(spec),
        "contract_digest": contract_digest(spec),
        "source": dict(source.summary()),
        "image": {
            "repository": spec.image.repository,
            "tag": artifacts["build"]["image_tag"],
            "digest": image_digest,
            "runtime": spec.image.runtime,
            "mode": spec.image.mode,
            "build_revision": source.commit,
        },
        "schema": {
            "expected_revision": spec.expected_schema_revision,
            "packaged_revision": packaged_schema_revision,
        },
        "artifacts": [
            {"name": name, "sha256": json_artifact_digest(artifacts[name])}
            for name in ARTIFACT_NAMES
        ],
    }
    require_secret_free(manifest, code="unsafe_manifest_content")
    canonical_json_bytes(manifest)
    return manifest


def manifest_json_schema() -> dict[str, Any]:
    digest = {"pattern": "^[0-9a-f]{64}$", "type": "string"}
    properties = {
        "manifest_version": {"const": MANIFEST_VERSION, "type": "integer"},
        "release_id": {"minLength": 1, "type": "string"},
        "contract_digest": digest,
        "source": {
            "additionalProperties": False,
            "properties": {
                "commit": {"pattern": "^[0-9a-f]{40}$", "type": "string"},
                "tree": {"pattern": "^[0-9a-f]{40}$", "type": "string"},
                "clean": {"const": True, "type": "boolean"},
            },
            "required": ["clean", "commit", "tree"],
            "type": "object",
        },
        "image": {
            "additionalProperties": False,
            "properties": {
                "repository": {"minLength": 1, "type": "string"},
                "tag": {"minLength": 1, "type": "string"},
                "digest": {"pattern": "^sha256:[0-9a-f]{64}$", "type": "string"},
                "runtime": {"enum": ["docker", "podman"], "type": "string"},
                "mode": {"enum": ["build", "existing"], "type": "string"},
                "build_revision": {"pattern": "^[0-9a-f]{40}$", "type": "string"},
            },
            "required": ["build_revision", "digest", "mode", "repository", "runtime", "tag"],
            "type": "object",
        },
        "schema": {
            "additionalProperties": False,
            "properties": {
                "expected_revision": {"minLength": 1, "type": "string"},
                "packaged_revision": {"minLength": 1, "type": "string"},
            },
            "required": ["expected_revision", "packaged_revision"],
            "type": "object",
        },
        "artifacts": {
            "items": {
                "additionalProperties": False,
                "properties": {
                    "name": {"enum": list(ARTIFACT_NAMES), "type": "string"},
                    "sha256": digest,
                },
                "required": ["name", "sha256"],
                "type": "object",
            },
            "maxItems": len(ARTIFACT_NAMES),
            "minItems": len(ARTIFACT_NAMES),
            "type": "array",
        },
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "additionalProperties": False,
        "properties": properties,
        "required": sorted(properties),
        "title": "BlockwartReleaseManifestV1",
        "type": "object",
    }
