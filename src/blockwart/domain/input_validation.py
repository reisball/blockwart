"""Structured, value-free diagnostics for shared request validators.

Rules describe input-only constraints, never stored or concealed catalog state.
Paths are relative to the validating model; Pydantic adds the enclosing location.
"""

from types import MappingProxyType

from pydantic import ValidationError

INPUT_RULES = MappingProxyType(
    {
        "secret_content": (
            "forbidden_key",
            "A forbidden secret-shaped key or raw secret value was found.",
        ),
        "acl_metadata": (
            "field_not_allowed",
            "Catalog access control belongs to the object grant API.",
        ),
        "asset_state_kind": (
            "field_not_allowed",
            "Lifecycle and health are only valid for asset kinds.",
        ),
        "placement_kind": (
            "field_not_allowed",
            "Placement metadata is supported only for system and service objects.",
        ),
        "placement_object": ("type_mismatch", "Placement metadata must be an object."),
        "placement_state": ("value_not_allowed", "Explicit placement state must be unassigned."),
        "placement_reason": ("value_too_short", "Placement reason must be a non-empty string."),
        "placement_reason_type": ("type_mismatch", "Placement reason must be a string."),
        "timestamp_rfc3339": (
            "invalid_format",
            "A timestamp with an explicit UTC offset is required.",
        ),
        "safe_http_url": ("invalid_format", "A safe HTTP(S) URL without credentials is required."),
        "github_reference_identity": (
            "rule_violation",
            "Commits require SHA only; issues/pulls require number only.",
        ),
        "unique_criterion_ids": ("rule_violation", "Criterion IDs must be unique."),
        "requirement_fields": (
            "rule_violation",
            "Only requirement items may carry requirement text or criteria.",
        ),
        "evidence_fields": (
            "rule_violation",
            "Evidence items require structured evidence, other items forbid it.",
        ),
        "unique_github_references": ("rule_violation", "GitHub references must be unique."),
        "unique_relations": ("rule_violation", "Relation and target pairs must be unique."),
        "github_status_authority": (
            "rule_violation",
            "GitHub status authority requires a linked leading issue.",
        ),
        "one_credential_reference": (
            "rule_violation",
            "Choose an existing or new credential reference, not both.",
        ),
        "credential_reference_kind": (
            "value_not_allowed",
            "New access metadata must be a credential reference.",
        ),
        "comment_body": ("required_field_missing", "A comment body is required."),
        "assessment_fields": ("rule_violation", "An assessment requires result and reason."),
        "evidence_reuse_fields": (
            "rule_violation",
            "Evidence reuse requires references and reason.",
        ),
        "patch_changes": ("field_not_allowed", "Changes are allowed only for patch actions."),
    }
)


class InputRuleError(ValueError):
    """One allowlisted rule; no submitted value or arbitrary exception text."""

    def __init__(self, rule: str, path: tuple[str | int, ...] = ()) -> None:
        self.rule = rule
        self.path = path
        super().__init__(INPUT_RULES.get(rule, (None, "Input validation failed"))[1])


def reject_input(title: str, violations: list[tuple[tuple[str | int, ...], str]]) -> None:
    """Keep independent violations and relative locations through nested models."""
    if violations:
        raise ValidationError.from_exception_data(
            title,
            [
                {
                    "type": "value_error",
                    "loc": path,
                    "input": None,
                    "ctx": {"error": InputRuleError(rule, path)},
                }
                for path, rule in violations
            ],
        )
