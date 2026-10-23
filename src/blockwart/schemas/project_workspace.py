"""One closed contract shared by UI, REST and MCP project records."""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, field_validator, model_validator

from blockwart.domain.object_schema import is_safe_external_http_url
from blockwart.domain.provenance import parse_rfc3339_utc
from blockwart.domain.security import find_secret_violations
from blockwart.domain.timestamps import format_rfc3339_utc
from blockwart.schemas.catalog import CatalogObjectIn

RecordKind = Literal["item", "page", "access", "repository"]
ItemStatus = Literal["open", "in_progress", "blocked", "done", "deferred"]
ItemType = Literal[
    "task",
    "question",
    "blocker",
    "use_case",
    "requirement_group",
    "requirement",
    "decision",
    "evidence",
]


class RecordBase(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    title: str = Field(min_length=1, max_length=255)

    @model_validator(mode="after")
    def safe_metadata(self):
        if find_secret_violations(self.model_dump(mode="json")):
            raise ValueError("Secret-shaped content is not allowed; use a credential reference")
        return self


class RelationIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    relation: Literal[
        "implements",
        "applies_to",
        "depends_on",
        "precedes",
        "blocked_by",
        "supersedes",
        "informed_by",
        "documents",
        "evidence_for",
    ]
    target_id: str = Field(min_length=1, max_length=36)
    target_version: int | None = Field(default=None, ge=1)


class CriterionIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    id: str = Field(min_length=1, max_length=40, pattern=r"^[a-zA-Z0-9_-]+$")
    description: str = Field(min_length=1, max_length=1000)
    required: bool = True


class RequirementIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    original: str = Field(default="", max_length=4000)
    source_url: str | None = Field(default=None, max_length=2048)
    change_reason: str = Field(default="", max_length=2000)
    disposition: Literal["active", "superseded", "deferred", "waived"] = "active"

    @field_validator("source_url")
    @classmethod
    def safe_url(cls, value):
        return validated_url(value)


class EvidenceIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    requirement_id: str = Field(min_length=1, max_length=36)
    requirement_revision: int = Field(ge=1)
    criteria: list[str] = Field(min_length=1, max_length=50)
    outcome: Literal["pass", "fail", "inconclusive"]
    subject: str = Field(min_length=1, max_length=1000)
    scope: str = Field(min_length=1, max_length=2000)
    limitations: str = Field(default="", max_length=2000)
    source_url: str = Field(max_length=2048)
    observed_at: str

    @field_validator("source_url")
    @classmethod
    def safe_url(cls, value):
        return validated_url(value)

    @field_validator("observed_at")
    @classmethod
    def timestamp(cls, value):
        return normalized_time(value)


class GitHubReferenceIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    repository_id: str = Field(min_length=1, max_length=36)
    kind: Literal["issue", "pull", "commit"]
    number: int | None = Field(default=None, ge=1)
    sha: str | None = Field(default=None, pattern=r"^[0-9a-f]{40}$")

    @model_validator(mode="after")
    def identity(self):
        if self.kind == "commit":
            if not self.sha or self.number is not None:
                raise ValueError("A commit requires a full SHA and no number")
        elif self.number is None or self.sha is not None:
            raise ValueError("An issue or pull request requires a number and no SHA")
        return self


class LegacyOriginIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    field: Literal["open_questions", "blockers", "next_actions"]
    index: int = Field(ge=0)
    text: str = Field(min_length=1, max_length=4000)


class ProjectRepositoryIn(RecordBase):
    kind: Literal["repository"]
    owner: str = Field(min_length=1, max_length=100, pattern=r"^[a-zA-Z0-9_.-]+$")
    name: str = Field(min_length=1, max_length=100, pattern=r"^[a-zA-Z0-9_.-]+$")
    github_id: int | None = Field(default=None, ge=1)
    sync_enabled: bool = False
    credential_reference: str | None = Field(default=None, max_length=192)
    archived: bool = False


class ProjectItemIn(RecordBase):
    kind: Literal["item"]
    description: str = Field(default="", max_length=4000)
    item_type: ItemType = "task"
    status: ItemStatus = "open"
    assignee: str = Field(default="", max_length=255)
    due_at: str | None = None
    parent_id: str | None = Field(default=None, min_length=1, max_length=36)
    issue_url: str | None = Field(default=None, max_length=2048)
    related_objects: list[str] = Field(default_factory=list, max_length=50)
    relations: list[RelationIn] = Field(default_factory=list, max_length=100)
    priority: Literal["low", "normal", "high", "urgent"] = "normal"
    assignee_principal_id: str | None = Field(default=None, min_length=1, max_length=36)
    blocked_reason: str = Field(default="", max_length=2000)
    mandatory: bool = True
    archived: bool = False
    criteria: list[CriterionIn] = Field(default_factory=list, max_length=50)
    requirement: RequirementIn | None = None
    evidence: EvidenceIn | None = None
    github_references: list[GitHubReferenceIn] = Field(default_factory=list, max_length=50)
    status_authority: Literal["local", "github"] = "local"
    leading_reference: GitHubReferenceIn | None = None
    legacy_origin: LegacyOriginIn | None = None

    @model_validator(mode="after")
    def semantics(self):
        if len({c.id for c in self.criteria}) != len(self.criteria):
            raise ValueError("Criterion IDs must be unique")
        if (self.requirement or self.criteria) and self.item_type != "requirement":
            raise ValueError("Only requirements have requirement text or criteria")
        if bool(self.evidence) != (self.item_type == "evidence"):
            raise ValueError("Evidence records require structured evidence")
        refs = [r.model_dump_json() for r in self.github_references]
        if len(set(refs)) != len(refs):
            raise ValueError("Duplicate GitHub reference")
        links = [(r.relation, r.target_id) for r in self.relations]
        if len(set(links)) != len(links):
            raise ValueError("Duplicate relation")
        if self.status_authority == "github" and (
            not self.leading_reference
            or self.leading_reference.kind != "issue"
            or self.leading_reference.model_dump_json() not in refs
        ):
            raise ValueError("GitHub authority requires exactly one linked leading issue")
        return self

    @field_validator("due_at")
    @classmethod
    def timestamp(cls, value):
        return normalized_time(value)

    @field_validator("issue_url")
    @classmethod
    def safe_url(cls, value):
        return validated_url(value)


class ProjectPageIn(RecordBase):
    kind: Literal["page"]
    body: str = Field(default="", max_length=4000)
    review_after: str | None = None
    related_objects: list[str] = Field(default_factory=list, max_length=50)

    relations: list[RelationIn] = Field(default_factory=list, max_length=100)
    lifecycle: Literal["current", "historical", "superseded"] = "current"

    @field_validator("review_after")
    @classmethod
    def timestamp(cls, value):
        return normalized_time(value)


class ProjectAccessIn(RecordBase):
    kind: Literal["access"]
    url: str | None = Field(default=None, max_length=2048)
    purpose: str = Field(default="", max_length=2000)
    account: str = Field(default="", max_length=255)
    credential_reference: str | None = Field(default=None, max_length=192)
    new_credential_reference: CatalogObjectIn | None = Field(default=None, exclude=True)

    @field_validator("url")
    @classmethod
    def safe_url(cls, value):
        return validated_url(value)

    @model_validator(mode="after")
    def one_reference(self):
        if self.credential_reference and self.new_credential_reference:
            raise ValueError("Choose an existing or a new reference, not both")
        if (
            self.new_credential_reference
            and self.new_credential_reference.kind != "credential_reference"
        ):
            raise ValueError("Only credential_reference metadata can be created here")
        return self


ProjectRecordIn = Annotated[
    ProjectItemIn | ProjectPageIn | ProjectAccessIn | ProjectRepositoryIn,
    Field(discriminator="kind"),
]
RECORD_ADAPTER = TypeAdapter(ProjectRecordIn)


class ProjectRecordOut(BaseModel):
    id: str
    kind: RecordKind
    data: dict
    version: int
    created_at: str
    updated_at: str
    completed_at: str | None = None
    overdue: bool = False
    short_code: str = ""
    record_etag: str = ""
    requirement_revision: int = 1
    context: dict = Field(default_factory=dict)
    effective_status: ItemStatus | None = None


class ProjectRecordPageOut(BaseModel):
    items: list[ProjectRecordOut]
    next_cursor: str | None = None
    total: int


class ProjectRecordCommandOut(BaseModel):
    record: ProjectRecordOut
    revision: int
    etag: str
    replayed: bool = False


class ProjectRecordVersionOut(BaseModel):
    version: int
    data: dict
    author_id: str
    author_label: str
    origin: str
    created_at: str
    completed_at: str | None = None


class ProjectHistoryPageOut(BaseModel):
    items: list[ProjectRecordVersionOut]
    next_cursor: str | None = None
    total: int


class ProjectSearchHitOut(BaseModel):
    kind: str
    id: str
    title: str
    text: str


class ProjectSearchPageOut(BaseModel):
    items: list[ProjectSearchHitOut]
    next_cursor: str | None = None
    total: int


def normalized_time(value):
    if value is None:
        return None
    return format_rfc3339_utc(parse_rfc3339_utc(value))


def validated_url(value):
    if value is not None and not is_safe_external_http_url(value):
        raise ValueError("A safe HTTP(S) URL without credentials is required")
    return value


class ProjectActionIn(BaseModel):
    """Only explicitly supplied fields are changed. Null clears nullable fields only."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    action: Literal["patch", "comment", "assess", "reuse_evidence", "sync_github"]
    changes: dict = Field(default_factory=dict)
    body: str = Field(default="", max_length=4000)
    result: Literal["accepted", "exception", "rejected", "reopened"] | None = None
    reason: str = Field(default="", max_length=2000)
    evidence_ids: list[str] = Field(default_factory=list, max_length=100)

    @model_validator(mode="after")
    def valid_action(self):
        if find_secret_violations(self.model_dump(mode="json")):
            raise ValueError("Use credential references, not secret values")
        if self.action == "comment" and not self.body:
            raise ValueError("A comment body is required")
        if self.action == "assess" and (not self.result or not self.reason):
            raise ValueError("An assessment requires result and reason")
        if self.action == "reuse_evidence" and (not self.reason or not self.evidence_ids):
            raise ValueError("Reusing evidence requires references and reason")
        if self.action != "patch" and self.changes:
            raise ValueError("Changes are only allowed for patch actions")
        return self


class ProjectEventOut(BaseModel):
    id: str
    record_id: str
    kind: str
    data: dict
    author_id: str
    author_label: str
    origin: str
    created_at: str


class ProjectEventPageOut(BaseModel):
    items: list[ProjectEventOut]
    next_cursor: str | None = None
    total: int
