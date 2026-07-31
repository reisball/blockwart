from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="BLOCKWART_", env_file=".env", extra="ignore")

    env: str = "dev"
    build_revision: str = Field(
        default="unknown",
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9._+-]+$",
        description="Build or Git revision exposed by health endpoints.",
    )
    database_url: str = "sqlite:///./blockwart.sqlite3"
    sqlite_busy_timeout_ms: int = Field(
        default=5000,
        ge=100,
        le=60000,
        description="Maximum SQLite lock wait in milliseconds.",
    )
    sqlite_wal_enabled: bool = Field(
        default=True,
        description="Enable WAL journal mode for persistent SQLite databases.",
    )
    secret_reference: str = Field(
        default="local-dev-placeholder",
        description="Reference label only; never a secret value.",
    )
    schema_overrides_path: str = Field(
        default="",
        description="Optional JSON file for UI schema metadata overrides.",
    )
    auth_session_ttl_seconds: int = Field(
        default=3600,
        ge=300,
        le=86400,
        description="Absolute lifetime of an authenticated browser session.",
    )
    auth_login_challenge_ttl_seconds: int = Field(
        default=600,
        ge=60,
        le=3600,
        description="Lifetime of a one-time pre-authentication CSRF challenge.",
    )
    auth_login_rate_window_seconds: int = Field(
        default=60,
        ge=10,
        le=3600,
        description="Fixed window for per-process login and challenge throttles.",
    )
    auth_login_source_attempt_limit: int = Field(
        default=10,
        ge=1,
        le=1000,
        description="Password attempts accepted per source and rate window.",
    )
    auth_login_account_attempt_limit: int = Field(
        default=5,
        ge=1,
        le=1000,
        description="Password attempts accepted per account fingerprint and rate window.",
    )
    auth_login_global_attempt_limit: int = Field(
        default=60,
        ge=1,
        le=10000,
        description="Password attempts accepted by one app process and rate window.",
    )
    auth_login_source_challenge_limit: int = Field(
        default=30,
        ge=1,
        le=10000,
        description="Login challenges issued per source and rate window.",
    )
    auth_login_global_challenge_limit: int = Field(
        default=120,
        ge=1,
        le=100000,
        description="Login challenges issued by one app process and rate window.",
    )
    auth_password_max_concurrency: int = Field(
        default=2,
        ge=1,
        le=16,
        description="Maximum concurrent Argon2 password checks per app process.",
    )
    auth_security_event_retention_days: int = Field(
        default=90,
        ge=1,
        le=3650,
        description="Maximum age of retained security events.",
    )
    auth_security_event_max_rows: int = Field(
        default=100000,
        ge=1000,
        le=10000000,
        description="Maximum retained security-event rows after periodic pruning.",
    )
    auth_service_token_rate_window_seconds: int = Field(
        default=60,
        ge=10,
        le=3600,
        description="Shared fixed window for failed service-token authentication.",
    )
    auth_service_token_global_failure_limit: int = Field(
        default=300,
        ge=1,
        le=100000,
        description="Failed service-token attempts accepted globally per window.",
    )
    auth_service_token_source_failure_limit: int = Field(
        default=30,
        ge=1,
        le=10000,
        description="Failed service-token attempts accepted per source per window.",
    )
    auth_service_token_fingerprint_failure_limit: int = Field(
        default=10,
        ge=1,
        le=1000,
        description="Failed attempts accepted per opaque-token fingerprint per window.",
    )
    auth_service_token_failure_bucket_max_rows: int = Field(
        default=10000,
        ge=100,
        le=1000000,
        description="Maximum retained shared service-token failure buckets.",
    )
    auth_service_token_failure_bucket_prune_interval_seconds: int = Field(
        default=60,
        ge=10,
        le=3600,
        description="Amortized request-path interval for pruning failure buckets.",
    )
    auth_trusted_proxy_cidrs: str = Field(
        default="",
        max_length=4096,
        description="Comma-separated proxy IP networks trusted to supply one forwarded source.",
    )
    idempotency_ttl_seconds: int = Field(
        default=86400,
        ge=300,
        le=604800,
        description="Retention and replay window for create-command idempotency keys.",
    )

def get_settings() -> Settings:
    return Settings()
