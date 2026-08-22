from pydantic import Field, model_validator
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
        le=3600,
        description="Absolute lifetime of an authenticated browser session.",
    )
    auth_remember_session_ttl_seconds: int = Field(
        default=2592000,
        ge=86400,
        le=7776000,
        description=(
            "Absolute lifetime of a browser session issued with the opt-in "
            "'keep me signed in' choice. Server-selected and never sliding."
        ),
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
    monitoring_poller_enabled: bool = Field(
        default=False,
        description="Whether this deployment may run built-in service health checks.",
    )
    monitoring_default_interval_seconds: int = Field(
        default=300,
        ge=60,
        le=86400,
        description="Server-wide check interval for services without an override.",
    )
    monitoring_allowed_target_networks: str = Field(
        default="",
        max_length=4096,
        description=(
            "Comma-separated IP networks a health check may connect to. Empty "
            "denies every target."
        ),
    )
    monitoring_allowed_target_ports: str = Field(
        default="80,443",
        max_length=1024,
        description="Comma-separated ports a health check may connect to.",
    )
    monitoring_connect_timeout_ms: int = Field(
        default=2000,
        ge=100,
        le=15000,
        description="Maximum time one health check may spend connecting.",
    )
    monitoring_total_timeout_ms: int = Field(
        default=5000,
        ge=200,
        le=30000,
        description="Maximum total time one health check may take.",
    )
    monitoring_max_response_bytes: int = Field(
        default=65536,
        ge=1024,
        le=1048576,
        description=(
            "Maximum declared response-body size accepted; the response body "
            "is never read or stored."
        ),
    )
    monitoring_max_checks_per_run: int = Field(
        default=20,
        ge=1,
        le=1000,
        description="Maximum due checks one scheduler run may claim.",
    )
    monitoring_max_concurrent_checks: int = Field(
        default=4,
        ge=1,
        le=32,
        description="Maximum health checks executed in parallel by one process.",
    )
    monitoring_lease_seconds: int = Field(
        default=60,
        ge=10,
        le=3600,
        description="Lifetime of one database-backed check lease.",
    )
    monitoring_jitter_seconds: int = Field(
        default=30,
        ge=0,
        le=3600,
        description="Maximum random delay added when a check is scheduled.",
    )
    monitoring_poll_interval_seconds: int = Field(
        default=5,
        ge=1,
        le=60,
        description="How often each web process looks for due database leases.",
    )

    @model_validator(mode="after")
    def validate_monitoring_time_bounds(self) -> "Settings":
        if self.monitoring_connect_timeout_ms > self.monitoring_total_timeout_ms:
            raise ValueError("monitoring connect timeout must not exceed total timeout")
        if self.monitoring_lease_seconds * 1000 <= self.monitoring_total_timeout_ms:
            raise ValueError("monitoring lease must exceed the total probe timeout")
        from blockwart.domain.monitoring_policy import (
            MonitoringPolicyError,
            parse_target_policy,
        )

        try:
            parse_target_policy(
                allowed_networks=self.monitoring_allowed_target_networks,
                allowed_ports=self.monitoring_allowed_target_ports,
            )
        except MonitoringPolicyError as exc:
            raise ValueError("monitoring target policy is invalid") from exc
        return self


def get_settings() -> Settings:
    return Settings()
