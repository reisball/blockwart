from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="BLOCKWART_", env_file=".env", extra="ignore")

    env: str = "dev"
    database_url: str = "sqlite:///./blockwart.sqlite3"
    secret_reference: str = Field(
        default="local-dev-placeholder",
        description="Reference label only; never a secret value.",
    )
    schema_overrides_path: str = Field(
        default="",
        description="Optional JSON file for UI schema metadata overrides.",
    )
    admin_token: SecretStr | None = Field(
        default=None,
        repr=False,
        description="Admin unlock secret. Empty or missing means read-only mode.",
    )
    admin_session_ttl_seconds: int = Field(
        default=3600,
        ge=300,
        le=86400,
        description="Lifetime of a signed UI admin session.",
    )
    admin_cookie_secure: bool = Field(
        default=False,
        description="Require HTTPS when sending the UI admin session cookie.",
    )

    @field_validator("admin_token", mode="before")
    @classmethod
    def normalize_empty_admin_token(cls, value: object) -> object:
        if isinstance(value, str) and not value:
            return None
        return value

    @field_validator("admin_token")
    @classmethod
    def require_strong_admin_token(cls, value: SecretStr | None) -> SecretStr | None:
        if value is not None and len(value.get_secret_value()) < 32:
            raise ValueError("BLOCKWART_ADMIN_TOKEN must contain at least 32 characters")
        return value


def get_settings() -> Settings:
    return Settings()
