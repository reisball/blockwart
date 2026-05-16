from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="BLOCKWART_", env_file=".env", extra="ignore")

    env: str = "dev"
    database_url: str = "sqlite:///./blockwart.sqlite3"
    secret_reference: str = Field(
        default="local-dev-placeholder",
        description="Reference label only; never a secret value.",
    )


def get_settings() -> Settings:
    return Settings()

