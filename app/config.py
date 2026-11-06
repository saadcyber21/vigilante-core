from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "vigilante-core"
    environment: str = "development"
    database_url: str = "sqlite:///./vigilante.db"
    jwt_secret: str = "development-only-change-me"
    jwt_expire_minutes: int = 480
    admin_username: str = "admin"
    admin_password: str = "change-me"
    webhook_secret: str = "development-webhook-secret"
    max_payload_bytes: int = 1_048_576
    cors_origins: str = "http://localhost:5173"
    llm_enabled: bool = False
    llm_provider: str = "disabled"
    llm_base_url: str | None = None
    llm_api_key: str | None = None
    llm_model: str | None = None

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    @property
    def origins(self) -> list[str]:
        return [x.strip() for x in self.cors_origins.split(",") if x.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
