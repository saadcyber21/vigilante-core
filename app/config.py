from functools import lru_cache
import re
from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "vigilante-core"
    environment: str = "development"
    database_url: str = "sqlite:///./vigilante.db"
    tenant_id: str = Field(default="default", min_length=1, max_length=120)
    jwt_secret: str = "development-only-change-me"
    jwt_expire_minutes: int = Field(default=480, ge=5, le=1440)
    admin_username: str = "admin"
    admin_password: str = "change-me"
    webhook_secret: str = "development-webhook-secret"
    webhook_source_secrets: dict[str, str] = Field(default_factory=dict)
    max_payload_bytes: int = Field(default=1_048_576, ge=1024, le=10_485_760)
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

    def webhook_secret_for(self, source_key: str) -> str | None:
        if self.webhook_source_secrets:
            return self.webhook_source_secrets.get(source_key)
        return self.webhook_secret

    @model_validator(mode="after")
    def validate_production_security(self):
        if self.environment.strip().lower() not in {"production", "prod"}:
            return self

        def unsafe_secret(value: str, minimum_length: int = 32) -> bool:
            normalized = value.strip().lower()
            return (
                len(value.strip()) < minimum_length
                or normalized.startswith(("replace-", "change-", "development-", "example-"))
                or normalized in {"admin", "password", "secret", "changeme"}
            )

        problems = []
        if unsafe_secret(self.jwt_secret):
            problems.append("JWT_SECRET must be a unique random value of at least 32 characters")
        if len(self.admin_password) < 16 or self.admin_password.strip().lower().startswith(("replace-", "change-", "example-")):
            problems.append("ADMIN_PASSWORD must be a unique value of at least 16 characters")

        webhook_values = self.webhook_source_secrets.values() if self.webhook_source_secrets else [self.webhook_secret]
        if not webhook_values or any(unsafe_secret(value) for value in webhook_values):
            problems.append("Configure WEBHOOK_SECRET or WEBHOOK_SOURCE_SECRETS with random values of at least 32 characters")
        if any(not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,119}", source) for source in self.webhook_source_secrets):
            problems.append("Webhook source names may contain only letters, numbers, dots, underscores, and hyphens")

        if problems:
            raise ValueError("Unsafe production configuration: " + "; ".join(problems))
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
