"""Application configuration loaded from environment variables."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Centralized typed settings (12-factor)."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ─── App ──────────────────────────────────────────────────────────────
    app_name: str = "GuardIAn"
    app_env: Literal["dev", "prod", "test"] = "dev"
    app_version: str = "2.0.0"
    api_prefix: str = "/api"

    # ─── Server ───────────────────────────────────────────────────────────
    host: str = "0.0.0.0"
    port: int = 8000

    # ─── CORS ─────────────────────────────────────────────────────────────
    cors_origins: list[str] = Field(
        default_factory=lambda: [
            "http://localhost:5173",
            "http://localhost:3000",
            "http://127.0.0.1:5173",
        ]
    )

    # ─── Security ─────────────────────────────────────────────────────────
    secret_key: str = "change-me-in-prod-please-use-openssl-rand-hex-32"
    jwt_algorithm: str = "HS256"
    jwt_access_ttl_minutes: int = 60
    jwt_agent_ttl_days: int = 30
    bootstrap_admin_email: str = "admin@guardian.local"
    bootstrap_admin_password: str = "change-me-on-first-login"

    # ─── Database ─────────────────────────────────────────────────────────
    database_url: str = "postgresql+psycopg://guardian:guardian@db:5432/guardian"

    # ─── Redis / queue ────────────────────────────────────────────────────
    redis_url: str = "redis://redis:6379/0"

    # ─── Storage ──────────────────────────────────────────────────────────
    storage_dir: str = "/var/lib/guardian"
    uploads_dir: str = "/var/lib/guardian/uploads"
    quarantine_dir: str = "/var/lib/guardian/quarantine"
    models_dir: str = "/var/lib/guardian/models"
    rules_dir: str = "/var/lib/guardian/rules"
    max_upload_mb: int = 100

    # ─── Detector thresholds ──────────────────────────────────────────────
    threshold_low: float = 0.40
    threshold_medium: float = 0.65
    threshold_high: float = 0.85

    # ─── Logging ──────────────────────────────────────────────────────────
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"


@lru_cache
def get_settings() -> Settings:
    """Cached settings instance."""
    return Settings()


settings = get_settings()
