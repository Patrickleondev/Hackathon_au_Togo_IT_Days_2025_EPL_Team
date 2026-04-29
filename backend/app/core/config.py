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
    app_name: str = "RansomGuard"
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
    bootstrap_admin_email: str = "admin@ransomguard.local"
    bootstrap_admin_password: str = "change-me-on-first-login"

    # ─── Database ─────────────────────────────────────────────────────────
    database_url: str = "postgresql+psycopg://ransomguard:ransomguard@db:5432/ransomguard"

    # ─── Redis / queue ────────────────────────────────────────────────────
    redis_url: str = "redis://redis:6379/0"

    # ─── Storage ──────────────────────────────────────────────────────────
    storage_dir: str = "/var/lib/ransomguard"
    uploads_dir: str = "/var/lib/ransomguard/uploads"
    quarantine_dir: str = "/var/lib/ransomguard/quarantine"
    models_dir: str = "/var/lib/ransomguard/models"
    rules_dir: str = "/var/lib/ransomguard/rules"
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
