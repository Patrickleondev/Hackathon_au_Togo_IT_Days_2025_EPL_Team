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
    # SECRET_KEY and BOOTSTRAP_ADMIN_PASSWORD MUST be supplied via env vars.
    # Empty defaults are intentional so misconfiguration is caught at startup
    # (see app.main lifespan) and so no plausible-looking value is committed.
    secret_key: str = ""
    jwt_algorithm: str = "HS256"
    jwt_access_ttl_minutes: int = 60
    jwt_agent_ttl_days: int = 30
    bootstrap_admin_email: str = "admin@guardian.local"
    bootstrap_admin_password: str = ""
    # Pre-shared secret required by /agents/enroll. If empty/None, enrollment is rejected
    # in non-dev environments. In dev it falls back to allowing enrollment with a warning.
    agent_enrollment_secret: str | None = None

    # ─── Database ───────────────────────────────────────────────────────────
    # Must be supplied via DATABASE_URL env var. The default below is a placeholder
    # that will FAIL to connect, on purpose, so that misconfiguration is caught early.
    database_url: str = "postgresql+psycopg://CHANGE_ME@db:5432/CHANGE_ME"

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
    # ─── Detector internals (tunable) ──────────────────────────────────────────
    # Bytes read from a file when computing entropy / signature features.
    feature_max_read_bytes: int = 4 * 1024 * 1024  # 4 MiB
    # Block size used by the chunked entropy estimator.
    feature_entropy_block_bytes: int = 64 * 1024  # 64 KiB
    # Shannon-entropy threshold above which a payload is considered "high-entropy".
    feature_entropy_threshold: float = 7.5

    # ─── Scans ────────────────────────────────────────────────────────────────
    # Hard cap on the number of files inspected during a single directory scan.
    scan_max_files: int = 5000

    # ─── Threat Intelligence (auto-update from external feeds) ─────────────────
    # Master kill-switch. If False, no outbound calls to feeds are made.
    intel_enabled: bool = True
    # How often the scheduler refreshes each feed (hours).
    intel_update_interval_hours: int = 6
    # Per-feed enable flags (let ops disable a misbehaving feed without redeploy).
    intel_malware_bazaar_enabled: bool = True
    intel_urlhaus_enabled: bool = True
    intel_threatfox_enabled: bool = True
    intel_feodo_enabled: bool = True
    intel_yaraify_enabled: bool = True
    intel_abuseipdb_enabled: bool = False  # off by default, requires key
    intel_otx_enabled: bool = False  # off by default, requires key
    # API credentials. abuse.ch requires a free Auth-Key since 2024.
    abuse_ch_auth_key: str = ""
    abuseipdb_api_key: str = ""
    otx_api_key: str = ""
    # HTTP behaviour for feed fetches.
    intel_http_timeout_seconds: float = 30.0
    intel_http_max_retries: int = 3
    # Retention: drop indicators older than N days at each refresh.
    intel_retention_days: int = 90
    # Per-feed soft cap to avoid blowing up the DB on huge feeds.
    intel_max_rows_per_feed: int = 250_000

    # ─── Logging ──────────────────────────────────────────────────────────
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    # ─── Assistant / chatbot (LLM bridge) ─────────────────────────────────
    # Provider for the public /api/chat endpoint. ``none`` = answer only from
    # the local FAQ knowledge base (zero outbound calls, default).
    llm_provider: Literal[
        "none", "openai", "anthropic", "mistral", "openrouter", "ollama"
    ] = "none"
    # API key for the selected provider (not needed for ``ollama`` / ``none``).
    llm_api_key: str = ""
    # Override the model id — empty string lets the provider layer pick a sane default.
    llm_model: str = ""
    # Override the HTTP base URL (useful for self-hosted Ollama or proxies).
    llm_base_url: str = ""
    # Output cap — keeps cost predictable.
    llm_max_tokens: int = 512
    # Per-request timeout when calling the upstream LLM.
    llm_timeout_seconds: float = 20.0
    # Soft per-IP rate limit on /api/chat (requests / minute). 0 = disabled.
    chat_rate_per_minute: int = 30


@lru_cache
def get_settings() -> Settings:
    """Cached settings instance."""
    return Settings()


settings = get_settings()
