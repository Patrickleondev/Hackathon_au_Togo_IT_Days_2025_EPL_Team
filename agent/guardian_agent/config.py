"""Agent configuration."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class AgentSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="GUARDIAN_",
        extra="ignore",
    )

    backend_url: str = "http://localhost:8000"
    api_prefix: str = "/api"
    token: str = ""               # filled in after enrollment
    agent_id: str = ""            # filled in after enrollment
    enrollment_secret: str = ""   # required by the backend's /agents/enroll

    state_dir: Path = Path.home() / ".guardian-agent"

    # Watch paths (defaults to user home; admin can override)
    watch_paths: list[str] = []

    heartbeat_sec: int = 30
    upload_max_mb: int = 50
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"


settings = AgentSettings()
