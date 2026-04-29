"""HTTP client for the central RansomGuard API."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx

from ransomguard_agent.config import settings


def _url(path: str) -> str:
    return f"{settings.backend_url.rstrip('/')}{settings.api_prefix}{path}"


def _headers() -> dict[str, str]:
    h = {"User-Agent": "ransomguard-agent/2.0"}
    if settings.token:
        h["Authorization"] = f"Bearer {settings.token}"
    return h


def enroll(hostname: str, os_name: str, os_version: str, agent_version: str) -> dict[str, Any]:
    payload = {
        "hostname": hostname,
        "os": os_name,
        "os_version": os_version,
        "agent_version": agent_version,
    }
    with httpx.Client(timeout=15) as c:
        r = c.post(_url("/agents/enroll"), json=payload, headers=_headers())
        r.raise_for_status()
        return r.json()


def heartbeat(metrics: dict[str, Any]) -> None:
    with httpx.Client(timeout=10) as c:
        r = c.post(_url("/agents/heartbeat"), json={"metrics": metrics}, headers=_headers())
        r.raise_for_status()


def upload_file(path: Path) -> dict[str, Any]:
    with httpx.Client(timeout=60) as c, path.open("rb") as f:
        r = c.post(
            _url("/analyze/agent-file"),
            files={"file": (path.name, f, "application/octet-stream")},
            headers=_headers(),
        )
        r.raise_for_status()
        return r.json()
