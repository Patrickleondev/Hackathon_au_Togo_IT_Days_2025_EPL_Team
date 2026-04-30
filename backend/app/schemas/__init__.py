"""Pydantic schemas (request / response DTOs)."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field


# ─── Auth ─────────────────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserOut | None = None


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    email: EmailStr
    role: str
    is_active: bool


# ─── Agents ───────────────────────────────────────────────────────────────
class AgentEnrollRequest(BaseModel):
    hostname: str
    os: str
    os_version: str = ""
    agent_version: str = ""
    metadata: dict = Field(default_factory=dict)


class AgentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    hostname: str
    os: str
    os_version: str
    agent_version: str
    is_active: bool
    last_seen_at: datetime | None
    created_at: datetime


class AgentEnrollResponse(BaseModel):
    agent: AgentOut
    token: str  # JWT for the agent


class AgentHeartbeat(BaseModel):
    cpu: float = 0.0
    memory: float = 0.0
    metrics: dict = Field(default_factory=dict)


# ─── Threats ──────────────────────────────────────────────────────────────
class ThreatIn(BaseModel):
    """Sent by the agent or by /api/analyze endpoints."""

    threat_type: str
    severity: str
    confidence: float = Field(ge=0.0, le=1.0)
    file_path: str | None = None
    file_sha256: str | None = None
    process_name: str | None = None
    description: str = ""
    indicators: dict = Field(default_factory=dict)
    detection_source: str = "ml"


class ThreatOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    agent_id: str | None
    threat_type: str
    severity: str
    status: str
    confidence: float
    file_path: str | None
    file_sha256: str | None
    process_name: str | None
    description: str
    indicators: dict
    detection_source: str
    quarantined: bool
    created_at: datetime


class ThreatList(BaseModel):
    items: list[ThreatOut]
    count: int


# ─── Scans ────────────────────────────────────────────────────────────────
class ScanRequest(BaseModel):
    scan_type: str = "quick"
    target_paths: list[str] = Field(default_factory=list)
    agent_id: str | None = None


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    scan_type: str
    status: str
    target_paths: list[str]
    files_scanned: int
    threats_found: int
    started_at: datetime | None
    finished_at: datetime | None
    error: str | None


# ─── Analyze ──────────────────────────────────────────────────────────────
class FileAnalysisResult(BaseModel):
    file_name: str
    file_size: int
    file_sha256: str
    is_threat: bool
    confidence: float
    threat_type: str
    severity: str
    description: str
    indicators: dict
    recommendations: list[str]
    analysis_method: str
    timestamp: datetime


# ─── Status / Health ──────────────────────────────────────────────────────
class SystemStatus(BaseModel):
    status: str = "active"
    version: str
    threats_detected: int
    agents_online: int
    files_scanned_24h: int
    cpu_usage: float
    memory_usage: float
    disk_usage: float
    detector_ready: bool


# ─── Eradication ──────────────────────────────────────────────────────────
class EradicationScope(BaseModel):
    agent_ids: list[str] = Field(default_factory=list)
    paths: list[str] = Field(default_factory=list)


class EradicationRequest(BaseModel):
    threat_id: str | None = None
    scope: EradicationScope
    actions: list[str] = Field(default_factory=lambda: ["quarantine_files"])
    dry_run: bool = True
    min_confidence: float = 0.85


class EradicationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    threat_id: str | None
    actions: list[str]
    scope: dict
    dry_run: bool
    min_confidence: float
    result: dict
    created_at: datetime


# Resolve forward refs
TokenResponse.model_rebuild()
