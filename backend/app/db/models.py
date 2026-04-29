"""SQLAlchemy ORM models."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


def _uuid() -> str:
    return uuid.uuid4().hex


class Role(StrEnum):
    ADMIN = "admin"
    ANALYST = "analyst"
    READONLY = "readonly"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatStatus(StrEnum):
    DETECTED = "detected"
    QUARANTINED = "quarantined"
    NEUTRALIZED = "neutralized"
    DISMISSED = "dismissed"


class ScanType(StrEnum):
    QUICK = "quick"
    FULL = "full"
    CUSTOM = "custom"


class ScanStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


# ─── User ─────────────────────────────────────────────────────────────────
class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(32), default=Role.ANALYST, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


# ─── Agent (Windows endpoint) ─────────────────────────────────────────────
class Agent(Base):
    __tablename__ = "agents"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    os: Mapped[str] = mapped_column(String(64), nullable=False)
    os_version: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    agent_version: Mapped[str] = mapped_column(String(32), default="", nullable=False)
    enrollment_token: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)

    threats: Mapped[list[Threat]] = relationship(back_populates="agent", cascade="all, delete-orphan")


# ─── Threat ───────────────────────────────────────────────────────────────
class Threat(Base):
    __tablename__ = "threats"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    agent_id: Mapped[str | None] = mapped_column(
        String(32), ForeignKey("agents.id", ondelete="SET NULL"), nullable=True, index=True
    )
    threat_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), default=ThreatStatus.DETECTED, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    file_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    file_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    process_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    indicators: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    detection_source: Mapped[str] = mapped_column(String(32), default="ml", nullable=False)
    quarantined: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    agent: Mapped[Agent | None] = relationship(back_populates="threats")


# ─── Scan ─────────────────────────────────────────────────────────────────
class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    agent_id: Mapped[str | None] = mapped_column(
        String(32), ForeignKey("agents.id", ondelete="SET NULL"), nullable=True
    )
    scan_type: Mapped[str] = mapped_column(String(16), default=ScanType.QUICK, nullable=False)
    status: Mapped[str] = mapped_column(String(16), default=ScanStatus.PENDING, nullable=False)
    target_paths: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    files_scanned: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    threats_found: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)


# ─── Eradication plan ─────────────────────────────────────────────────────
class Eradication(Base):
    __tablename__ = "eradications"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    threat_id: Mapped[str | None] = mapped_column(
        String(32), ForeignKey("threats.id", ondelete="SET NULL"), nullable=True
    )
    actions: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    scope: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    dry_run: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    min_confidence: Mapped[float] = mapped_column(Float, default=0.85, nullable=False)
    result: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    initiated_by: Mapped[str | None] = mapped_column(String(32), nullable=True)
