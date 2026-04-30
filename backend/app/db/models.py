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


# ─── Threat Intelligence ──────────────────────────────────────────────────
class IntelHash(Base):
    """Known-malicious file hash from external TI feeds (MalwareBazaar, etc.)."""

    __tablename__ = "intel_hashes"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    sha256: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    sha1: Mapped[str | None] = mapped_column(String(40), nullable=True, index=True)
    md5: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    imphash: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    ssdeep: Mapped[str | None] = mapped_column(String(255), nullable=True)
    tlsh: Mapped[str | None] = mapped_column(String(72), nullable=True)
    file_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    file_size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    signature: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    family: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    tags: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    source: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    confidence: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)
    first_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    extra: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)


class IntelIndicator(Base):
    """Network/web indicator (IP, domain, URL, CIDR) from TI feeds."""

    __tablename__ = "intel_indicators"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    # type: "ip" | "domain" | "url" | "cidr"
    indicator_type: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    value: Mapped[str] = mapped_column(String(2048), nullable=False, index=True)
    family: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    threat_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    confidence: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)
    attack_techniques: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    tags: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    first_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    extra: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)


class IntelYaraRule(Base):
    """Auto-fetched YARA rule from a community feed (e.g. YARAify)."""

    __tablename__ = "intel_yara_rules"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    rule_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    sha256: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    author: Mapped[str | None] = mapped_column(String(255), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    added_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class IntelFeedRun(Base):
    """Audit trail for each feed refresh attempt."""

    __tablename__ = "intel_feed_runs"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    feed: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # "ok" | "error" | "skipped"
    status: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    ingested: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    updated: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0, nullable=False)


# ─── Network-V2 (Phase C) ─────────────────────────────────────────────────
class NetworkEvent(Base):
    """Single network observation pushed by an agent / Suricata / Zeek.

    Sized to be cheap (no full payload, no PCAP) — we only store the bits
    we use for analytics and joins to TI.
    """

    __tablename__ = "network_events"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    agent_id: Mapped[str | None] = mapped_column(
        String(32), ForeignKey("agents.id", ondelete="SET NULL"), nullable=True, index=True
    )
    src_ip: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    dst_ip: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    src_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    proto: Mapped[str] = mapped_column(String(8), nullable=False)
    bytes_in: Mapped[int | None] = mapped_column(Integer, nullable=True)
    bytes_out: Mapped[int | None] = mapped_column(Integer, nullable=True)
    domain: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    sni: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    http_host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    http_uri: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    http_user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)
    ja3: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    ja4: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    suricata_alert: Mapped[str | None] = mapped_column(String(255), nullable=True)
    suricata_severity: Mapped[int | None] = mapped_column(Integer, nullable=True)
    risk: Mapped[float] = mapped_column(Float, default=0.0, nullable=False, index=True)
    risk_factors: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    source: Mapped[str] = mapped_column(String(16), default="agent", nullable=False, index=True)


class NetworkBeacon(Base):
    """Detected periodic communication channel — running summary.

    A row is created/updated by the periodic beaconing analyser per
    ``(src_ip, dst_ip, dst_port)`` tuple it considers suspicious enough
    (``score >= 0.65``).
    """

    __tablename__ = "network_beacons"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    src_ip: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    dst_ip: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    n_events: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    duration_s: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    period_s: Mapped[float | None] = mapped_column(Float, nullable=True)
    score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False, index=True)
    jitter: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    verdict: Mapped[str] = mapped_column(String(32), default="unknown", nullable=False, index=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class JA3Fingerprint(Base):
    """Known-bad JA3 / JA4 fingerprint loaded from feeds or seeded built-in."""

    __tablename__ = "ja3_fingerprints"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String(8), default="ja3", nullable=False)
    family: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    source: Mapped[str] = mapped_column(String(64), default="builtin", nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    added_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
