"""Threat service — convert detection results into persisted Threat rows."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.db import Severity, Threat, ThreatStatus
from app.ml import DetectionResult


def record_threat(
    db: Session,
    *,
    result: DetectionResult,
    file_path: str | None = None,
    file_name: str | None = None,
    agent_id: str | None = None,
    detection_source: str = "api",
) -> Threat:
    threat = Threat(
        agent_id=agent_id,
        threat_type=result.threat_type,
        severity=result.severity,
        status=ThreatStatus.DETECTED,
        confidence=result.confidence,
        file_path=file_path or file_name,
        file_sha256=result.sha256 or None,
        description=result.description,
        indicators={
            **result.indicators,
            "matched_rules": result.matched_rules,
            "score_heuristic": result.score_heuristic,
            "score_ml": result.score_ml,
            "score_yara": result.score_yara,
        },
        detection_source=detection_source,
    )
    db.add(threat)
    db.commit()
    db.refresh(threat)
    return threat


def list_threats(db: Session, limit: int = 50) -> list[Threat]:
    stmt = select(Threat).order_by(desc(Threat.created_at)).limit(limit)
    return list(db.scalars(stmt))


def count_threats_24h(db: Session) -> int:
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    stmt = select(func.count(Threat.id)).where(Threat.created_at >= since)
    return int(db.scalar(stmt) or 0)


def update_threat_status(db: Session, threat_id: str, status: str) -> Threat | None:
    threat = db.get(Threat, threat_id)
    if threat is None:
        return None
    threat.status = status
    if status == ThreatStatus.QUARANTINED:
        threat.quarantined = True
    db.commit()
    db.refresh(threat)
    return threat


def severity_breakdown(db: Session) -> dict[str, int]:
    stmt = select(Threat.severity, func.count(Threat.id)).group_by(Threat.severity)
    rows = db.execute(stmt).all()
    out = {s.value: 0 for s in Severity}
    for sev, n in rows:
        out[sev] = int(n)
    return out
