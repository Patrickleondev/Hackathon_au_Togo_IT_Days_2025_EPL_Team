"""Threats listing & lifecycle actions."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.security import require_user
from app.db import ThreatStatus, get_db
from app.schemas import ThreatIn, ThreatList, ThreatOut
from app.services import threats as threats_service

router = APIRouter(prefix="/threats", tags=["threats"])


@router.get("", response_model=ThreatList)
def list_threats(
    limit: int = 50,
    _user: dict = Depends(require_user),
    db: Session = Depends(get_db),
) -> ThreatList:
    rows = threats_service.list_threats(db, limit=limit)
    return ThreatList(items=[ThreatOut.model_validate(r) for r in rows], count=len(rows))


@router.post("", response_model=ThreatOut, status_code=201)
def create_threat(
    payload: ThreatIn,
    _user: dict = Depends(require_user),
    db: Session = Depends(get_db),
) -> ThreatOut:
    """Manual ingestion endpoint (analysts can record an indicator)."""
    from app.db import Threat

    threat = Threat(
        threat_type=payload.threat_type,
        severity=payload.severity,
        confidence=payload.confidence,
        file_path=payload.file_path,
        file_sha256=payload.file_sha256,
        process_name=payload.process_name,
        description=payload.description,
        indicators=payload.indicators,
        detection_source=payload.detection_source,
    )
    db.add(threat)
    db.commit()
    db.refresh(threat)
    return ThreatOut.model_validate(threat)


@router.post("/{threat_id}/quarantine", response_model=ThreatOut)
def quarantine(
    threat_id: str,
    _user: dict = Depends(require_user),
    db: Session = Depends(get_db),
) -> ThreatOut:
    threat = threats_service.update_threat_status(db, threat_id, ThreatStatus.QUARANTINED)
    if not threat:
        raise HTTPException(404, "Threat not found")
    return ThreatOut.model_validate(threat)


@router.post("/{threat_id}/neutralize", response_model=ThreatOut)
def neutralize(
    threat_id: str,
    _user: dict = Depends(require_user),
    db: Session = Depends(get_db),
) -> ThreatOut:
    threat = threats_service.update_threat_status(db, threat_id, ThreatStatus.NEUTRALIZED)
    if not threat:
        raise HTTPException(404, "Threat not found")
    return ThreatOut.model_validate(threat)


@router.post("/{threat_id}/dismiss", response_model=ThreatOut)
def dismiss(
    threat_id: str,
    _user: dict = Depends(require_user),
    db: Session = Depends(get_db),
) -> ThreatOut:
    threat = threats_service.update_threat_status(db, threat_id, ThreatStatus.DISMISSED)
    if not threat:
        raise HTTPException(404, "Threat not found")
    return ThreatOut.model_validate(threat)
