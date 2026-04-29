"""System status & health."""

from __future__ import annotations

from datetime import datetime, timezone

import psutil
from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import require_user
from app.db import Agent, Scan, get_db
from app.ml import get_detector
from app.schemas import SystemStatus
from app.services import threats as threats_service

router = APIRouter(tags=["status"])


@router.get("/health")
def health() -> dict:
    return {
        "status": "healthy",
        "version": settings.app_version,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/status", response_model=SystemStatus)
def system_status(
    _user: dict = Depends(require_user),
    db: Session = Depends(get_db),
) -> SystemStatus:
    cpu = psutil.cpu_percent(interval=0.2)
    mem = psutil.virtual_memory().percent
    try:
        disk = psutil.disk_usage("/").percent
    except Exception:
        disk = 0.0

    agents_online = int(
        db.scalar(
            select(func.count(Agent.id)).where(
                Agent.last_seen_at.isnot(None),
            )
        )
        or 0
    )
    files_24h = int(
        db.scalar(select(func.coalesce(func.sum(Scan.files_scanned), 0))) or 0
    )

    return SystemStatus(
        version=settings.app_version,
        threats_detected=threats_service.count_threats_24h(db),
        agents_online=agents_online,
        files_scanned_24h=files_24h,
        cpu_usage=cpu,
        memory_usage=mem,
        disk_usage=disk,
        detector_ready=get_detector().ready,
    )


@router.get("/stats")
def stats(_user: dict = Depends(require_user), db: Session = Depends(get_db)) -> dict:
    return {
        "severity_breakdown": threats_service.severity_breakdown(db),
        "threats_24h": threats_service.count_threats_24h(db),
        "detector_ready": get_detector().ready,
        "version": settings.app_version,
    }
