"""Background tasks executed by the RQ worker.

The current implementation keeps tasks side-effect free: they all go through
the unified detector and persist results via a fresh DB session.
"""

from __future__ import annotations

from datetime import datetime, timezone

from app.core.logging import get_logger
from app.db import SessionLocal
from app.ml import get_detector
from app.services import threats as threats_service

log = get_logger(__name__)


def analyze_path_async(file_path: str, agent_id: str | None = None) -> dict:
    detector = get_detector()
    result = detector.analyze_path(file_path)
    db = SessionLocal()
    try:
        if result.is_threat:
            threats_service.record_threat(
                db,
                result=result,
                file_path=file_path,
                agent_id=agent_id,
                detection_source="worker",
            )
    finally:
        db.close()
    log.info("worker.analyze_path", path=file_path, threat=result.is_threat)
    return {**result.to_dict(), "completed_at": datetime.now(timezone.utc).isoformat()}
