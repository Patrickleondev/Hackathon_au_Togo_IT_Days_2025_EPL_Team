"""Scans router (queue + status)."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logging import get_logger
from app.core.security import require_user
from app.db import Scan, ScanStatus, ScanType, get_db
from app.ml import get_detector
from app.schemas import ScanOut, ScanRequest
from app.services import threats as threats_service

router = APIRouter(prefix="/scans", tags=["scans"])
log = get_logger(__name__)


def _safe_targets(paths: list[str]) -> list[Path]:
    """Only allow scanning under the storage roots managed by the backend."""
    safe_roots = [Path(settings.uploads_dir), Path(settings.storage_dir)]
    out: list[Path] = []
    for p in paths or []:
        try:
            ap = Path(p).resolve()
        except OSError:
            continue
        if any(str(ap).startswith(str(r.resolve())) for r in safe_roots):
            out.append(ap)
    if not out:
        out = [Path(settings.uploads_dir)]
    return out


def _run_scan(scan_id: str) -> None:
    """Background scan runner. Uses its own DB session."""
    from app.db import SessionLocal

    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if scan is None:
            return
        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.now(timezone.utc)
        db.commit()

        detector = get_detector()
        files_scanned = 0
        threats_found = 0
        max_files = settings.scan_max_files
        for root in _safe_targets(scan.target_paths):
            if not root.exists():
                continue
            for path in root.rglob("*"):
                if not path.is_file():
                    continue
                files_scanned += 1
                if files_scanned > max_files:
                    break
                result = detector.analyze_path(path)
                if result.is_threat:
                    threats_service.record_threat(
                        db,
                        result=result,
                        file_path=str(path),
                        detection_source=f"scan:{scan.scan_type}",
                    )
                    threats_found += 1
            if files_scanned > max_files:
                break

        scan.files_scanned = files_scanned
        scan.threats_found = threats_found
        scan.status = ScanStatus.COMPLETED
        scan.finished_at = datetime.now(timezone.utc)
        db.commit()
        log.info("scan.done", scan_id=scan_id, files=files_scanned, threats=threats_found)
    except Exception as exc:
        scan = db.get(Scan, scan_id)
        if scan:
            scan.status = ScanStatus.FAILED
            scan.error = str(exc)
            scan.finished_at = datetime.now(timezone.utc)
            db.commit()
        log.error("scan.failed", scan_id=scan_id, error=str(exc))
    finally:
        db.close()


@router.post("", response_model=ScanOut, status_code=202)
def start_scan(
    payload: ScanRequest,
    background: BackgroundTasks,
    _user: dict = Depends(require_user),
    db: Session = Depends(get_db),
) -> ScanOut:
    if payload.scan_type not in {t.value for t in ScanType}:
        raise HTTPException(400, f"Unsupported scan_type: {payload.scan_type}")
    scan = Scan(
        scan_type=payload.scan_type,
        status=ScanStatus.PENDING,
        target_paths=payload.target_paths,
        agent_id=payload.agent_id,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    background.add_task(_run_scan, scan.id)
    return ScanOut.model_validate(scan)


@router.get("/{scan_id}", response_model=ScanOut)
def get_scan(
    scan_id: str,
    _user: dict = Depends(require_user),
    db: Session = Depends(get_db),
) -> ScanOut:
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return ScanOut.model_validate(scan)


@router.post("/{scan_id}/cancel", response_model=ScanOut)
def cancel_scan(
    scan_id: str,
    _user: dict = Depends(require_user),
    db: Session = Depends(get_db),
) -> ScanOut:
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    if scan.status in (ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED):
        return ScanOut.model_validate(scan)
    scan.status = ScanStatus.CANCELLED
    scan.finished_at = datetime.now(timezone.utc)
    db.commit()
    return ScanOut.model_validate(scan)
