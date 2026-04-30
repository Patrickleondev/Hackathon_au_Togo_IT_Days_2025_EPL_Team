"""On-demand file analysis (uploads + agent submissions)."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import require_agent, require_user
from app.db import get_db
from app.ml import get_detector
from app.schemas import FileAnalysisResult
from app.services import threats as threats_service

router = APIRouter(prefix="/analyze", tags=["analyze"])


def _build_result(detector_result, file_name: str, size: int) -> FileAnalysisResult:
    recommendations = [
        "Do not execute the file.",
        "Isolate the host from the network if a real infection is suspected.",
        "Contact CERT-TG hotline (+228) 70 54 93 25 in Togo.",
        "Never pay the ransom.",
    ]
    return FileAnalysisResult(
        file_name=file_name,
        file_size=size,
        file_sha256=detector_result.sha256,
        is_threat=detector_result.is_threat,
        confidence=detector_result.confidence,
        threat_type=detector_result.threat_type,
        severity=detector_result.severity,
        description=detector_result.description,
        indicators={
            **detector_result.indicators,
            "matched_rules": detector_result.matched_rules,
            "score_heuristic": detector_result.score_heuristic,
            "score_ml": detector_result.score_ml,
            "score_yara": detector_result.score_yara,
        },
        recommendations=recommendations,
        analysis_method="unified_detector",
        timestamp=datetime.now(timezone.utc),
    )


@router.post("/file", response_model=FileAnalysisResult)
async def analyze_file_upload(
    file: UploadFile = File(...),
    _user: dict = Depends(require_user),
    db: Session = Depends(get_db),
) -> FileAnalysisResult:
    """Analyst-uploads a file from the dashboard."""
    if not file.filename:
        raise HTTPException(400, "Missing filename")

    data = await file.read()
    if len(data) > settings.max_upload_mb * 1024 * 1024:
        raise HTTPException(413, f"File exceeds {settings.max_upload_mb} MB")

    detector = get_detector()
    result = detector.analyze_bytes(file.filename, data)

    if result.is_threat:
        threats_service.record_threat(
            db,
            result=result,
            file_name=file.filename,
            detection_source="upload",
        )

    return _build_result(result, file.filename, len(data))


@router.post("/agent-file", response_model=FileAnalysisResult)
async def analyze_agent_file(
    file: UploadFile = File(...),
    claims: dict = Depends(require_agent),
    db: Session = Depends(get_db),
) -> FileAnalysisResult:
    """Endpoint agents push suspicious files here for second-opinion analysis."""
    if not file.filename:
        raise HTTPException(400, "Missing filename")
    data = await file.read()
    if len(data) > settings.max_upload_mb * 1024 * 1024:
        raise HTTPException(413, "File too large")

    result = get_detector().analyze_bytes(file.filename, data)

    if result.is_threat:
        threats_service.record_threat(
            db,
            result=result,
            file_name=file.filename,
            agent_id=claims["sub"],
            detection_source="agent",
        )
    return _build_result(result, file.filename, len(data))
