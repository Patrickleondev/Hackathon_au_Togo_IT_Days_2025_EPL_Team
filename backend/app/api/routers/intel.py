"""Threat-intelligence read endpoints + manual refresh trigger.

Read endpoints are auth'd as any logged-in user. The refresh endpoint
requires admin role — letting any user trigger feed pulls would let them
burn the abuse.ch quota.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.security import require_user
from app.db import get_db
from app.intel.service import IntelService, run_all_feeds_once

router = APIRouter(prefix="/intel", tags=["intel"])


async def require_admin(payload: dict[str, Any] = Depends(require_user)) -> dict[str, Any]:
    """Local admin gate — the JWT must carry ``role == 'admin'``."""
    if (payload.get("role") or "").lower() != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required")
    return payload


@router.get("/stats")
def stats(
    db: Session = Depends(get_db),
    _: dict[str, Any] = Depends(require_user),
) -> dict[str, Any]:
    """Per-feed and global TI counts + last-run audit data."""
    return IntelService(db).stats()


@router.get("/lookup/hash/{sha256}")
def lookup_hash(
    sha256: str,
    db: Session = Depends(get_db),
    _: dict[str, Any] = Depends(require_user),
) -> dict[str, Any]:
    """Return the IntelHash row for ``sha256`` (404 if unknown)."""
    row = IntelService(db).lookup_hash(sha256)
    if row is None:
        raise HTTPException(status_code=404, detail="hash not in TI DB")
    return _serialize_hash(row)


@router.get("/lookup/indicator")
def lookup_indicator(
    value: str = Query(..., min_length=1, max_length=2048),
    db: Session = Depends(get_db),
    _: dict[str, Any] = Depends(require_user),
) -> dict[str, Any]:
    """Look up an IP / domain / URL across every feed."""
    rows = IntelService(db).lookup_indicator(value)
    return {
        "value": value,
        "matches": [_serialize_indicator(r) for r in rows],
        "count": len(rows),
    }


@router.post("/refresh", status_code=202)
def refresh(
    background: BackgroundTasks,
    only: str | None = Query(default=None, description="Comma-separated feed names"),
    _: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    """Trigger a feed refresh in the background. Admin only.

    Use ``?only=malware_bazaar,threatfox`` to refresh a subset.
    """
    feeds = [s.strip() for s in only.split(",")] if only else None
    background.add_task(run_all_feeds_once, only=feeds)
    return {"accepted": True, "only": feeds}


# ─── Serializers ──────────────────────────────────────────────────────────
def _serialize_hash(r: Any) -> dict[str, Any]:
    return {
        "sha256": r.sha256,
        "sha1": r.sha1,
        "md5": r.md5,
        "imphash": r.imphash,
        "ssdeep": r.ssdeep,
        "tlsh": r.tlsh,
        "file_type": r.file_type,
        "file_size": r.file_size,
        "signature": r.signature,
        "family": r.family,
        "tags": r.tags,
        "source": r.source,
        "confidence": r.confidence,
        "first_seen_at": r.first_seen_at.isoformat() if r.first_seen_at else None,
        "last_seen_at": r.last_seen_at.isoformat() if r.last_seen_at else None,
    }


def _serialize_indicator(r: Any) -> dict[str, Any]:
    return {
        "indicator_type": r.indicator_type,
        "value": r.value,
        "family": r.family,
        "threat_type": r.threat_type,
        "source": r.source,
        "confidence": r.confidence,
        "attack_techniques": r.attack_techniques,
        "tags": r.tags,
        "first_seen_at": r.first_seen_at.isoformat() if r.first_seen_at else None,
        "last_seen_at": r.last_seen_at.isoformat() if r.last_seen_at else None,
    }
