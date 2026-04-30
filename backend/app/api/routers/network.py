"""Network-V2 endpoints (Phase C).

Routes
------
* ``POST /network/events``       — bulk ingest from agent / Suricata / Zeek
* ``POST /network/events/raw``   — ingest raw eve.json or zeek lines
* ``GET  /network/stats``        — counts + last-N summaries
* ``GET  /network/dga``          — score one domain on-demand (no DB write)
* ``GET  /network/beacons``      — list known beaconing channels
* ``POST /network/beacons/recompute`` — admin trigger
* ``GET  /network/ja3/{fp}``     — known-bad lookup

Auth model mirrors the rest of the API: ingest = agent JWT, analytics =
any authenticated user, recompute = admin only. We never expose raw
network events without auth — they can carry sensitive corporate URLs.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, BackgroundTasks, Body, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import require_agent, require_user
from app.db import get_db
from app.db.models import JA3Fingerprint, NetworkBeacon
from app.network.dga import dga_score
from app.network.ingest import (
    NetworkEventIn,
    parse_suricata_eve,
    parse_zeek_conn,
    parse_zeek_dns,
    parse_zeek_ssl,
)
from app.network.ja3 import is_known_bad_ja3
from app.network.service import NetworkService

router = APIRouter(prefix="/network", tags=["network"])


async def require_admin(payload: dict[str, Any] = Depends(require_user)) -> dict[str, Any]:
    if (payload.get("role") or "").lower() != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required")
    return payload


# ─── Pydantic payloads ────────────────────────────────────────────────────
class NetworkEventPayload(BaseModel):
    ts: str = Field(..., description="ISO-8601 timestamp")
    src_ip: str = Field(..., max_length=64)
    dst_ip: str = Field(..., max_length=64)
    proto: str = Field("tcp", max_length=8)
    src_port: int | None = None
    dst_port: int | None = None
    bytes_in: int | None = None
    bytes_out: int | None = None
    domain: str | None = Field(None, max_length=255)
    sni: str | None = Field(None, max_length=255)
    http_host: str | None = Field(None, max_length=255)
    http_uri: str | None = Field(None, max_length=2048)
    http_user_agent: str | None = Field(None, max_length=512)
    ja3: str | None = Field(None, max_length=64)
    ja4: str | None = Field(None, max_length=64)
    suricata_alert: str | None = Field(None, max_length=255)
    suricata_severity: int | None = None
    source: str = Field("agent", max_length=16)


class NetworkEventBatch(BaseModel):
    events: list[NetworkEventPayload] = Field(default_factory=list, max_length=5000)


class RawIngestPayload(BaseModel):
    fmt: str = Field("suricata-eve", description="suricata-eve | zeek-conn | zeek-dns | zeek-ssl")
    lines: list[str] = Field(default_factory=list, max_length=5000)


# ─── Helpers ──────────────────────────────────────────────────────────────
def _payload_to_event(p: NetworkEventPayload) -> NetworkEventIn:
    from datetime import datetime
    try:
        ts = datetime.fromisoformat(p.ts.replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid ts: {p.ts}")
    return NetworkEventIn(
        ts=ts, src_ip=p.src_ip, dst_ip=p.dst_ip, proto=p.proto,
        src_port=p.src_port, dst_port=p.dst_port,
        bytes_in=p.bytes_in, bytes_out=p.bytes_out,
        domain=p.domain, sni=p.sni,
        http_host=p.http_host, http_uri=p.http_uri,
        http_user_agent=p.http_user_agent,
        ja3=p.ja3, ja4=p.ja4,
        suricata_alert=p.suricata_alert, suricata_severity=p.suricata_severity,
        source=p.source,
    )


def _serialize_beacon(b: NetworkBeacon) -> dict[str, Any]:
    return {
        "id": b.id,
        "src_ip": b.src_ip,
        "dst_ip": b.dst_ip,
        "dst_port": b.dst_port,
        "n_events": b.n_events,
        "duration_s": b.duration_s,
        "period_s": b.period_s,
        "score": b.score,
        "jitter": b.jitter,
        "verdict": b.verdict,
        "first_seen_at": b.first_seen_at.isoformat(),
        "last_seen_at": b.last_seen_at.isoformat(),
    }


def _serialize_ja3(r: JA3Fingerprint) -> dict[str, Any]:
    return {
        "fingerprint": r.fingerprint,
        "kind": r.kind,
        "family": r.family,
        "source": r.source,
        "description": r.description,
        "enabled": r.enabled,
    }


# ─── Ingest ───────────────────────────────────────────────────────────────
@router.post("/events", status_code=202)
def ingest_events(
    body: NetworkEventBatch,
    db: Session = Depends(get_db),
    auth: dict[str, Any] = Depends(require_agent),
) -> dict[str, Any]:
    """Bulk ingest of pre-parsed events from agent / sidecar."""
    svc = NetworkService(db)
    agent_id = auth.get("sub")
    events = [_payload_to_event(p) for p in body.events]
    n = svc.ingest_batch(events, agent_id=agent_id)
    return {"accepted": n, "rejected": len(events) - n}


@router.post("/events/raw", status_code=202)
def ingest_raw(
    body: RawIngestPayload,
    db: Session = Depends(get_db),
    auth: dict[str, Any] = Depends(require_agent),
) -> dict[str, Any]:
    """Ingest raw lines from Suricata eve.json or Zeek logs."""
    parser = {
        "suricata-eve": parse_suricata_eve,
        "zeek-conn": parse_zeek_conn,
        "zeek-dns": parse_zeek_dns,
        "zeek-ssl": parse_zeek_ssl,
    }.get(body.fmt)
    if parser is None:
        raise HTTPException(status_code=400, detail=f"Unknown fmt: {body.fmt}")

    events = [ev for ev in (parser(line) for line in body.lines) if ev is not None]
    svc = NetworkService(db)
    n = svc.ingest_batch(events, agent_id=auth.get("sub"))
    return {"parsed": len(events), "accepted": n, "skipped": len(body.lines) - len(events)}


# ─── Read endpoints ───────────────────────────────────────────────────────
@router.get("/stats")
def stats(
    db: Session = Depends(get_db),
    _: dict[str, Any] = Depends(require_user),
) -> dict[str, Any]:
    return NetworkService(db).stats()


@router.get("/dga")
def score_domain(
    domain: str = Query(..., min_length=1, max_length=255),
    _: dict[str, Any] = Depends(require_user),
) -> dict[str, Any]:
    """Score one domain — pure function, never hits the DB."""
    return dga_score(domain)


@router.get("/beacons")
def list_beacons(
    min_score: float = Query(0.0, ge=0.0, le=1.0),
    limit: int = Query(100, ge=1, le=1000),
    db: Session = Depends(get_db),
    _: dict[str, Any] = Depends(require_user),
) -> dict[str, Any]:
    rows = list(db.execute(
        select(NetworkBeacon)
        .where(NetworkBeacon.score >= min_score)
        .order_by(NetworkBeacon.score.desc())
        .limit(limit)
    ).scalars())
    return {"count": len(rows), "items": [_serialize_beacon(r) for r in rows]}


@router.post("/beacons/recompute", status_code=202)
def recompute_beacons(
    background: BackgroundTasks,
    lookback_hours: int = Query(6, ge=1, le=72),
    db: Session = Depends(get_db),
    _: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    """Trigger a beaconing recomputation in the background."""
    def _run() -> None:
        from app.db import SessionLocal
        s = SessionLocal()
        try:
            NetworkService(s).recompute_beacons(lookback_hours=lookback_hours)
        finally:
            s.close()

    background.add_task(_run)
    return {"accepted": True, "lookback_hours": lookback_hours}


@router.get("/ja3/{fingerprint}")
def lookup_ja3(
    fingerprint: str,
    db: Session = Depends(get_db),
    _: dict[str, Any] = Depends(require_user),
) -> dict[str, Any]:
    """Lookup against DB first, fall back to built-in list."""
    fp = (fingerprint or "").lower().strip()
    row = db.execute(
        select(JA3Fingerprint).where(JA3Fingerprint.fingerprint == fp)
    ).scalar_one_or_none()
    if row is not None:
        return {"found": True, **_serialize_ja3(row)}
    builtin = is_known_bad_ja3(fp)
    if builtin is not None:
        return {
            "found": True,
            "fingerprint": builtin.fingerprint,
            "kind": builtin.kind,
            "family": builtin.family,
            "source": builtin.source,
            "description": builtin.description,
            "enabled": True,
        }
    return {"found": False, "fingerprint": fp}
