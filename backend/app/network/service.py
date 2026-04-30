"""Network-V2 service — orchestrates detectors and persists results.

Responsibilities
----------------
* Persist :class:`~app.network.ingest.NetworkEventIn` records as
  :class:`~app.db.models.NetworkEvent` rows, attaching risk factors
  computed live (DGA on ``domain``/``sni``, JA3 known-bad lookup,
  Suricata alert pass-through, TI indicator match).
* Recompute beaconing summaries on demand from recent events.
* Seed the built-in JA3 known-bad list once at startup.

The service deliberately keeps every analytic *side-effect-free* on the
agent path: a missing native dep (numpy) or an exception during DGA
scoring degrades to ``risk=0`` rather than aborting the ingest.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.db.models import (
    JA3Fingerprint,
    NetworkBeacon,
    NetworkEvent,
)
from app.intel.service import IntelService
from app.network.beaconing import detect_beacon
from app.network.dga import dga_score
from app.network.ingest import NetworkEventIn
from app.network.ja3 import builtin_bad_iter, normalise_ja3, normalise_ja4

log = get_logger(__name__)


# Beaconing thresholds — calibrated against pcap traces of Cobalt Strike,
# Empire and benign Slack/Teams noise. The defaults err on the side of
# false-negative in dev; production deployments can tighten via a config knob.
BEACON_MIN_SCORE = 0.65
BEACON_MIN_EVENTS = 6
BEACON_LOOKBACK_HOURS = 6


class NetworkService:
    """Read+write entry-point for Phase C network analytics."""

    def __init__(self, db: Session) -> None:
        self.db = db
        self._intel = IntelService(db)

    # ── Ingest ────────────────────────────────────────────────────────
    def ingest_event(self, ev: NetworkEventIn, *, agent_id: str | None = None) -> NetworkEvent:
        """Persist one event after annotating risk factors. Never raises."""
        try:
            self._annotate_risk(ev)
        except Exception as exc:  # pragma: no cover - defensive
            log.warning("network.annotate.failed", error=str(exc))

        row = NetworkEvent(
            ts=ev.ts,
            agent_id=agent_id,
            src_ip=ev.src_ip,
            dst_ip=ev.dst_ip,
            src_port=ev.src_port,
            dst_port=ev.dst_port,
            proto=ev.proto,
            bytes_in=ev.bytes_in,
            bytes_out=ev.bytes_out,
            domain=ev.domain,
            sni=ev.sni,
            http_host=ev.http_host,
            http_uri=ev.http_uri,
            http_user_agent=ev.http_user_agent,
            ja3=normalise_ja3(ev.ja3 or "") or None,
            ja4=normalise_ja4(ev.ja4 or "") or None,
            suricata_alert=ev.suricata_alert,
            suricata_severity=ev.suricata_severity,
            risk=ev.risk,
            risk_factors=list(ev.risk_factors),
            source=ev.source,
        )
        self.db.add(row)
        self.db.commit()
        self.db.refresh(row)
        return row

    def ingest_batch(
        self, events: Iterable[NetworkEventIn], *, agent_id: str | None = None
    ) -> int:
        """Bulk path. Failures on individual rows do not abort the batch."""
        n = 0
        for ev in events:
            try:
                self.ingest_event(ev, agent_id=agent_id)
                n += 1
            except Exception as exc:  # pragma: no cover - defensive
                log.warning("network.ingest.row_failed", error=str(exc))
                self.db.rollback()
        return n

    # ── Risk annotation ───────────────────────────────────────────────
    def _annotate_risk(self, ev: NetworkEventIn) -> None:
        """Mutates ``ev.risk`` and ``ev.risk_factors`` in place."""
        risk = 0.0
        factors: list[str] = list(ev.risk_factors or [])

        # DGA on the most-meaningful domain field available.
        domain = ev.domain or ev.sni or ev.http_host
        if domain:
            try:
                d = dga_score(domain)
                if float(d["score"]) >= 0.55:
                    risk = max(risk, float(d["score"]))
                    factors.append(f"dga:{d['verdict']}:{d['score']:.2f}")
            except Exception:
                pass

        # JA3 / JA4 lookup against DB.
        ja3 = normalise_ja3(ev.ja3 or "")
        if ja3:
            row = self.db.execute(
                select(JA3Fingerprint).where(
                    JA3Fingerprint.fingerprint == ja3,
                    JA3Fingerprint.enabled.is_(True),
                )
            ).scalar_one_or_none()
            if row is not None:
                risk = max(risk, 0.85)
                fam = row.family or "unknown"
                factors.append(f"ja3:{fam}:{row.source}")

        # TI indicator match — IP / domain reused across the codebase.
        if ev.dst_ip:
            try:
                hits = self._intel.lookup_ip(ev.dst_ip)
                if hits:
                    risk = max(risk, 0.9)
                    fams = ",".join(sorted({h.family or "?" for h in hits}))
                    factors.append(f"ti_ip:{fams}")
            except Exception:
                pass
        if domain:
            try:
                hits = self._intel.lookup_domain(domain)
                if hits:
                    risk = max(risk, 0.9)
                    fams = ",".join(sorted({h.family or "?" for h in hits}))
                    factors.append(f"ti_domain:{fams}")
            except Exception:
                pass

        # Suricata alert — already authoritative, just propagate.
        if ev.suricata_alert:
            sev = ev.suricata_severity or 3
            sev_score = 0.4 + 0.2 * max(0, 4 - sev)  # sev1 -> 1.0, sev3 -> 0.6
            risk = max(risk, min(sev_score, 1.0))
            factors.append(f"suricata:{ev.suricata_alert[:80]}")

        ev.risk = round(risk, 4)
        ev.risk_factors = factors

    # ── Beaconing analyser ────────────────────────────────────────────
    def recompute_beacons(
        self,
        *,
        lookback_hours: int = BEACON_LOOKBACK_HOURS,
        min_events: int = BEACON_MIN_EVENTS,
        min_score: float = BEACON_MIN_SCORE,
    ) -> int:
        """Scan recent events, group by (src,dst,port), keep periodic ones.

        Returns the number of beacon rows written/refreshed.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
        rows = list(self.db.execute(
            select(NetworkEvent).where(NetworkEvent.ts >= cutoff)
        ).scalars())

        # Group by (src_ip, dst_ip, dst_port).
        buckets: dict[tuple[str, str, int | None], list[datetime]] = {}
        for r in rows:
            key = (r.src_ip, r.dst_ip, r.dst_port)
            buckets.setdefault(key, []).append(r.ts)

        written = 0
        now = datetime.now(timezone.utc)
        for (src, dst, port), times in buckets.items():
            if len(times) < min_events:
                continue
            res = detect_beacon(times, min_events=min_events)
            if res.score < min_score:
                continue

            # Upsert by (src, dst, port).
            existing = self.db.execute(
                select(NetworkBeacon).where(
                    NetworkBeacon.src_ip == src,
                    NetworkBeacon.dst_ip == dst,
                    NetworkBeacon.dst_port == port,
                )
            ).scalar_one_or_none()

            if existing is None:
                self.db.add(NetworkBeacon(
                    src_ip=src, dst_ip=dst, dst_port=port,
                    n_events=res.n_events, duration_s=res.duration_s,
                    period_s=res.period_s, score=res.score, jitter=res.jitter,
                    verdict=res.verdict, first_seen_at=min(times), last_seen_at=now,
                ))
            else:
                existing.n_events = res.n_events
                existing.duration_s = res.duration_s
                existing.period_s = res.period_s
                existing.score = res.score
                existing.jitter = res.jitter
                existing.verdict = res.verdict
                existing.last_seen_at = now
            written += 1

        self.db.commit()
        return written

    # ── JA3 management ────────────────────────────────────────────────
    def seed_builtin_ja3(self) -> int:
        """Insert built-in known-bad JA3 entries (idempotent)."""
        n = 0
        now = datetime.now(timezone.utc)
        for rec in builtin_bad_iter():
            fp = rec["fingerprint"]
            existing = self.db.execute(
                select(JA3Fingerprint).where(JA3Fingerprint.fingerprint == fp)
            ).scalar_one_or_none()
            if existing is not None:
                continue
            self.db.add(JA3Fingerprint(
                fingerprint=fp,
                kind=rec.get("kind", "ja3"),
                family=rec.get("family"),
                source=rec.get("source", "builtin"),
                description=rec.get("description"),
                added_at=now,
            ))
            n += 1
        if n:
            self.db.commit()
        return n

    # ── Stats ─────────────────────────────────────────────────────────
    def stats(self) -> dict[str, Any]:
        total_events = self.db.execute(select(func.count()).select_from(NetworkEvent)).scalar() or 0
        recent_cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
        last_24h = self.db.execute(
            select(func.count()).select_from(NetworkEvent).where(NetworkEvent.ts >= recent_cutoff)
        ).scalar() or 0
        beacons = self.db.execute(select(func.count()).select_from(NetworkBeacon)).scalar() or 0
        ja3_n = self.db.execute(select(func.count()).select_from(JA3Fingerprint)).scalar() or 0
        per_source = dict(self.db.execute(
            select(NetworkEvent.source, func.count()).group_by(NetworkEvent.source)
        ).all())
        return {
            "events_total": total_events,
            "events_last_24h": last_24h,
            "beacons": beacons,
            "ja3_fingerprints": ja3_n,
            "per_source": per_source,
        }

    # ── Maintenance ───────────────────────────────────────────────────
    def prune_old_events(self, retention_days: int = 30) -> int:
        cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
        res = self.db.execute(delete(NetworkEvent).where(NetworkEvent.ts < cutoff))
        self.db.commit()
        return res.rowcount or 0
