"""Intel service — orchestrates all feed clients and exposes a single entry-point.

The scheduler (``app.intel.scheduler``) calls :func:`run_all_feeds_once` on a
recurring interval. Code that needs synchronous TI lookups (the detector,
the analyze endpoint, the agent heartbeat) talks to :class:`IntelService`
which only reads from the local DB — never the network.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logging import get_logger
from app.db.models import IntelFeedRun, IntelHash, IntelIndicator, IntelYaraRule
from app.db.session import SessionLocal
from app.intel.abuseipdb import AbuseIPDBFeed
from app.intel.base import Feed
from app.intel.feodo_tracker import FeodoTrackerFeed
from app.intel.malware_bazaar import MalwareBazaarFeed
from app.intel.otx import OTXFeed
from app.intel.threatfox import ThreatFoxFeed
from app.intel.urlhaus import URLhausFeed
from app.intel.yaraify import YaraifyFeed

log = get_logger(__name__)


def _all_feed_classes() -> list[type[Feed]]:
    return [
        MalwareBazaarFeed,
        URLhausFeed,
        ThreatFoxFeed,
        FeodoTrackerFeed,
        YaraifyFeed,
        AbuseIPDBFeed,
        OTXFeed,
    ]


# ─── Public synchronous service (used by detector / API) ───────────────────
class IntelService:
    """Read-only TI lookups against the local DB. No outbound calls here."""

    def __init__(self, db: Session) -> None:
        self.db = db

    # ── Hash ──────────────────────────────────────────────────────────────
    def lookup_hash(self, sha256: str) -> IntelHash | None:
        sha = (sha256 or "").lower().strip()
        if len(sha) != 64:
            return None
        return self.db.execute(
            select(IntelHash).where(IntelHash.sha256 == sha)
        ).scalar_one_or_none()

    # ── Fuzzy / structural hash lookups (Phase B) ─────────────────────────
    def lookup_imphash(self, imphash: str) -> list[IntelHash]:
        """Exact imphash match — same import table = same code reuse."""
        h = (imphash or "").lower().strip()
        if not h:
            return []
        return list(self.db.execute(
            select(IntelHash).where(IntelHash.imphash == h)
        ).scalars())

    def lookup_fuzzy(
        self,
        ssdeep_value: str | None = None,
        tlsh_value: str | None = None,
        ssdeep_min_similarity: int = 70,
        tlsh_max_distance: int = 70,
        max_candidates: int = 2000,
    ) -> list[tuple[IntelHash, str, int]]:
        """Return ``(row, kind, score)`` tuples for similar samples.

        ``kind`` is ``"ssdeep"`` (score=similarity 0-100) or ``"tlsh"``
        (score=distance — lower is closer). The DB has no native ssdeep/tlsh
        index, so we cap the candidate set at ``max_candidates`` rows and
        compare in Python. Good enough until corpus passes ~100k samples.
        """
        # Local import — keeps app.intel free of native dep coupling.
        from app.ml.static_v2 import ssdeep_compare, tlsh_distance

        hits: list[tuple[IntelHash, str, int]] = []

        if ssdeep_value:
            rows = list(self.db.execute(
                select(IntelHash)
                .where(IntelHash.ssdeep.is_not(None))
                .limit(max_candidates)
            ).scalars())
            for row in rows:
                sim = ssdeep_compare(ssdeep_value, row.ssdeep or "")
                if sim >= ssdeep_min_similarity:
                    hits.append((row, "ssdeep", sim))

        if tlsh_value:
            rows = list(self.db.execute(
                select(IntelHash)
                .where(IntelHash.tlsh.is_not(None))
                .limit(max_candidates)
            ).scalars())
            for row in rows:
                d = tlsh_distance(tlsh_value, row.tlsh or "")
                if d is not None and d <= tlsh_max_distance:
                    hits.append((row, "tlsh", d))

        return hits

    # ── Indicator ─────────────────────────────────────────────────────────
    def lookup_ip(self, ip: str) -> list[IntelIndicator]:
        return list(self.db.execute(
            select(IntelIndicator).where(
                IntelIndicator.indicator_type == "ip",
                IntelIndicator.value == ip.strip(),
            )
        ).scalars())

    def lookup_domain(self, domain: str) -> list[IntelIndicator]:
        d = domain.strip().lower()
        return list(self.db.execute(
            select(IntelIndicator).where(
                IntelIndicator.indicator_type == "domain",
                IntelIndicator.value == d,
            )
        ).scalars())

    def lookup_url(self, url: str) -> list[IntelIndicator]:
        url = url.strip()
        if not url:
            return []
        # Exact URL match first; fall back to host match (broader signal).
        rows = list(self.db.execute(
            select(IntelIndicator).where(
                IntelIndicator.indicator_type == "url",
                IntelIndicator.value == url,
            )
        ).scalars())
        if rows:
            return rows
        try:
            host = (urlparse(url).hostname or "").lower()
        except Exception:
            host = ""
        if not host:
            return []
        return self.lookup_domain(host)

    def lookup_indicator(self, value: str) -> list[IntelIndicator]:
        """Return *every* matching indicator regardless of type — for /lookup."""
        v = value.strip()
        return list(self.db.execute(
            select(IntelIndicator).where(IntelIndicator.value.in_([v, v.lower()]))
        ).scalars())

    # ── Stats ─────────────────────────────────────────────────────────────
    def stats(self) -> dict[str, Any]:
        # Counts per feed
        per_feed_hashes = dict(self.db.execute(
            select(IntelHash.source, func.count()).group_by(IntelHash.source)
        ).all())
        per_feed_indicators = dict(self.db.execute(
            select(IntelIndicator.source, func.count()).group_by(IntelIndicator.source)
        ).all())
        # Last run per feed
        last_runs: dict[str, dict[str, Any]] = {}
        for feed in _all_feed_classes():
            row = self.db.execute(
                select(IntelFeedRun)
                .where(IntelFeedRun.feed == feed.name)
                .order_by(IntelFeedRun.started_at.desc())
                .limit(1)
            ).scalar_one_or_none()
            if row is not None:
                last_runs[feed.name] = {
                    "started_at": row.started_at.isoformat(),
                    "finished_at": row.finished_at.isoformat() if row.finished_at else None,
                    "status": row.status,
                    "ingested": row.ingested,
                    "updated": row.updated,
                    "duration_ms": row.duration_ms,
                    "error": row.error,
                }

        total_hashes = self.db.execute(select(func.count()).select_from(IntelHash)).scalar() or 0
        total_indicators = self.db.execute(
            select(func.count()).select_from(IntelIndicator)
        ).scalar() or 0
        total_yara = self.db.execute(
            select(func.count()).select_from(IntelYaraRule)
        ).scalar() or 0

        return {
            "enabled": settings.intel_enabled,
            "totals": {
                "hashes": total_hashes,
                "indicators": total_indicators,
                "yara_rules": total_yara,
            },
            "per_feed_hashes": per_feed_hashes,
            "per_feed_indicators": per_feed_indicators,
            "last_runs": last_runs,
        }


# ─── Maintenance ───────────────────────────────────────────────────────────
def prune_old_indicators(db: Session) -> int:
    """Delete indicators older than ``intel_retention_days``. Returns row count."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=settings.intel_retention_days)
    res = db.execute(
        delete(IntelIndicator).where(IntelIndicator.last_seen_at < cutoff)
    )
    db.commit()
    return res.rowcount or 0


# ─── One-shot feed runner (called by scheduler) ────────────────────────────
def run_all_feeds_once(only: Iterable[str] | None = None) -> list[dict[str, Any]]:
    """Execute every enabled feed once. Returns per-feed result dicts.

    Each feed runs in its own DB session and any exception is caught inside
    :meth:`Feed.run`, so one bad feed never aborts the others. Safe to call
    from APScheduler or from a manual ``POST /api/intel/refresh``.
    """
    if not settings.intel_enabled:
        log.info("intel.disabled")
        return [{"feed": "*", "status": "skipped", "reason": "intel disabled"}]

    only_set = {s.strip() for s in only} if only else None
    results: list[dict[str, Any]] = []
    for feed_cls in _all_feed_classes():
        if only_set and feed_cls.name not in only_set:
            continue
        try:
            feed = feed_cls(SessionLocal)
            results.append(feed.run())
        except Exception as e:  # noqa: BLE001 — last-line defence
            log.error("intel.feed.crash", feed=feed_cls.name, error=repr(e))
            results.append({"feed": feed_cls.name, "status": "error", "error": repr(e)})

    # Post-run maintenance — best-effort, never raise.
    try:
        with SessionLocal() as db:
            removed = prune_old_indicators(db)
            if removed:
                log.info("intel.pruned", removed=removed)
    except Exception as e:  # noqa: BLE001
        log.warning("intel.prune_failed", error=repr(e))

    return results
