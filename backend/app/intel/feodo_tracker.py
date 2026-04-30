"""Feodo Tracker (abuse.ch) — botnet C2 IPs (Emotet, TrickBot, Dridex, QakBot, …).

Public JSON: https://feodotracker.abuse.ch/downloads/ipblocklist.json

This endpoint does not require an Auth-Key; we still send it if present so
abuse.ch can rate-limit us as a known consumer.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from dateutil import parser as dateparser
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logging import get_logger
from app.intel.base import Feed, HttpClient, upsert_indicators

log = get_logger(__name__)

API_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"


class FeodoTrackerFeed(Feed):
    name = "feodo_tracker"
    keyless = True  # works even without abuse_ch_auth_key

    def is_enabled(self) -> bool:
        return settings.intel_feodo_enabled

    def fetch(self, db: Session) -> tuple[int, int]:
        headers = {}
        if settings.abuse_ch_auth_key:
            headers["Auth-Key"] = settings.abuse_ch_auth_key
        with HttpClient() as http:
            r = http.request("GET", API_URL, headers=headers or None)
        try:
            data = r.json()
        except ValueError:
            log.warning("intel.feodo.invalid_json")
            return (0, 0)

        rows: list[dict[str, Any]] = []
        for entry in (data or [])[: settings.intel_max_rows_per_feed]:
            ip = (entry.get("ip_address") or "").strip()
            if not ip:
                continue
            family = (entry.get("malware") or "").strip() or None
            first_seen = _safe_dt(entry.get("first_seen"))
            last_online = _safe_dt(entry.get("last_online"))
            rows.append({
                "indicator_type": "ip",
                "value": ip,
                "family": family,
                "threat_type": "botnet_c2",
                "tags": [t for t in [family, "c2"] if t],
                "confidence": 1.0,
                "first_seen_at": first_seen,
                "last_seen_at": last_online,
                "extra": {
                    "port": entry.get("port"),
                    "status": entry.get("status"),
                    "as_number": entry.get("as_number"),
                    "as_name": entry.get("as_name"),
                    "country": entry.get("country"),
                    "hostname": entry.get("hostname"),
                },
            })
        return upsert_indicators(db, rows, source=self.name)


def _safe_dt(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        dt = dateparser.parse(str(value))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return None
