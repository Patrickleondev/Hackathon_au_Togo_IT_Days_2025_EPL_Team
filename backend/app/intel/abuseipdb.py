"""AbuseIPDB — IP reputation feed.

API: https://docs.abuseipdb.com/

Free tier: 1000 lookups/day. We do NOT do per-IP lookups on a schedule
(that would burn quota); instead we pull the bulk *blocklist* once per cycle.
This returns the most reported IPs above a confidence threshold.
"""

from __future__ import annotations

from datetime import datetime, timezone

from dateutil import parser as dateparser
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logging import get_logger
from app.intel.base import Feed, HttpClient, upsert_indicators

log = get_logger(__name__)

API_URL = "https://api.abuseipdb.com/api/v2/blacklist"
CONFIDENCE_MIN = 90  # only pull high-confidence reports


class AbuseIPDBFeed(Feed):
    name = "abuseipdb"

    def is_enabled(self) -> bool:
        return settings.intel_abuseipdb_enabled and bool(settings.abuseipdb_api_key)

    def fetch(self, db: Session) -> tuple[int, int]:
        with HttpClient() as http:
            r = http.request(
                "GET",
                API_URL,
                headers={
                    "Key": settings.abuseipdb_api_key,
                    "Accept": "application/json",
                },
                params={"confidenceMinimum": CONFIDENCE_MIN, "limit": 10000},
            )
        payload = r.json()
        if "data" not in payload:
            log.warning("intel.abuseipdb.bad_payload", body=str(payload)[:200])
            return (0, 0)

        rows = []
        for entry in payload["data"][: settings.intel_max_rows_per_feed]:
            ip = (entry.get("ipAddress") or "").strip()
            if not ip:
                continue
            last = entry.get("lastReportedAt")
            try:
                last_dt = dateparser.parse(last) if last else None
                if last_dt and last_dt.tzinfo is None:
                    last_dt = last_dt.replace(tzinfo=timezone.utc)
            except (ValueError, TypeError):
                last_dt = None
            score = float(entry.get("abuseConfidenceScore", CONFIDENCE_MIN)) / 100.0
            rows.append({
                "indicator_type": "ip",
                "value": ip,
                "threat_type": "abusive_reporter_aggregate",
                "confidence": score,
                "tags": ["abuseipdb"],
                "last_seen_at": last_dt or datetime.now(timezone.utc),
                "extra": {
                    "country_code": entry.get("countryCode"),
                    "abuse_confidence_score": entry.get("abuseConfidenceScore"),
                },
            })
        return upsert_indicators(db, rows, source=self.name)
