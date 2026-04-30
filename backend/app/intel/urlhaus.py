"""URLhaus (abuse.ch) feed client — malicious URLs distributing malware.

API: https://urlhaus.abuse.ch/api/

We use the JSON ``urls/recent/`` endpoint (last 1000 URLs added in the past
3 days). Each URL is stored as an :class:`IntelIndicator` with ``indicator_type``
``"url"``. We *also* extract the host and persist it as a ``"domain"`` indicator
so DNS-only matchers (e.g. an agent with sniffing) can find it.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from dateutil import parser as dateparser
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logging import get_logger
from app.intel.base import Feed, HttpClient, upsert_indicators

log = get_logger(__name__)

API_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/"


class URLhausFeed(Feed):
    name = "urlhaus"

    def is_enabled(self) -> bool:
        return settings.intel_urlhaus_enabled and bool(settings.abuse_ch_auth_key)

    def fetch(self, db: Session) -> tuple[int, int]:
        with HttpClient() as http:
            r = http.request(
                "POST",
                API_URL,
                headers={"Auth-Key": settings.abuse_ch_auth_key},
            )
        payload = r.json()
        if payload.get("query_status") != "ok":
            log.warning("intel.urlhaus.bad_status", status=payload.get("query_status"))
            return (0, 0)

        rows: list[dict[str, Any]] = []
        for entry in payload.get("urls", [])[: settings.intel_max_rows_per_feed]:
            url = entry.get("url")
            if not url:
                continue
            first_seen = _safe_dt(entry.get("date_added"))
            tags = [t for t in (entry.get("tags") or []) if t]
            family = (entry.get("threat") or "").strip() or None
            base_extra = {
                "url_status": entry.get("url_status"),
                "host": entry.get("host"),
                "reporter": entry.get("reporter"),
                "urlhaus_reference": entry.get("urlhaus_reference"),
            }
            rows.append({
                "indicator_type": "url",
                "value": url,
                "family": family,
                "threat_type": "malware_distribution",
                "tags": tags,
                "first_seen_at": first_seen,
                "extra": base_extra,
            })
            # Also persist the host so a DNS-level matcher can hit.
            host = (entry.get("host") or _host_of(url) or "").strip()
            if host and not _is_ipv4(host):
                rows.append({
                    "indicator_type": "domain",
                    "value": host.lower(),
                    "family": family,
                    "threat_type": "malware_distribution",
                    "tags": tags,
                    "first_seen_at": first_seen,
                    "extra": {"derived_from_url": url},
                })
            elif host and _is_ipv4(host):
                rows.append({
                    "indicator_type": "ip",
                    "value": host,
                    "family": family,
                    "threat_type": "malware_distribution",
                    "tags": tags,
                    "first_seen_at": first_seen,
                    "extra": {"derived_from_url": url},
                })
        return upsert_indicators(db, rows, source=self.name)


def _host_of(url: str) -> str | None:
    try:
        return urlparse(url).hostname
    except Exception:
        return None


def _is_ipv4(s: str) -> bool:
    parts = s.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


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
