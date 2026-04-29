"""ThreatFox (abuse.ch) — IOCs (IP, domain, URL, hash) tagged with MITRE ATT&CK.

API: https://threatfox.abuse.ch/api/

We pull the last 3 days via ``get_iocs`` and route entries by IOC type:
  * ``url`` / ``domain`` / ``ip:port`` → IntelIndicator
  * ``sha256_hash`` / ``md5_hash`` / ``sha1_hash`` → IntelHash

ThreatFox provides ``malware`` (family) and ``confidence_level`` for every IOC,
which is gold for the detector.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from dateutil import parser as dateparser
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logging import get_logger
from app.intel.base import Feed, HttpClient, upsert_hashes, upsert_indicators

log = get_logger(__name__)

API_URL = "https://threatfox-api.abuse.ch/api/v1/"


class ThreatFoxFeed(Feed):
    name = "threatfox"

    def is_enabled(self) -> bool:
        return settings.intel_threatfox_enabled and bool(settings.abuse_ch_auth_key)

    def fetch(self, db: Session) -> tuple[int, int]:
        with HttpClient() as http:
            r = http.request(
                "POST",
                API_URL,
                headers={"Auth-Key": settings.abuse_ch_auth_key},
                json={"query": "get_iocs", "days": 3},
            )
        payload = r.json()
        if payload.get("query_status") != "ok":
            log.warning("intel.threatfox.bad_status", status=payload.get("query_status"))
            return (0, 0)

        hash_rows: list[dict[str, Any]] = []
        ind_rows: list[dict[str, Any]] = []
        cap = settings.intel_max_rows_per_feed
        for entry in (payload.get("data") or [])[:cap]:
            ioc = (entry.get("ioc") or "").strip()
            ioc_type = (entry.get("ioc_type") or "").strip().lower()
            if not ioc or not ioc_type:
                continue
            family = (entry.get("malware") or "").strip() or None
            confidence = float(entry.get("confidence_level") or 50) / 100.0
            first_seen = _safe_dt(entry.get("first_seen"))
            last_seen = _safe_dt(entry.get("last_seen"))
            tags = [t for t in (entry.get("tags") or []) if t]
            attack = []
            if entry.get("malware_alias"):
                tags.append(f"alias:{entry['malware_alias']}")
            if entry.get("threat_type"):
                tags.append(f"threat:{entry['threat_type']}")

            extra = {
                "ioc_type": ioc_type,
                "threat_type": entry.get("threat_type"),
                "malware_alias": entry.get("malware_alias"),
                "malware_printable": entry.get("malware_printable"),
                "reporter": entry.get("reporter"),
                "reference": entry.get("reference"),
            }

            if ioc_type in ("md5_hash", "sha1_hash", "sha256_hash"):
                # Build a hash row — try to populate the right column.
                row = {
                    "sha256": ioc if ioc_type == "sha256_hash" else None,
                    "sha1": ioc if ioc_type == "sha1_hash" else None,
                    "md5": ioc if ioc_type == "md5_hash" else None,
                    "family": family,
                    "tags": tags,
                    "confidence": confidence,
                    "first_seen_at": first_seen,
                    "last_seen_at": last_seen,
                    "extra": extra,
                }
                if not row["sha256"]:
                    # We only persist when we have a sha256 (primary key in our DB).
                    # md5/sha1-only rows get logged for completeness but skipped.
                    continue
                hash_rows.append(row)
            else:
                itype = _normalize_ioc_type(ioc_type)
                if itype is None:
                    continue
                value = ioc
                if itype == "ip" and ":" in value:
                    value = value.split(":", 1)[0]  # strip :port
                ind_rows.append({
                    "indicator_type": itype,
                    "value": value.lower() if itype == "domain" else value,
                    "family": family,
                    "threat_type": entry.get("threat_type"),
                    "confidence": confidence,
                    "attack_techniques": attack,
                    "tags": tags,
                    "first_seen_at": first_seen,
                    "last_seen_at": last_seen,
                    "extra": extra,
                })

        h_in, h_up = upsert_hashes(db, hash_rows, source=self.name)
        i_in, i_up = upsert_indicators(db, ind_rows, source=self.name)
        return (h_in + i_in, h_up + i_up)


_TYPE_MAP = {
    "url": "url",
    "domain": "domain",
    "ip:port": "ip",
    "ip": "ip",
    "ipv4": "ip",
    "ipv6": "ip",
}


def _normalize_ioc_type(t: str) -> str | None:
    return _TYPE_MAP.get(t)


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
