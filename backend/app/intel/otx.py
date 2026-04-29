"""AlienVault OTX — community pulses (curated IOC bundles).

API: https://otx.alienvault.com/api

Strategy: pull the user's *subscribed* pulses (cheap) and ingest each pulse's
indicators. A pulse already groups indicators by campaign / actor, so
``family`` is naturally populated from ``pulse.name``.
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

API_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"
PAGE_SIZE = 50
MAX_PAGES = 4  # 200 most recent pulses is plenty per refresh


class OTXFeed(Feed):
    name = "otx"

    def is_enabled(self) -> bool:
        return settings.intel_otx_enabled and bool(settings.otx_api_key)

    def fetch(self, db: Session) -> tuple[int, int]:
        ind_rows: list[dict[str, Any]] = []
        hash_rows: list[dict[str, Any]] = []
        with HttpClient() as http:
            for page in range(1, MAX_PAGES + 1):
                r = http.request(
                    "GET",
                    API_URL,
                    headers={"X-OTX-API-KEY": settings.otx_api_key},
                    params={"page": page, "limit": PAGE_SIZE},
                )
                payload = r.json()
                results = payload.get("results") or []
                if not results:
                    break
                for pulse in results:
                    family = (pulse.get("name") or "").strip() or None
                    tags = [t for t in (pulse.get("tags") or []) if t]
                    attack = list(pulse.get("attack_ids") or [])
                    created = _safe_dt(pulse.get("created"))
                    for ind in pulse.get("indicators") or []:
                        _route_indicator(ind, family, tags, attack, created, ind_rows, hash_rows)
                if len(results) < PAGE_SIZE:
                    break

        h_in, h_up = upsert_hashes(db, hash_rows, source=self.name)
        i_in, i_up = upsert_indicators(db, ind_rows, source=self.name)
        return (h_in + i_in, h_up + i_up)


def _route_indicator(
    ind: dict[str, Any],
    family: str | None,
    tags: list[str],
    attack: list[str],
    created: datetime | None,
    ind_rows: list[dict[str, Any]],
    hash_rows: list[dict[str, Any]],
) -> None:
    itype = (ind.get("type") or "").strip()
    value = (ind.get("indicator") or "").strip()
    if not itype or not value:
        return

    extra = {"otx_id": ind.get("id"), "description": ind.get("description")}
    if itype == "FileHash-SHA256":
        hash_rows.append({
            "sha256": value.lower(),
            "family": family,
            "tags": tags,
            "first_seen_at": created,
            "extra": extra,
        })
    elif itype == "URL":
        ind_rows.append({
            "indicator_type": "url",
            "value": value,
            "family": family,
            "attack_techniques": attack,
            "tags": tags,
            "first_seen_at": created,
            "extra": extra,
        })
    elif itype in ("domain", "hostname"):
        ind_rows.append({
            "indicator_type": "domain",
            "value": value.lower(),
            "family": family,
            "attack_techniques": attack,
            "tags": tags,
            "first_seen_at": created,
            "extra": extra,
        })
    elif itype in ("IPv4", "IPv6"):
        ind_rows.append({
            "indicator_type": "ip",
            "value": value,
            "family": family,
            "attack_techniques": attack,
            "tags": tags,
            "first_seen_at": created,
            "extra": extra,
        })
    elif itype == "CIDR":
        ind_rows.append({
            "indicator_type": "cidr",
            "value": value,
            "family": family,
            "attack_techniques": attack,
            "tags": tags,
            "first_seen_at": created,
            "extra": extra,
        })


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
