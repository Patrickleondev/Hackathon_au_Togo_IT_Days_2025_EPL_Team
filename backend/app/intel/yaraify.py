"""YARAify (abuse.ch) — community YARA rules.

API: https://yaraify.abuse.ch/api/

Strategy: pull the list of *recently shared* rules and, for each new rule we
don't have, fetch its full content. Persist deduplicated by sha256 of content.

We do NOT auto-compile fetched rules into the live detector here — that lives
in :mod:`app.ml.detector` and is gated by an explicit reload call so an
operator can review what showed up before it changes detection behaviour.
"""

from __future__ import annotations

import hashlib
from typing import Any

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logging import get_logger
from app.intel.base import Feed, HttpClient, upsert_yara_rule

log = get_logger(__name__)

API_URL = "https://yaraify-api.abuse.ch/api/v1/"


class YaraifyFeed(Feed):
    name = "yaraify"

    def is_enabled(self) -> bool:
        return settings.intel_yaraify_enabled and bool(settings.abuse_ch_auth_key)

    def fetch(self, db: Session) -> tuple[int, int]:
        with HttpClient() as http:
            # 1) list recent rules
            r = http.request(
                "POST",
                API_URL,
                headers={"Auth-Key": settings.abuse_ch_auth_key},
                json={"query": "recent_yararules"},
            )
            payload = r.json()
            if payload.get("query_status") != "ok":
                log.warning("intel.yaraify.bad_status", status=payload.get("query_status"))
                return (0, 0)

            inserted = 0
            cap = min(50, settings.intel_max_rows_per_feed)  # rate-limit our outbound
            seen_count = 0
            for entry in payload.get("data", []):
                if seen_count >= cap:
                    break
                rule_uuid = entry.get("yarahub_uuid") or entry.get("rule_uuid")
                rule_name = entry.get("rule_name") or "unknown_rule"
                if not rule_uuid:
                    continue
                seen_count += 1

                # 2) fetch content for this rule
                try:
                    cr = http.request(
                        "POST",
                        API_URL,
                        headers={"Auth-Key": settings.abuse_ch_auth_key},
                        json={"query": "get_yara", "search_term": rule_uuid},
                    )
                    cpayload = cr.json()
                except Exception as e:  # noqa: BLE001
                    log.warning("intel.yaraify.rule_fetch_failed", uuid=rule_uuid, error=str(e))
                    continue
                if cpayload.get("query_status") != "ok":
                    continue
                rules_data = cpayload.get("data") or []
                if not rules_data:
                    continue
                content = rules_data[0].get("yara_rule")
                if not content or not isinstance(content, str):
                    continue
                sha = hashlib.sha256(content.encode("utf-8")).hexdigest()
                if upsert_yara_rule(
                    db,
                    rule_name=rule_name,
                    content=content,
                    sha256=sha,
                    source=self.name,
                    author=entry.get("author"),
                    description=entry.get("description"),
                ):
                    inserted += 1
        return (inserted, 0)
