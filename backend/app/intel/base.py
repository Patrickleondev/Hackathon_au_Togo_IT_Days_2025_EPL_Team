"""Common building blocks for all TI feed clients."""

from __future__ import annotations

import abc
import time
from collections.abc import Iterable
from datetime import datetime, timezone
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session
from tenacity import (
    RetryError,
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from app.core.config import settings
from app.core.logging import get_logger
from app.db.models import (
    IntelFeedRun,
    IntelHash,
    IntelIndicator,
    IntelYaraRule,
)

log = get_logger(__name__)


# ─── HTTP ──────────────────────────────────────────────────────────────────
class HttpClient:
    """Thin wrapper around httpx with retry + sane defaults.

    Used instead of letting each feed instantiate its own client so we can
    enforce a single User-Agent and a single timeout policy across the codebase.
    """

    USER_AGENT = "GuardIAn-Intel/1.0 (+https://github.com/Patrickleondev/GuardIAn)"

    def __init__(self, timeout: float | None = None) -> None:
        self._client = httpx.Client(
            timeout=timeout or settings.intel_http_timeout_seconds,
            headers={"User-Agent": self.USER_AGENT},
            follow_redirects=True,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> HttpClient:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    @retry(
        reraise=True,
        retry=retry_if_exception_type((httpx.TransportError, httpx.HTTPStatusError)),
        stop=stop_after_attempt(settings.intel_http_max_retries),
        wait=wait_exponential(multiplier=1, min=2, max=10),
    )
    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
        expected_status: tuple[int, ...] = (200,),
    ) -> httpx.Response:
        r = self._client.request(method, url, headers=headers, params=params, data=data, json=json)
        # Treat 429 / 5xx as retryable; everything else passes through.
        if r.status_code in (429, 500, 502, 503, 504):
            raise httpx.HTTPStatusError(f"retryable status {r.status_code}", request=r.request, response=r)
        if r.status_code not in expected_status:
            raise httpx.HTTPStatusError(
                f"unexpected status {r.status_code}: {r.text[:200]}",
                request=r.request,
                response=r,
            )
        return r


# ─── Feed base class ───────────────────────────────────────────────────────
class Feed(abc.ABC):
    """Abstract feed. Subclasses implement :meth:`fetch` and persist via helpers."""

    #: Short stable identifier used in DB rows + logs (e.g. "malware_bazaar").
    name: str = ""
    #: True when no API key is required (saves an env-var check on each run).
    keyless: bool = False

    def __init__(self, db_session_factory) -> None:  # noqa: ANN001
        self._db_session_factory = db_session_factory

    # ── interface ──────────────────────────────────────────────────────────
    @abc.abstractmethod
    def fetch(self, db: Session) -> tuple[int, int]:
        """Pull data from the remote feed and persist it.

        Returns
        -------
        (ingested, updated): rows newly inserted, rows updated (best-effort).
        """

    def is_enabled(self) -> bool:
        """Per-feed gate. Subclasses override with their own settings flag."""
        return True

    # ── orchestration helper ───────────────────────────────────────────────
    def run(self) -> dict[str, Any]:
        """Execute :meth:`fetch` inside a fresh DB session and audit-log it."""
        if not settings.intel_enabled:
            return {"feed": self.name, "status": "skipped", "reason": "intel disabled"}
        if not self.is_enabled():
            return {"feed": self.name, "status": "skipped", "reason": "feed disabled"}

        started = datetime.now(timezone.utc)
        t0 = time.perf_counter()
        ingested, updated, status, err = 0, 0, "ok", None

        with self._db_session_factory() as db:
            try:
                ingested, updated = self.fetch(db)
            except RetryError as e:  # tenacity wraps the original
                status, err = "error", f"retry exhausted: {e.last_attempt.exception()!r}"
                log.warning("intel.feed.failed", feed=self.name, error=err)
            except Exception as e:  # noqa: BLE001 — feed errors must never crash the scheduler
                status, err = "error", repr(e)
                log.warning("intel.feed.failed", feed=self.name, error=err)

            run = IntelFeedRun(
                feed=self.name,
                started_at=started,
                finished_at=datetime.now(timezone.utc),
                status=status,
                ingested=ingested,
                updated=updated,
                error=err,
                duration_ms=int((time.perf_counter() - t0) * 1000),
            )
            db.add(run)
            db.commit()

        return {
            "feed": self.name,
            "status": status,
            "ingested": ingested,
            "updated": updated,
            "duration_ms": int((time.perf_counter() - t0) * 1000),
            "error": err,
        }


# ─── Persistence helpers ───────────────────────────────────────────────────
def upsert_hashes(db: Session, rows: Iterable[dict[str, Any]], source: str) -> tuple[int, int]:
    """Idempotent upsert keyed on (sha256). Returns (inserted, updated)."""
    inserted, updated = 0, 0
    for row in rows:
        sha256 = (row.get("sha256") or "").lower().strip()
        if len(sha256) != 64:
            continue
        existing = db.execute(select(IntelHash).where(IntelHash.sha256 == sha256)).scalar_one_or_none()
        if existing is None:
            db.add(IntelHash(
                sha256=sha256,
                sha1=(row.get("sha1") or None),
                md5=(row.get("md5") or None),
                imphash=(row.get("imphash") or None),
                ssdeep=(row.get("ssdeep") or None),
                tlsh=(row.get("tlsh") or None),
                file_type=(row.get("file_type") or None),
                file_size=row.get("file_size"),
                signature=(row.get("signature") or None),
                family=(row.get("family") or None),
                tags=row.get("tags") or [],
                source=source,
                confidence=float(row.get("confidence", 1.0)),
                first_seen_at=row.get("first_seen_at"),
                last_seen_at=row.get("last_seen_at") or datetime.now(timezone.utc),
                extra=row.get("extra") or {},
            ))
            inserted += 1
        else:
            existing.last_seen_at = row.get("last_seen_at") or datetime.now(timezone.utc)
            if row.get("family") and not existing.family:
                existing.family = row["family"]
            if row.get("tags"):
                existing.tags = sorted(set((existing.tags or []) + row["tags"]))
            updated += 1
    db.commit()
    return inserted, updated


def upsert_indicators(db: Session, rows: Iterable[dict[str, Any]], source: str) -> tuple[int, int]:
    """Upsert keyed on (indicator_type, value, source)."""
    inserted, updated = 0, 0
    for row in rows:
        itype = row.get("indicator_type")
        value = (row.get("value") or "").strip()
        if not itype or not value:
            continue
        existing = db.execute(
            select(IntelIndicator).where(
                IntelIndicator.indicator_type == itype,
                IntelIndicator.value == value,
                IntelIndicator.source == source,
            )
        ).scalar_one_or_none()
        if existing is None:
            db.add(IntelIndicator(
                indicator_type=itype,
                value=value,
                family=(row.get("family") or None),
                threat_type=(row.get("threat_type") or None),
                source=source,
                confidence=float(row.get("confidence", 1.0)),
                attack_techniques=row.get("attack_techniques") or [],
                tags=row.get("tags") or [],
                first_seen_at=row.get("first_seen_at"),
                last_seen_at=row.get("last_seen_at") or datetime.now(timezone.utc),
                extra=row.get("extra") or {},
            ))
            inserted += 1
        else:
            existing.last_seen_at = row.get("last_seen_at") or datetime.now(timezone.utc)
            if row.get("family") and not existing.family:
                existing.family = row["family"]
            updated += 1
    db.commit()
    return inserted, updated


def upsert_yara_rule(db: Session, rule_name: str, content: str, sha256: str, source: str,
                    author: str | None = None, description: str | None = None) -> bool:
    """Insert a YARA rule if its sha256 is new. Returns True if inserted."""
    existing = db.execute(
        select(IntelYaraRule).where(IntelYaraRule.sha256 == sha256)
    ).scalar_one_or_none()
    if existing is not None:
        return False
    db.add(IntelYaraRule(
        rule_name=rule_name,
        source=source,
        sha256=sha256,
        content=content,
        author=author,
        description=description,
        added_at=datetime.now(timezone.utc),
    ))
    db.commit()
    return True
