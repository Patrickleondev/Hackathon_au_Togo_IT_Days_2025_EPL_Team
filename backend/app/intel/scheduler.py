"""APScheduler integration — recurring TI feed refresh.

Lives outside :mod:`service` so it can be started/stopped from the FastAPI
lifespan without pulling in the heavy feed clients during simple lookups.
"""

from __future__ import annotations

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

from app.core.config import settings
from app.core.logging import get_logger
from app.intel.service import run_all_feeds_once

log = get_logger(__name__)

_scheduler: BackgroundScheduler | None = None


def start_scheduler() -> BackgroundScheduler | None:
    """Start the background scheduler. Idempotent. Returns the scheduler or None."""
    global _scheduler
    if not settings.intel_enabled:
        log.info("intel.scheduler.disabled")
        return None
    if _scheduler is not None:
        return _scheduler

    sched = BackgroundScheduler(daemon=True, timezone="UTC")
    interval = max(1, settings.intel_update_interval_hours)

    sched.add_job(
        _safe_run,
        trigger=IntervalTrigger(hours=interval),
        id="intel_refresh_all",
        name="Refresh every TI feed",
        coalesce=True,
        max_instances=1,
        misfire_grace_time=60 * 30,  # 30 min
        replace_existing=True,
    )

    # Optional: kick a first run shortly after startup so the DB is non-empty
    # without making the API container's startup hang on network calls.
    sched.add_job(
        _safe_run,
        id="intel_initial_refresh",
        name="Initial TI refresh",
        next_run_time=None,  # disabled by default; set to <datetime> if desired
        replace_existing=True,
    )

    sched.start()
    _scheduler = sched
    log.info("intel.scheduler.started", interval_hours=interval)
    return sched


def stop_scheduler() -> None:
    global _scheduler
    if _scheduler is not None:
        try:
            _scheduler.shutdown(wait=False)
        except Exception as e:  # noqa: BLE001
            log.warning("intel.scheduler.shutdown_failed", error=repr(e))
        _scheduler = None


def _safe_run() -> None:
    try:
        results = run_all_feeds_once()
        log.info("intel.refresh.done", count=len(results))
    except Exception as e:  # noqa: BLE001 — must never bring down the scheduler thread
        log.error("intel.refresh.crash", error=repr(e))
