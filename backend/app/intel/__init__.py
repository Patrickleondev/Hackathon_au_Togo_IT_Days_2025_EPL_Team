"""Threat-intelligence ingestion subsystem.

This package fetches indicators from external feeds (abuse.ch, AbuseIPDB,
AlienVault OTX) on a recurring schedule and persists them in the local DB
so the detector can do O(1) hash / IP / domain / URL lookups offline.

Design goals
------------
* Each feed is an independent class implementing :class:`base.Feed`.
* No feed can take down the others — failures are isolated and logged.
* All HTTP I/O goes through :class:`base.HttpClient` (retries, timeout, UA).
* All persistence goes through :func:`base.upsert_*` helpers (idempotent).
* The scheduler (``intel.scheduler``) is the only place that triggers runs.
"""

from app.intel.service import IntelService, run_all_feeds_once

__all__ = ["IntelService", "run_all_feeds_once"]
