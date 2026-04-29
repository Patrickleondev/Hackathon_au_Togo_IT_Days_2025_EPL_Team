"""RQ worker entrypoint.

Usage (inside the container):
    rq worker --url $REDIS_URL ransomguard

Tasks live in app.workers.tasks.
"""

from __future__ import annotations

import os
import sys

from redis import Redis
from rq import Connection, Queue, Worker

from app.core.config import settings
from app.core.logging import configure_logging, get_logger


def main() -> int:
    configure_logging()
    log = get_logger(__name__)
    redis = Redis.from_url(settings.redis_url)
    log.info("worker.start", redis=settings.redis_url)
    with Connection(redis):
        worker = Worker([Queue("ransomguard")])
        worker.work(with_scheduler=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
