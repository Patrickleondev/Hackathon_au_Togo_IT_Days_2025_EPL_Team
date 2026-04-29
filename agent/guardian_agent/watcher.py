"""File-system watcher using watchdog."""

from __future__ import annotations

import logging
from pathlib import Path
from queue import Queue
from typing import Iterable

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

log = logging.getLogger(__name__)


class _Handler(FileSystemEventHandler):
    def __init__(self, queue: Queue) -> None:
        self.queue = queue

    def on_created(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self.queue.put(Path(event.src_path))

    def on_modified(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self.queue.put(Path(event.src_path))


class FileWatcher:
    def __init__(self, paths: Iterable[str], queue: Queue) -> None:
        self.paths = [Path(p) for p in paths]
        self.queue = queue
        self.observer = Observer()

    def start(self) -> None:
        handler = _Handler(self.queue)
        for p in self.paths:
            if p.exists():
                self.observer.schedule(handler, str(p), recursive=True)
                log.info("Watching %s", p)
            else:
                log.warning("Path %s does not exist, skipping", p)
        self.observer.start()

    def stop(self) -> None:
        self.observer.stop()
        self.observer.join(timeout=5)
