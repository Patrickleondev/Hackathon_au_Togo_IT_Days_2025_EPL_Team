"""Agent main loop.

Usage (after enrollment):
    python -m ransomguard_agent --enroll          # registers with the backend
    python -m ransomguard_agent                   # runs the watcher service
"""

from __future__ import annotations

import argparse
import json
import logging
import platform
import socket
import sys
import time
from pathlib import Path
from queue import Empty, Queue
from threading import Thread

import psutil

from ransomguard_agent import __version__
from ransomguard_agent import client as api
from ransomguard_agent.config import settings
from ransomguard_agent.heuristics import is_suspicious
from ransomguard_agent.watcher import FileWatcher

log = logging.getLogger("ransomguard-agent")
STATE_FILE = settings.state_dir / "state.json"


def _save_state(data: dict) -> None:
    settings.state_dir.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(data, indent=2))


def _load_state() -> dict:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except Exception:
            return {}
    return {}


def cmd_enroll() -> int:
    state = _load_state()
    if state.get("token"):
        print("Already enrolled. State:", state.get("agent_id"))
        return 0

    info = api.enroll(
        hostname=socket.gethostname(),
        os_name=platform.system(),
        os_version=platform.release(),
        agent_version=__version__,
    )
    state.update({
        "agent_id": info["agent"]["id"],
        "token": info["token"],
        "backend_url": settings.backend_url,
    })
    _save_state(state)
    settings.token = state["token"]
    settings.agent_id = state["agent_id"]
    print(f"Enrolled as {state['agent_id']}.")
    return 0


def _heartbeat_loop() -> None:
    while True:
        try:
            api.heartbeat({
                "cpu": psutil.cpu_percent(interval=None),
                "memory": psutil.virtual_memory().percent,
                "uptime_s": int(time.time() - psutil.boot_time()),
            })
        except Exception as exc:
            log.warning("heartbeat failed: %s", exc)
        time.sleep(settings.heartbeat_sec)


def cmd_run() -> int:
    state = _load_state()
    if not state.get("token"):
        print("Agent not enrolled. Run with --enroll first.", file=sys.stderr)
        return 1
    settings.token = state["token"]
    settings.agent_id = state["agent_id"]

    watch_paths = settings.watch_paths or [str(Path.home())]
    queue: Queue = Queue(maxsize=10000)
    watcher = FileWatcher(watch_paths, queue)
    watcher.start()

    Thread(target=_heartbeat_loop, daemon=True).start()
    log.info("Agent %s running. Watching: %s", settings.agent_id, watch_paths)

    try:
        while True:
            try:
                path: Path = queue.get(timeout=1)
            except Empty:
                continue
            if not path.is_file():
                continue
            try:
                suspicious, reason = is_suspicious(path)
            except Exception:
                continue
            if not suspicious:
                continue
            try:
                size = path.stat().st_size
                if size > settings.upload_max_mb * 1024 * 1024:
                    continue
                result = api.upload_file(path)
                log.info("uploaded %s (%s) → threat=%s severity=%s",
                         path, reason, result.get("is_threat"), result.get("severity"))
            except Exception as exc:
                log.warning("upload failed for %s: %s", path, exc)
    except KeyboardInterrupt:
        pass
    finally:
        watcher.stop()
    return 0


def main() -> int:
    logging.basicConfig(
        level=settings.log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    parser = argparse.ArgumentParser("ransomguard-agent")
    parser.add_argument("--enroll", action="store_true", help="Register this host with the backend")
    args = parser.parse_args()

    if args.enroll:
        return cmd_enroll()
    return cmd_run()


if __name__ == "__main__":
    sys.exit(main())
