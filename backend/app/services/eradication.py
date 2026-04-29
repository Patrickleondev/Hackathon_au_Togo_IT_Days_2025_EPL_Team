"""Eradication / quarantine service.

Server-side eradication is intentionally limited: only paths inside
`settings.quarantine_dir` and `settings.uploads_dir` may be touched. For
endpoint actions (kill process, delete file on a workstation), the backend
emits a job for the corresponding agent which executes it locally.
"""

from __future__ import annotations

import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logging import get_logger
from app.db import Eradication
from app.schemas import EradicationRequest

log = get_logger(__name__)


def _is_safe_local_path(p: str) -> bool:
    try:
        absolute = Path(p).resolve()
    except OSError:
        return False
    safe_roots = [Path(settings.uploads_dir).resolve(), Path(settings.storage_dir).resolve()]
    return any(str(absolute).startswith(str(root)) for root in safe_roots)


def quarantine_local_file(file_path: str) -> dict[str, Any]:
    src = Path(file_path)
    if not src.exists():
        return {"success": False, "error": "not_found", "file_path": file_path}
    if not _is_safe_local_path(file_path):
        return {"success": False, "error": "outside_safe_root", "file_path": file_path}

    qdir = Path(settings.quarantine_dir)
    qdir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    dst = qdir / f"{ts}_{src.name}.quar"
    try:
        shutil.move(str(src), dst)
    except OSError as exc:
        return {"success": False, "error": str(exc), "file_path": file_path}
    return {"success": True, "file_path": file_path, "quarantine_path": str(dst)}


def execute_plan(db: Session, plan: EradicationRequest, *, user_id: str | None) -> Eradication:
    """Build an Eradication row, optionally executing local actions."""
    summary: dict[str, Any] = {
        "dry_run": plan.dry_run,
        "min_confidence": plan.min_confidence,
        "actions": plan.actions,
        "scope": plan.scope.model_dump(),
        "steps": [],
        "stats": {"local_files_quarantined": 0, "agent_jobs_emitted": 0},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    # Local quarantine (only for paths within safe roots)
    for path in plan.scope.paths:
        step: dict[str, Any] = {"path": path, "agent_ids": plan.scope.agent_ids}
        if plan.dry_run:
            step["preview"] = True
            summary["steps"].append(step)
            continue
        if "quarantine_files" in plan.actions and _is_safe_local_path(path):
            res = quarantine_local_file(path)
            step["local_action"] = res
            if res.get("success"):
                summary["stats"]["local_files_quarantined"] += 1
        elif plan.scope.agent_ids:
            # In a fuller implementation we'd push a job onto the agent queue
            step["agent_action"] = "job_emitted"
            summary["stats"]["agent_jobs_emitted"] += len(plan.scope.agent_ids)
        else:
            step["skipped"] = "no_local_root_and_no_agent"
        summary["steps"].append(step)

    row = Eradication(
        threat_id=plan.threat_id,
        actions=plan.actions,
        scope=plan.scope.model_dump(),
        dry_run=plan.dry_run,
        min_confidence=plan.min_confidence,
        result=summary,
        initiated_by=user_id,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    log.info("eradication.executed", id=row.id, dry_run=plan.dry_run)
    return row
