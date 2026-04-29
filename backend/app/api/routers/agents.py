"""Agent enrollment, heartbeat, and listing."""

from __future__ import annotations

import hmac
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import create_agent_token, require_agent, require_user
from app.db import Agent, get_db
from app.schemas import AgentEnrollRequest, AgentEnrollResponse, AgentHeartbeat, AgentOut
from app.services.bootstrap import new_enrollment_token

router = APIRouter(prefix="/agents", tags=["agents"])
logger = logging.getLogger(__name__)


def _verify_enrollment_secret(provided: str | None) -> None:
    """Reject the request unless the provided secret matches settings.agent_enrollment_secret.

    In dev, if the secret is unset on the server, enrollment is allowed with a warning
    to keep the local developer experience smooth. In prod/test the secret is mandatory.
    """
    expected = settings.agent_enrollment_secret
    if not expected:
        if settings.app_env == "dev":
            logger.warning(
                "AGENT_ENROLLMENT_SECRET is not set; allowing enrollment because APP_ENV=dev. "
                "Set AGENT_ENROLLMENT_SECRET before deploying."
            )
            return
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Agent enrollment is disabled (server has no AGENT_ENROLLMENT_SECRET configured).",
        )
    if not provided or not hmac.compare_digest(provided, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing enrollment secret.",
            headers={"WWW-Authenticate": "Bearer"},
        )


@router.post("/enroll", response_model=AgentEnrollResponse)
def enroll(
    payload: AgentEnrollRequest,
    db: Session = Depends(get_db),
    x_enrollment_secret: str | None = Header(default=None, alias="X-Enrollment-Secret"),
) -> AgentEnrollResponse:
    """Register a new agent. Requires the pre-shared `X-Enrollment-Secret` header."""
    _verify_enrollment_secret(x_enrollment_secret)
    agent = Agent(
        hostname=payload.hostname,
        os=payload.os,
        os_version=payload.os_version,
        agent_version=payload.agent_version,
        enrollment_token=new_enrollment_token(),
        metadata_json=payload.metadata,
    )
    db.add(agent)
    db.commit()
    db.refresh(agent)
    token = create_agent_token(agent.id)
    return AgentEnrollResponse(agent=AgentOut.model_validate(agent), token=token)


@router.post("/heartbeat", response_model=AgentOut)
def heartbeat(
    payload: AgentHeartbeat,
    claims: dict = Depends(require_agent),
    db: Session = Depends(get_db),
) -> AgentOut:
    agent = db.get(Agent, claims["sub"])
    if agent is None:
        raise HTTPException(404, "Agent not found")
    agent.last_seen_at = datetime.now(timezone.utc)
    if payload.metrics:
        agent.metadata_json = {**agent.metadata_json, "last_metrics": payload.metrics}
    db.commit()
    db.refresh(agent)
    return AgentOut.model_validate(agent)


@router.get("", response_model=list[AgentOut])
def list_agents(_user: dict = Depends(require_user), db: Session = Depends(get_db)) -> list[AgentOut]:
    rows = db.scalars(select(Agent).order_by(Agent.last_seen_at.desc().nullslast()))
    return [AgentOut.model_validate(a) for a in rows]
