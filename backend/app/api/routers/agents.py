"""Agent enrollment, heartbeat, and listing."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import create_agent_token, require_agent, require_user
from app.db import Agent, get_db
from app.schemas import AgentEnrollRequest, AgentEnrollResponse, AgentHeartbeat, AgentOut
from app.services.bootstrap import new_enrollment_token

router = APIRouter(prefix="/agents", tags=["agents"])


@router.post("/enroll", response_model=AgentEnrollResponse)
def enroll(payload: AgentEnrollRequest, db: Session = Depends(get_db)) -> AgentEnrollResponse:
    """Open endpoint — in production it should be protected by an enrollment secret."""
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
