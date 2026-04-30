"""Eradication router."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.core.security import require_user
from app.db import Eradication, get_db
from app.schemas import EradicationOut, EradicationRequest
from app.services.eradication import execute_plan

router = APIRouter(prefix="/eradications", tags=["eradication"])


@router.post("", response_model=EradicationOut, status_code=201)
def create(
    plan: EradicationRequest,
    user: dict = Depends(require_user),
    db: Session = Depends(get_db),
) -> EradicationOut:
    row = execute_plan(db, plan, user_id=user["sub"])
    return EradicationOut.model_validate(row)


@router.get("", response_model=list[EradicationOut])
def list_(
    limit: int = 50,
    _user: dict = Depends(require_user),
    db: Session = Depends(get_db),
) -> list[EradicationOut]:
    rows = db.scalars(select(Eradication).order_by(desc(Eradication.created_at)).limit(limit))
    return [EradicationOut.model_validate(r) for r in rows]
