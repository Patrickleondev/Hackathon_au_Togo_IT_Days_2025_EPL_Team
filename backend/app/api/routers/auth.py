"""Authentication router."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import (
    create_access_token,
    require_user,
    verify_password,
)
from app.db import User, get_db
from app.schemas import TokenResponse, UserOut

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse)
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)) -> TokenResponse:
    user = db.scalar(select(User).where(User.email == form.username))
    if user is None or not verify_password(form.password, user.password_hash) or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user.last_login_at = datetime.now(timezone.utc)
    db.commit()

    token = create_access_token(subject=user.id, scope="user", extra={"role": user.role})
    return TokenResponse(
        access_token=token,
        expires_in=settings.jwt_access_ttl_minutes * 60,
        user=UserOut.model_validate(user),
    )


@router.get("/me", response_model=UserOut)
def me(claims: dict = Depends(require_user), db: Session = Depends(get_db)) -> UserOut:
    user = db.get(User, claims["sub"])
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return UserOut.model_validate(user)
