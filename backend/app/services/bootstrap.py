"""DB bootstrap helpers (create tables + seed admin)."""

from __future__ import annotations

import secrets

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logging import get_logger
from app.core.security import hash_password
from app.db import Agent, Base, Role, User, engine

log = get_logger(__name__)


def init_db(db: Session) -> None:
    """Create tables (if not yet handled by Alembic) and seed default admin."""
    Base.metadata.create_all(bind=engine)

    existing = db.scalar(select(User).where(User.email == settings.bootstrap_admin_email))
    if not existing:
        admin = User(
            email=settings.bootstrap_admin_email,
            password_hash=hash_password(settings.bootstrap_admin_password),
            role=Role.ADMIN,
            is_active=True,
        )
        db.add(admin)
        db.commit()
        log.warning(
            "auth.bootstrap.admin_created",
            email=settings.bootstrap_admin_email,
            password_hint="see BOOTSTRAP_ADMIN_PASSWORD env (change immediately)",
        )


def new_enrollment_token() -> str:
    return secrets.token_urlsafe(32)


def ensure_demo_agent(db: Session) -> Agent | None:
    """Create a single demo agent in dev so the dashboard is not empty."""
    if settings.app_env != "dev":
        return None
    existing = db.scalar(select(Agent).where(Agent.hostname == "demo-host"))
    if existing:
        return existing
    agent = Agent(
        hostname="demo-host",
        os="Windows",
        os_version="10.0.19045",
        agent_version="2.0.0",
        enrollment_token=new_enrollment_token(),
    )
    db.add(agent)
    db.commit()
    db.refresh(agent)
    log.info("dev.demo_agent_created", agent_id=agent.id)
    return agent
