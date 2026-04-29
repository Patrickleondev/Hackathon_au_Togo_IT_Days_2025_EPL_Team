"""FastAPI application factory & ASGI entrypoint."""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routers import agents, analyze, auth, eradication, scans, status, threats
from app.core.config import settings
from app.core.logging import configure_logging, get_logger
from app.db import SessionLocal
from app.ml import get_detector
from app.services.bootstrap import ensure_demo_agent, init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging()
    log = get_logger(__name__)
    log.info("app.startup", env=settings.app_env, version=settings.app_version)

    # Storage dirs
    for d in (settings.storage_dir, settings.uploads_dir, settings.quarantine_dir,
              settings.models_dir, settings.rules_dir):
        Path(d).mkdir(parents=True, exist_ok=True)

    # DB bootstrap (idempotent)
    db = SessionLocal()
    try:
        init_db(db)
        ensure_demo_agent(db)
    finally:
        db.close()

    # Warm the detector (loads model + rules)
    get_detector()

    yield
    log.info("app.shutdown")


def create_app() -> FastAPI:
    app = FastAPI(
        title="GuardIAn API",
        description="Ransomware detection & response — central API.",
        version=settings.app_version,
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Routers
    api = settings.api_prefix
    app.include_router(status.router, prefix=api)
    app.include_router(auth.router, prefix=api)
    app.include_router(agents.router, prefix=api)
    app.include_router(threats.router, prefix=api)
    app.include_router(scans.router, prefix=api)
    app.include_router(analyze.router, prefix=api)
    app.include_router(eradication.router, prefix=api)

    @app.get("/")
    def root() -> dict:
        return {
            "name": settings.app_name,
            "version": settings.app_version,
            "docs": "/docs",
            "health": f"{api}/health",
        }

    return app


app = create_app()
