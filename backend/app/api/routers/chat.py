"""Public assistant endpoint — bilingual FAQ + optional LLM bridge."""

from __future__ import annotations

import time
from collections import deque
from threading import Lock
from typing import Literal

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field

from app.assistant import answer, get_faq, get_suggestions
from app.assistant.providers import is_configured as llm_configured
from app.core.config import settings
from app.core.logging import get_logger

router = APIRouter(prefix="/chat", tags=["assistant"])
log = get_logger(__name__)

Lang = Literal["fr", "en"]


# ---------------------------------------------------------------------------
# Pydantic schemas — kept in this file because they are not reused elsewhere.
# ---------------------------------------------------------------------------
class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=2000)
    lang: Lang | None = None


class RelatedFAQ(BaseModel):
    id: str
    category: str
    question: str
    answer: str
    score: float | None = None


class ChatResponse(BaseModel):
    text: str
    lang: Lang
    source: Literal["kb", "llm", "fallback"]
    provider: str | None = None
    confidence: float
    related: list[RelatedFAQ] = []


class ProviderInfo(BaseModel):
    configured: bool
    provider: str
    model: str | None = None


class FAQItem(BaseModel):
    id: str
    category: str
    question: str
    answer: str


# ---------------------------------------------------------------------------
# Tiny in-process token-bucket per IP.
# Anonymous endpoint → we don't have a user identity, so we throttle by IP.
# Replace with Redis if you ever scale this horizontally.
# ---------------------------------------------------------------------------
_RATE_WINDOW_S = 60.0
_RATE_BUCKETS: dict[str, deque[float]] = {}
_RATE_LOCK = Lock()


def _check_rate_limit(ip: str) -> None:
    limit = settings.chat_rate_per_minute
    if limit <= 0:
        return
    now = time.monotonic()
    with _RATE_LOCK:
        bucket = _RATE_BUCKETS.setdefault(ip, deque())
        # drop expired timestamps
        while bucket and now - bucket[0] > _RATE_WINDOW_S:
            bucket.popleft()
        if len(bucket) >= limit:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"chat rate limit exceeded ({limit}/min)",
            )
        bucket.append(now)


def _client_ip(request: Request) -> str:
    # Prefer the leftmost X-Forwarded-For when running behind a reverse proxy.
    fwd = request.headers.get("x-forwarded-for", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


# ---------------------------------------------------------------------------
# Endpoints — all public (no auth required).
# ---------------------------------------------------------------------------
@router.post("", response_model=ChatResponse)
def post_chat(payload: ChatRequest, request: Request) -> ChatResponse:
    """Send a message to the GuardIAn assistant."""
    _check_rate_limit(_client_ip(request))

    result = answer(payload.message, lang=payload.lang)
    log.info(
        "assistant.reply",
        source=result.source,
        lang=result.lang,
        provider=result.provider,
        confidence=result.confidence,
    )
    return ChatResponse(**result.to_dict())


@router.get("/faq", response_model=list[FAQItem])
def get_faq_endpoint(lang: Lang = "fr") -> list[FAQItem]:
    """Full bilingual FAQ catalog used by the public ``/faq`` page."""
    return [FAQItem(**item) for item in get_faq(lang)]


@router.get("/suggestions", response_model=list[str])
def get_suggestions_endpoint(lang: Lang = "fr") -> list[str]:
    """Suggested prompts shown as chips in the chat widget."""
    return get_suggestions(lang)


@router.get("/provider", response_model=ProviderInfo)
def get_provider_info() -> ProviderInfo:
    """Tells the UI whether to label answers as KB-only or AI-powered."""
    return ProviderInfo(
        configured=llm_configured(),
        provider=settings.llm_provider,
        model=settings.llm_model or None,
    )
