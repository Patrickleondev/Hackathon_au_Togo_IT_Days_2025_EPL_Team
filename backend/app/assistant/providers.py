"""Pluggable LLM provider layer for the assistant.

We avoid pulling in heavy SDKs (anthropic, openai) — every supported
provider exposes a chat-completion HTTP endpoint that we hit with
``httpx``. Adding a new provider = ~20 lines below.

Supported providers (selected via ``settings.llm_provider``):

================  ===============================================  ==============================
``llm_provider``  Endpoint                                         Model env example
================  ===============================================  ==============================
``none``          —                                                (KB-only mode)
``openai``        ``https://api.openai.com/v1/chat/completions``   ``gpt-4o-mini``
``anthropic``     ``https://api.anthropic.com/v1/messages``        ``claude-3-5-haiku-latest``
``mistral``       ``https://api.mistral.ai/v1/chat/completions``   ``mistral-small-latest``
``openrouter``    ``https://openrouter.ai/api/v1/chat/completions`` ``anthropic/claude-3.5-haiku``
``ollama``        ``http://localhost:11434/api/chat``              ``llama3.2``
================  ===============================================  ==============================

Common settings:
- ``llm_api_key`` — required for every provider except ``ollama`` and ``none``.
- ``llm_model`` — provider-specific model id.
- ``llm_base_url`` — override the default endpoint (useful for self-hosted).
- ``llm_max_tokens`` — output cap (default 512).

The provider is **never** called if the FAQ retriever is already confident.
That keeps inference cost ~zero for the majority of the traffic.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

import httpx

from app.core.config import settings
from app.core.logging import get_logger

log = get_logger(__name__)

ProviderName = Literal["none", "openai", "anthropic", "mistral", "openrouter", "ollama"]

_DEFAULT_ENDPOINTS: dict[ProviderName, str] = {
    "openai": "https://api.openai.com/v1/chat/completions",
    "anthropic": "https://api.anthropic.com/v1/messages",
    "mistral": "https://api.mistral.ai/v1/chat/completions",
    "openrouter": "https://openrouter.ai/api/v1/chat/completions",
    "ollama": "http://localhost:11434/api/chat",
    "none": "",
}


@dataclass(frozen=True, slots=True)
class LLMResponse:
    """Normalised response across providers."""

    text: str
    provider: ProviderName
    model: str | None = None


class ProviderError(RuntimeError):
    """Raised when the upstream LLM API misbehaves."""


# ---------------------------------------------------------------------------
# Public API.
# ---------------------------------------------------------------------------
def is_configured() -> bool:
    """True iff a remote LLM is wired up and ready to use."""
    provider = settings.llm_provider
    if provider == "none" or not provider:
        return False
    if provider == "ollama":
        return True  # local, no key required
    return bool(settings.llm_api_key)


def complete(
    *,
    system: str,
    user: str,
    timeout: float | None = None,
) -> LLMResponse:
    """Send a single chat-completion request and return the assistant text.

    Raises :class:`ProviderError` if the provider is misconfigured or the
    upstream API returns an unexpected payload — callers should catch and
    fall back to the KB-only answer.
    """
    provider: ProviderName = settings.llm_provider  # type: ignore[assignment]
    if provider == "none" or not provider:
        raise ProviderError("LLM provider is disabled (LLM_PROVIDER=none)")

    base_url = settings.llm_base_url or _DEFAULT_ENDPOINTS.get(provider, "")
    if not base_url:
        raise ProviderError(f"unknown LLM provider: {provider!r}")

    model = settings.llm_model or _default_model(provider)
    timeout_s = timeout if timeout is not None else settings.llm_timeout_seconds

    headers, payload = _build_request(provider, model, system, user)

    try:
        with httpx.Client(timeout=timeout_s) as client:
            r = client.post(base_url, headers=headers, json=payload)
            r.raise_for_status()
            data = r.json()
    except httpx.HTTPError as exc:
        log.warning("assistant.llm.http_error", provider=provider, error=str(exc))
        raise ProviderError(f"LLM HTTP error: {exc}") from exc
    except ValueError as exc:  # JSON decode
        log.warning("assistant.llm.bad_json", provider=provider, error=str(exc))
        raise ProviderError("LLM returned non-JSON response") from exc

    text = _extract_text(provider, data)
    if not text:
        raise ProviderError("LLM returned empty completion")

    return LLMResponse(text=text.strip(), provider=provider, model=model)


# ---------------------------------------------------------------------------
# Internal — per-provider quirks.
# ---------------------------------------------------------------------------
def _default_model(provider: ProviderName) -> str:
    return {
        "openai": "gpt-4o-mini",
        "anthropic": "claude-3-5-haiku-latest",
        "mistral": "mistral-small-latest",
        "openrouter": "anthropic/claude-3.5-haiku",
        "ollama": "llama3.2",
        "none": "",
    }[provider]


def _build_request(
    provider: ProviderName,
    model: str,
    system: str,
    user: str,
) -> tuple[dict[str, str], dict[str, Any]]:
    max_tokens = settings.llm_max_tokens

    if provider == "anthropic":
        return (
            {
                "x-api-key": settings.llm_api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            {
                "model": model,
                "max_tokens": max_tokens,
                "system": system,
                "messages": [{"role": "user", "content": user}],
            },
        )

    if provider == "ollama":
        # Local Ollama doesn't need auth.
        return (
            {"content-type": "application/json"},
            {
                "model": model,
                "stream": False,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                "options": {"num_predict": max_tokens},
            },
        )

    # OpenAI-compatible: openai, mistral, openrouter.
    headers = {
        "Authorization": f"Bearer {settings.llm_api_key}",
        "Content-Type": "application/json",
    }
    if provider == "openrouter":
        headers["HTTP-Referer"] = "https://github.com/Patrickleondev/Hackathon_au_Togo_IT_Days_2025_EPL_Team"
        headers["X-Title"] = "GuardIAn"
    body = {
        "model": model,
        "max_tokens": max_tokens,
        "temperature": 0.2,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    }
    return headers, body


def _extract_text(provider: ProviderName, data: dict[str, Any]) -> str:
    try:
        if provider == "anthropic":
            blocks = data.get("content") or []
            for b in blocks:
                if b.get("type") == "text":
                    return b.get("text", "")
            return ""
        if provider == "ollama":
            return (data.get("message") or {}).get("content") or ""
        # OpenAI-compatible
        choices = data.get("choices") or []
        if not choices:
            return ""
        return ((choices[0] or {}).get("message") or {}).get("content") or ""
    except Exception:  # pragma: no cover - defensive
        return ""
