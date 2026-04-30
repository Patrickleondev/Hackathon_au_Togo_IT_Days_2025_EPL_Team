"""Assistant orchestration: KB lookup → optional LLM grounding → response.

Decision tree
~~~~~~~~~~~~~

1. Detect the language (FR / EN) from the user message — used for any
   fallback / grounding text.
2. Run :func:`app.assistant.retriever.search` over the bilingual FAQ.
3. If the top hit's score ≥ ``HIGH_CONF`` → return its answer verbatim
   with ``source = "kb"``. Cheap, deterministic, audit-friendly.
4. If a LLM provider is configured (``settings.llm_provider != "none"``):
   build a tight grounding prompt with the top-K FAQ entries and the
   user message, call the provider, return the response with
   ``source = "llm"``. Falls back gracefully on any error.
5. Otherwise return the best KB hit (if any) or a polite "I don't know"
   that points to the FAQ page.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from app.assistant import providers
from app.assistant.kb import SUGGESTIONS, FAQ, Lang, get_faq
from app.assistant.retriever import Hit, detect_lang, search
from app.core.logging import get_logger

log = get_logger(__name__)

# A score above this means "the FAQ already answers this perfectly".
_HIGH_CONF = 0.32
# Below this we don't even bother showing a fuzzy KB match — too noisy.
_MIN_REPLY_CONF = 0.10
# How many FAQ entries we ground the LLM on.
_LLM_TOP_K = 4


Source = Literal["kb", "llm", "fallback"]


@dataclass(frozen=True, slots=True)
class Answer:
    """Normalised assistant reply."""

    text: str
    lang: Lang
    source: Source
    provider: str | None = None
    confidence: float = 0.0
    related: tuple[dict, ...] = ()  # extra FAQ hits surfaced to the UI

    def to_dict(self) -> dict:
        return {
            "text": self.text,
            "lang": self.lang,
            "source": self.source,
            "provider": self.provider,
            "confidence": round(self.confidence, 4),
            "related": list(self.related),
        }


# ---------------------------------------------------------------------------
# Public surface.
# ---------------------------------------------------------------------------
def get_suggestions(lang: Lang = "fr") -> list[str]:
    """Return suggested user prompts shown as chips in the UI."""
    return list(SUGGESTIONS.get(lang, SUGGESTIONS["fr"]))


def answer(message: str, *, lang: Lang | None = None) -> Answer:
    """Main entrypoint used by the API router.

    ``lang`` may be passed by the caller (e.g. derived from the i18n state
    of the frontend). When omitted we fall back to a heuristic.
    """
    msg = (message or "").strip()
    if not msg:
        return _empty_answer(lang or "fr")

    detected: Lang = lang if lang in ("fr", "en") else detect_lang(msg)

    hits = search(msg, top_k=_LLM_TOP_K)
    top = hits[0] if hits else None

    # 1) High-confidence KB hit — short-circuit, no LLM call.
    if top and top.score >= _HIGH_CONF:
        return Answer(
            text=top.entry.answer(detected),
            lang=detected,
            source="kb",
            confidence=top.score,
            related=tuple(h.to_dict(detected) for h in hits[1:3]),
        )

    # 2) LLM grounded on the FAQ if a provider is configured.
    if providers.is_configured():
        try:
            llm_text = _ask_llm(msg, hits, detected)
            return Answer(
                text=llm_text.text,
                lang=detected,
                source="llm",
                provider=llm_text.provider,
                confidence=top.score if top else 0.0,
                related=tuple(h.to_dict(detected) for h in hits[:3]),
            )
        except providers.ProviderError as exc:
            log.warning("assistant.llm_failed", error=str(exc))
            # fall through to the KB-only fallback below

    # 3) Best-effort KB fallback.
    if top and top.score >= _MIN_REPLY_CONF:
        return Answer(
            text=top.entry.answer(detected),
            lang=detected,
            source="kb",
            confidence=top.score,
            related=tuple(h.to_dict(detected) for h in hits[1:3]),
        )

    return _no_match_answer(detected)


# ---------------------------------------------------------------------------
# Internals.
# ---------------------------------------------------------------------------
def _empty_answer(lang: Lang) -> Answer:
    text_fr = "Posez-moi une question sur GuardIAn — détection, installation, équipe…"
    text_en = "Ask me anything about GuardIAn — detection, install, team…"
    return Answer(
        text=text_en if lang == "en" else text_fr,
        lang=lang,
        source="fallback",
        confidence=0.0,
    )


def _no_match_answer(lang: Lang) -> Answer:
    text_fr = (
        "Je n'ai pas trouvé de réponse certaine dans la documentation. "
        "Consultez la page FAQ ou contactez l'équipe via la page « Contact »."
    )
    text_en = (
        "I couldn't find a confident answer in the documentation. Check the "
        "FAQ page or reach the team via the « Contact » page."
    )
    return Answer(
        text=text_en if lang == "en" else text_fr,
        lang=lang,
        source="fallback",
        confidence=0.0,
        related=tuple(
            {"id": e.id, "category": e.category, "question": e.question(lang), "answer": e.answer(lang)}
            for e in FAQ[:3]
        ),
    )


_SYSTEM_PROMPT = (
    "You are GuardIAn's official assistant for the Togo IT Days 2025 hackathon.\n"
    "GuardIAn is an open-source AI-powered antivirus / EDR built by the EPL team.\n"
    "Rules:\n"
    "- Answer ONLY using the FAQ context provided below. If the answer is not "
    "  in the context, say you don't know and point the user to the /faq page "
    "  or the Contact page.\n"
    "- Be concise (3-6 sentences max).\n"
    "- Reply in the same language as the user (French or English).\n"
    "- Never invent feature names, version numbers, prices or URLs.\n"
    "- Markdown is allowed for short bold or bullet lists.\n"
)


def _ask_llm(message: str, hits: list[Hit], lang: Lang) -> providers.LLMResponse:
    """Build the grounding prompt and call the configured provider."""
    grounding_lines: list[str] = []
    for i, h in enumerate(hits[:_LLM_TOP_K], start=1):
        grounding_lines.append(
            f"### FAQ #{i} — {h.entry.question(lang)}\n{h.entry.answer(lang)}"
        )
    grounding = "\n\n".join(grounding_lines) or "(no matching FAQ entry)"

    user_prompt = (
        f"Language: {'English' if lang == 'en' else 'French'}\n\n"
        f"=== FAQ context ===\n{grounding}\n\n"
        f"=== User message ===\n{message}\n\n"
        "Reply now."
    )

    return providers.complete(system=_SYSTEM_PROMPT, user=user_prompt)


def get_faq_payload(lang: Lang = "fr") -> list[dict]:
    """Re-export — keeps the API router import surface tidy."""
    return get_faq(lang)
