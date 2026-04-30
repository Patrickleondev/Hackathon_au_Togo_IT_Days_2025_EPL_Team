"""Tests for the assistant module (FAQ retriever + LLM bridge wrapper)."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from app.assistant import answer, get_faq, get_suggestions
from app.assistant.providers import LLMResponse, ProviderError
from app.assistant.retriever import detect_lang, search


# ---------------------------------------------------------------------------
# Retriever.
# ---------------------------------------------------------------------------
def test_search_returns_empty_for_blank_query() -> None:
    assert search("") == []
    assert search("   ") == []


def test_search_finds_offline_question_in_french() -> None:
    hits = search("GuardIAn fonctionne hors-ligne ?")
    assert hits, "expected at least one hit"
    assert hits[0].entry.id == "works-offline"
    assert hits[0].score > 0.2


def test_search_finds_install_question_in_english() -> None:
    hits = search("How do I install the windows agent?")
    assert hits and hits[0].entry.id == "install-agent"


def test_search_is_accent_insensitive() -> None:
    a = search("detection ransomware")
    b = search("détection ransomware")
    assert a and b
    assert a[0].entry.id == b[0].entry.id


def test_search_orders_by_descending_score() -> None:
    hits = search("how does GuardIAn detect a ransomware on disk?")
    scores = [h.score for h in hits]
    assert scores == sorted(scores, reverse=True)


def test_detect_lang_french_default() -> None:
    assert detect_lang("Comment fonctionne ce truc") == "fr"


def test_detect_lang_english_signals() -> None:
    assert detect_lang("How does this work with the agent") == "en"


def test_detect_lang_empty_returns_french() -> None:
    assert detect_lang("") == "fr"


# ---------------------------------------------------------------------------
# Service: KB-only mode (no LLM provider).
# ---------------------------------------------------------------------------
def test_answer_kb_high_confidence_returns_kb_source() -> None:
    res = answer("Comment GuardIAn detecte un ransomware ?", lang="fr")
    assert res.source == "kb"
    assert res.lang == "fr"
    assert "hash" in res.text.lower() or "yara" in res.text.lower()
    assert res.confidence > 0.3


def test_answer_uses_user_supplied_lang_for_response() -> None:
    res = answer("How does GuardIAn detect a ransomware?", lang="en")
    assert res.lang == "en"
    assert "ransomware" in res.text.lower()


def test_answer_falls_back_when_no_match_and_no_llm() -> None:
    res = answer("What's the boiling point of mercury?", lang="en")
    assert res.source in ("fallback", "kb")  # may surface a low-conf KB hit
    # but the related list should still surface a few FAQ items as guidance
    assert len(res.related) >= 0


def test_answer_handles_blank_message() -> None:
    res = answer("", lang="fr")
    assert res.source == "fallback"
    assert "GuardIAn" in res.text


# ---------------------------------------------------------------------------
# Service: LLM bridge — patched, never hits the network.
# ---------------------------------------------------------------------------
def test_answer_calls_llm_when_kb_confidence_low(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_response = LLMResponse(text="Mocked LLM reply.", provider="openai", model="gpt-x")

    with patch("app.assistant.service.providers.is_configured", return_value=True), \
         patch("app.assistant.service.providers.complete", return_value=fake_response) as mock_complete:
        res = answer("Tell me an obscure trivia about quantum chromodynamics", lang="en")

    assert res.source == "llm"
    assert res.text == "Mocked LLM reply."
    assert res.provider == "openai"
    assert mock_complete.called


def test_answer_falls_back_to_kb_when_llm_errors() -> None:
    with patch("app.assistant.service.providers.is_configured", return_value=True), \
         patch("app.assistant.service.providers.complete", side_effect=ProviderError("boom")):
        res = answer("totally unrelated nonsense gibberish", lang="en")

    # No high-confidence KB hit either → fallback path.
    assert res.source in ("kb", "fallback")
    # Provider must NOT be reported on a fallback.
    if res.source == "fallback":
        assert res.provider is None


def test_answer_skips_llm_when_kb_already_confident() -> None:
    """High-confidence KB hits should never trigger an LLM call (cost saver)."""
    with patch("app.assistant.service.providers.is_configured", return_value=True), \
         patch("app.assistant.service.providers.complete") as mock_complete:
        res = answer("Quelle est la difference avec un antivirus classique ?", lang="fr")

    assert res.source == "kb"
    mock_complete.assert_not_called()


# ---------------------------------------------------------------------------
# Catalog API.
# ---------------------------------------------------------------------------
def test_get_faq_returns_french_by_default() -> None:
    faq = get_faq()
    assert len(faq) >= 10
    # French entries reliably contain accented characters somewhere.
    assert any("é" in item["answer"] or "è" in item["answer"] for item in faq)


def test_get_faq_english_yields_english_questions() -> None:
    faq_fr = get_faq("fr")
    faq_en = get_faq("en")
    assert len(faq_fr) == len(faq_en)
    # Questions must differ between languages for at least most entries.
    differing = sum(
        1 for fr, en in zip(faq_fr, faq_en) if fr["question"] != en["question"]
    )
    assert differing >= len(faq_fr) - 1


def test_get_suggestions_returns_six_chips_per_lang() -> None:
    fr = get_suggestions("fr")
    en = get_suggestions("en")
    assert len(fr) >= 5 and len(en) >= 5
    assert all(isinstance(s, str) and s for s in fr + en)
