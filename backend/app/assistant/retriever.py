"""Lightweight keyword retriever over the FAQ knowledge base.

We keep the implementation pure-Python (no scikit-learn dependency) — the
catalog is small enough that a hand-rolled TF-IDF-like score over normalised
tokens runs in microseconds and is trivially auditable. Bigger catalogs can
later swap this for sentence-transformers + FAISS without touching callers.
"""

from __future__ import annotations

import math
import re
import unicodedata
from collections import Counter
from dataclasses import dataclass

from app.assistant.kb import FAQ, FAQEntry, Lang


_TOKEN_RE = re.compile(r"[a-z0-9]+")

# Minimal stopword list — bilingual, intentionally conservative so we never
# strip a meaningful technical term ("dga", "ja3", "ml", …).
_STOP = frozenset(
    {
        # FR
        "le", "la", "les", "un", "une", "des", "du", "de", "d", "l", "et",
        "ou", "à", "a", "au", "aux", "en", "pour", "par", "sur", "sous",
        "dans", "avec", "sans", "ce", "ces", "cet", "cette", "qui", "que",
        "quoi", "quel", "quelle", "comment", "pourquoi", "est", "sont",
        "ai", "as", "ne", "pas", "plus", "moins", "il", "elle", "on", "nous",
        "vous", "ils", "elles", "y", "se", "sa", "son", "ses", "mais", "où",
        "donc", "or", "ni", "car",
        # EN
        "the", "a", "an", "of", "to", "in", "on", "at", "for", "and", "or",
        "is", "are", "be", "do", "does", "how", "what", "why", "when",
        "who", "which", "this", "that", "these", "those", "it", "its",
        "with", "from", "by", "as", "but", "not", "no",
    }
)


def _normalise(text: str) -> str:
    """ASCII-fold + lowercase so ``détecte`` matches ``detecte``."""
    nfkd = unicodedata.normalize("NFKD", text)
    return "".join(c for c in nfkd if not unicodedata.combining(c)).lower()


def _tokenise(text: str) -> list[str]:
    return [t for t in _TOKEN_RE.findall(_normalise(text)) if t not in _STOP and len(t) > 1]


# ---------------------------------------------------------------------------
# Index built once at import time.
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class _IndexedEntry:
    entry: FAQEntry
    tokens: Counter[str]
    norm: float  # L2 norm for cosine


def _entry_text(entry: FAQEntry) -> str:
    # Mix both language sides + keywords so the retriever is language-agnostic.
    return " ".join(
        [
            entry.question_fr,
            entry.question_en,
            entry.answer_fr,
            entry.answer_en,
            " ".join(entry.keywords),
        ]
    )


def _build_index() -> tuple[list[_IndexedEntry], dict[str, float]]:
    indexed: list[_IndexedEntry] = []
    df: Counter[str] = Counter()
    for e in FAQ:
        toks = _tokenise(_entry_text(e))
        tf = Counter(toks)
        for tok in tf:
            df[tok] += 1
        norm = math.sqrt(sum(v * v for v in tf.values())) or 1.0
        indexed.append(_IndexedEntry(entry=e, tokens=tf, norm=norm))

    n = max(1, len(indexed))
    idf = {tok: math.log(1 + n / (1 + count)) for tok, count in df.items()}
    return indexed, idf


_INDEX, _IDF = _build_index()


# ---------------------------------------------------------------------------
# Query.
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class Hit:
    """Result of a retrieval — exposes both the entry and its match score."""

    entry: FAQEntry
    score: float

    def to_dict(self, lang: Lang) -> dict:
        return {
            "id": self.entry.id,
            "category": self.entry.category,
            "question": self.entry.question(lang),
            "answer": self.entry.answer(lang),
            "score": round(self.score, 4),
        }


def search(query: str, *, top_k: int = 3) -> list[Hit]:
    """Return the top-K FAQ entries matching ``query``.

    The score is a TF-IDF weighted cosine in [0, 1+]. A score ≥ 0.30 is
    typically a confident match; below that the caller should consider
    falling back to an LLM (if configured) or to a generic "I don't know"
    answer that points the user to the FAQ page.
    """
    q_tokens = _tokenise(query or "")
    if not q_tokens:
        return []

    q_tf = Counter(q_tokens)
    q_vec = {tok: tf * _IDF.get(tok, 1.0) for tok, tf in q_tf.items()}
    q_norm = math.sqrt(sum(v * v for v in q_vec.values())) or 1.0

    scored: list[Hit] = []
    for ix in _INDEX:
        # Sparse dot-product over tokens that exist in the entry.
        dot = 0.0
        for tok, qw in q_vec.items():
            if tok in ix.tokens:
                dot += qw * ix.tokens[tok] * _IDF.get(tok, 1.0)
        if dot <= 0:
            continue
        scored.append(Hit(entry=ix.entry, score=dot / (q_norm * ix.norm)))

    scored.sort(key=lambda h: h.score, reverse=True)
    return scored[:top_k]


def detect_lang(text: str) -> Lang:
    """Trivial FR/EN heuristic. Defaults to French (project's primary lang)."""
    if not text:
        return "fr"
    norm = _normalise(text)
    fr_hits = sum(1 for w in (" est ", " comment ", " quoi ", " pourquoi ", " avec ", " pour ") if w in f" {norm} ")
    en_hits = sum(1 for w in (" how ", " what ", " why ", " who ", " with ", " the ") if w in f" {norm} ")
    if en_hits > fr_hits:
        return "en"
    return "fr"
