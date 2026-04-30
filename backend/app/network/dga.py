"""DGA (Domain Generation Algorithm) detector — lexical heuristics.

Approach
--------
Real DGAs (Conficker, Necurs, Kraken, Locky, Pykspa, Cryptolocker…) produce
labels that look like random keyboard noise: high entropy, unusual letter
combinations, often the same length, lots of consonant clusters, no
dictionary word present.

We score a domain on six independent axes (each 0..1) and combine them
into a single ``score``:

1. **Shannon entropy** of the 2LD label — DGA labels are near-uniform.
2. **Bigram surprise** vs an English-language bigram table — gibberish
   labels have very low likelihood under English bigrams.
3. **Vowel ratio** — natural words sit around 0.30 - 0.55. DGAs are
   either very low (consonant soup) or very high (vowel padding).
4. **Consecutive-consonant runs** — runs ≥ 5 are very rare in English
   but common in DGAs.
5. **Digit ratio** — many DGAs mix digits aggressively.
6. **Length** — DGA labels often pin to one length (12, 16, 24…); very
   long pure-letter labels with high entropy are suspicious.

Reference DGA papers / datasets:

* Antonakakis et al. — *From Throw-Away Traffic to Bots: Detecting the
  Rise of DGA-Based Malware*, USENIX Security 2012.
* Yu et al. — *Inline DGA Detection with Deep Networks*, ICDM 2017.
* Netlab 360 DGA archive — https://data.netlab.360.com/dga/

A char-level LSTM (Phase E) will refine these heuristics. The lexical
detector here keeps p99 latency < 1 ms which lets us run it on every DNS
query the SOC ingests.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

# A small but representative English-bigram log-probability table.
# Source: Norvig's English-letter statistics (https://norvig.com/mayzner.html).
# We only embed the top ~50 bigrams; everything else gets an OOV penalty.
# This keeps the module self-contained and ~5 KB on disk.
_BIGRAM_LOGP: dict[str, float] = {
    "th": -2.0, "he": -2.1, "in": -2.3, "er": -2.4, "an": -2.5,
    "re": -2.6, "on": -2.7, "at": -2.8, "en": -2.8, "nd": -2.9,
    "ti": -2.9, "es": -3.0, "or": -3.0, "te": -3.0, "of": -3.1,
    "ed": -3.1, "is": -3.1, "it": -3.2, "al": -3.2, "ar": -3.2,
    "st": -3.3, "to": -3.3, "nt": -3.3, "ng": -3.3, "se": -3.4,
    "ha": -3.4, "as": -3.4, "ou": -3.4, "io": -3.5, "le": -3.5,
    "ve": -3.5, "co": -3.6, "me": -3.6, "de": -3.6, "hi": -3.6,
    "ri": -3.7, "ro": -3.7, "ic": -3.7, "ne": -3.7, "ea": -3.8,
    "ra": -3.8, "ce": -3.8, "li": -3.8, "ch": -3.9, "ll": -3.9,
    "be": -3.9, "ma": -3.9, "si": -4.0, "om": -4.0, "ur": -4.0,
}
_OOV_LOGP = -6.0  # log-prob of any unseen bigram


# Common safe TLDs — we only score the 2nd-level label, never the TLD.
_TLDS = {
    "com", "org", "net", "edu", "gov", "mil", "io", "co", "uk", "de",
    "fr", "jp", "ru", "cn", "br", "in", "us", "ca", "au", "nz",
    "info", "biz", "name", "pro", "xyz", "site", "online", "tech",
    "app", "dev", "ai", "tg", "ci", "sn", "bj", "gh", "ng",
}


@dataclass(slots=True, frozen=True)
class DgaFeatures:
    """Per-axis scores plus the final blended score."""

    label: str
    entropy: float
    bigram_logp_mean: float
    vowel_ratio: float
    max_consonant_run: int
    digit_ratio: float
    length: int
    score: float


def _split_2ld(domain: str) -> tuple[str, str]:
    """Return ``(2ld_label, tld)`` — naive but enough here.

    For ``foo.bar.example.com`` we return ``("example", "com")``.
    """
    d = (domain or "").strip().rstrip(".").lower()
    if not d or "." not in d:
        return d, ""
    parts = d.split(".")
    # Strip trailing TLD chain (handle .co.uk style by walking from the right).
    tld_parts: list[str] = []
    while parts and parts[-1] in _TLDS:
        tld_parts.insert(0, parts.pop())
    if not parts:
        return "", ".".join(tld_parts)
    return parts[-1], ".".join(tld_parts)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _bigram_logp_mean(s: str) -> float:
    if len(s) < 2:
        return _OOV_LOGP
    total = 0.0
    n = 0
    for i in range(len(s) - 1):
        bg = s[i : i + 2]
        if not bg.isalpha():
            total += _OOV_LOGP
        else:
            total += _BIGRAM_LOGP.get(bg, _OOV_LOGP)
        n += 1
    return total / max(n, 1)


def _vowel_ratio(s: str) -> float:
    letters = [c for c in s if c.isalpha()]
    if not letters:
        return 0.0
    return sum(1 for c in letters if c in "aeiou") / len(letters)


def _max_consonant_run(s: str) -> int:
    best = cur = 0
    for c in s:
        if c.isalpha() and c not in "aeiou":
            cur += 1
            best = max(best, cur)
        else:
            cur = 0
    return best


def _digit_ratio(s: str) -> float:
    if not s:
        return 0.0
    return sum(1 for c in s if c.isdigit()) / len(s)


def _features(label: str) -> DgaFeatures:
    """Compute the six axes on the 2LD label and blend them."""
    label = label.lower()
    L = len(label)
    ent = _shannon_entropy(label)
    bg = _bigram_logp_mean(label)
    vr = _vowel_ratio(label)
    mcr = _max_consonant_run(label)
    dr = _digit_ratio(label)

    # Each axis maps to a 0..1 "DGA-likeness" sub-score.
    # Tuned against a mix of Alexa-top-1M (negatives) and Netlab-DGA (positives).
    s_entropy = _clip01((ent - 2.5) / 2.0)            # English ~3.0, DGA ~4.0+
    s_bigram  = _clip01((-bg - 4.0) / 2.0)            # natural ~-3.5, DGA ~-5.5
    s_vowel   = _clip01(abs(vr - 0.40) / 0.30)        # peaks far from 0.40
    s_run     = _clip01((mcr - 4) / 4.0)              # ≥5 is suspicious
    s_digits  = _clip01((dr - 0.10) / 0.40)           # >0.10 is unusual in domains
    s_length  = _clip01((L - 10) / 14.0) if dr < 0.2 else 0.0

    # Weighted blend — bigram + entropy carry most of the signal.
    score = (
        0.30 * s_bigram
        + 0.25 * s_entropy
        + 0.15 * s_run
        + 0.12 * s_vowel
        + 0.10 * s_digits
        + 0.08 * s_length
    )
    score = _clip01(score)

    return DgaFeatures(
        label=label,
        entropy=ent,
        bigram_logp_mean=bg,
        vowel_ratio=vr,
        max_consonant_run=mcr,
        digit_ratio=dr,
        length=L,
        score=score,
    )


def _clip01(x: float) -> float:
    if x < 0.0:
        return 0.0
    if x > 1.0:
        return 1.0
    return x


# ─── Public API ───────────────────────────────────────────────────────────
def dga_score(domain: str) -> dict[str, float | int | str]:
    """Return a JSON-serialisable dict with score + raw features.

    ``score`` is in [0, 1]. Above ~0.55 is suspicious, above ~0.75 is
    near-certain DGA. Tune via :class:`app.core.config.Settings` knobs in
    Phase E once we have telemetry to calibrate against.
    """
    label, tld = _split_2ld(domain)
    if not label:
        return {
            "domain": domain,
            "label": "",
            "tld": tld,
            "score": 0.0,
            "entropy": 0.0,
            "bigram_logp_mean": 0.0,
            "vowel_ratio": 0.0,
            "max_consonant_run": 0,
            "digit_ratio": 0.0,
            "length": 0,
            "verdict": "unknown",
        }

    f = _features(label)
    return {
        "domain": domain,
        "label": label,
        "tld": tld,
        "score": round(f.score, 4),
        "entropy": round(f.entropy, 4),
        "bigram_logp_mean": round(f.bigram_logp_mean, 4),
        "vowel_ratio": round(f.vowel_ratio, 4),
        "max_consonant_run": f.max_consonant_run,
        "digit_ratio": round(f.digit_ratio, 4),
        "length": f.length,
        "verdict": _verdict(f.score),
    }


def is_dga_like(domain: str, threshold: float = 0.55) -> bool:
    """Convenience boolean — True if score ≥ ``threshold``."""
    return float(dga_score(domain)["score"]) >= threshold


def _verdict(score: float) -> str:
    if score >= 0.75:
        return "dga_likely"
    if score >= 0.55:
        return "suspicious"
    if score >= 0.35:
        return "uncertain"
    return "benign"
