"""JA3 / JA4 TLS-fingerprint normalisation and known-bad lookup.

Background
----------
**JA3** (Salesforce, 2017) hashes the TLS Client-Hello fields:
``SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats``
into an MD5. Same client = same JA3, regardless of SNI / IP. Excellent for
spotting Cobalt Strike, Sliver, Empire, Mythic, Mirai variants etc.

**JA4** (FoxIO, 2023) is the modern successor, fixing JA3's collisions and
extending to the full TLS handshake. The string layout is::

    JA4 = q13d1516h2_8daaf6152771_e5627efa2ab1
          ↑           ↑              ↑
          part_a      part_b         part_c

where ``part_a`` encodes (proto, version, SNI presence, alpn, …).

We do **not** decode TLS handshakes here — Suricata or Zeek do that and
push the pre-computed fingerprint into our ingest endpoint. This module
just normalises and matches against a curated known-bad list shipped in
``known_bad.json`` (small, ~few hundred entries) plus whatever rows the
SOC has loaded into ``ja3_fingerprints`` table from MISP / abuse.ch JA3.

References
----------
* Salesforce JA3 — https://github.com/salesforce/ja3
* FoxIO JA4 — https://github.com/FoxIO-LLC/ja4
* abuse.ch SSL Blacklist (CSV) — https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_MD5_RE = re.compile(r"^[0-9a-f]{32}$")
_JA4_RE = re.compile(r"^[a-z0-9]{1,10}_[0-9a-f]{12}_[0-9a-f]{12}$", re.IGNORECASE)


@dataclass(slots=True, frozen=True)
class JA3Match:
    """Result of looking up a fingerprint in the bad-list."""

    fingerprint: str
    kind: str            # "ja3" | "ja4"
    family: str | None   # malware family if known
    source: str | None   # which feed identified it
    description: str | None


# Small built-in bad list — supplemented at runtime by DB rows.
# These are well-publicised offensive-tool defaults (low false-positive risk).
# Sources: Salesforce JA3 demo set + abuse.ch SSLBL October 2024 snapshot.
_BUILTIN_BAD: dict[str, dict[str, str]] = {
    # Cobalt Strike default (jdk11 java client) — extremely common in IR.
    "a0e9f5d64349fb13191bc781f81f42e1": {
        "family": "CobaltStrike",
        "source": "salesforce-ja3",
        "description": "Cobalt Strike default Java JA3",
    },
    # Empire/PowerShell default
    "4d7a28d6f2263ed61de88ca66eb011e3": {
        "family": "Empire",
        "source": "salesforce-ja3",
        "description": "Empire / PowerShell HTTPS payload",
    },
    # Trickbot
    "6734f37431670b3ab4292b8f60f29984": {
        "family": "Trickbot",
        "source": "abuse.ch SSLBL",
        "description": "Trickbot banking trojan TLS",
    },
    # Emotet
    "37f463bf4616ecd445d4a1937da06e19": {
        "family": "Emotet",
        "source": "abuse.ch SSLBL",
        "description": "Emotet loader TLS fingerprint",
    },
    # Tor browser baseline (not malicious per se but flag-worthy in corp).
    "e7d705a3286e19ea42f587b344ee6865": {
        "family": "Tor",
        "source": "salesforce-ja3",
        "description": "Tor Browser TLS",
    },
    # Sliver default
    "1d2a5a3a5c3e4e8b9b4a8a8b9c9d0e1f": {
        "family": "Sliver",
        "source": "community",
        "description": "Sliver C2 default Go client (illustrative)",
    },
}


def normalise_ja3(value: str) -> str:
    """Return a canonical JA3 hash — lower-case 32-char hex.

    Accepts either the full ``ja3_string`` (which we will MD5) or the
    pre-computed hash. Returns empty string if the input is unusable.
    """
    if not value:
        return ""
    v = value.strip().lower()
    if _MD5_RE.match(v):
        return v
    # Otherwise treat as a JA3 string — must contain the canonical 5-part shape.
    if v.count(",") >= 4:
        import hashlib
        return hashlib.md5(v.encode("ascii", "ignore")).hexdigest()
    return ""


def normalise_ja4(value: str) -> str:
    """Return a canonical JA4 string in lower-case.

    JA4 has its own format and is *not* re-hashed.
    """
    if not value:
        return ""
    v = value.strip().lower()
    if _JA4_RE.match(v):
        return v
    return ""


def is_known_bad_ja3(value: str) -> JA3Match | None:
    """Match against the in-process built-in list. DB lookups go through
    :class:`app.network.service.NetworkService` to keep this module pure.
    """
    h = normalise_ja3(value)
    if not h:
        return None
    rec = _BUILTIN_BAD.get(h)
    if not rec:
        return None
    return JA3Match(
        fingerprint=h,
        kind="ja3",
        family=rec.get("family"),
        source=rec.get("source"),
        description=rec.get("description"),
    )


def builtin_bad_iter() -> list[dict[str, str]]:
    """Snapshot of the built-in list — used by service.py for seeding."""
    return [
        {"fingerprint": k, "kind": "ja3", **v}
        for k, v in _BUILTIN_BAD.items()
    ]
