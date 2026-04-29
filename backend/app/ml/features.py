"""Feature extraction for the unified detector.

The detector is intentionally lightweight and explainable. It mixes:
 - structural features (size, extension, magic-bytes mismatch)
 - statistical features (Shannon entropy of the first MB)
 - lexical features (suspicious string indicators)

All features are stable across platforms and require no native libs.
"""

from __future__ import annotations

import hashlib
import math
import os
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Magic bytes -> canonical extension
MAGIC_TABLE: dict[bytes, str] = {
    b"\x4d\x5a": ".exe",
    b"\x50\x4b\x03\x04": ".zip",
    b"\x25\x50\x44\x46": ".pdf",
    b"\x89\x50\x4e\x47": ".png",
    b"\xff\xd8\xff": ".jpg",
    b"\x47\x49\x46\x38": ".gif",
    b"\x7f\x45\x4c\x46": ".elf",
    b"\xca\xfe\xba\xbe": ".class",  # also Mach-O fat
    b"\xd0\xcf\x11\xe0": ".doc",
    b"#!/": ".sh",
}

SUSPICIOUS_EXT_SCORES: dict[str, float] = {
    ".exe": 0.55, ".dll": 0.45, ".bat": 0.65, ".cmd": 0.65,
    ".ps1": 0.60, ".vbs": 0.65, ".js": 0.40, ".jar": 0.45,
    ".scr": 0.85, ".pif": 0.85, ".com": 0.55, ".hta": 0.70,
    ".lnk": 0.50, ".msi": 0.45, ".wsf": 0.60,
}

# Lexical patterns commonly found in ransomware / commodity malware payloads.
# These run on text files and on UTF-8-decodable strings inside binaries.
SUSPICIOUS_PATTERNS: dict[str, re.Pattern[bytes]] = {
    "encryption_api": re.compile(
        rb"\b(CryptEncrypt|CryptGenKey|BCryptEncrypt|AES_encrypt|RSA_public_encrypt)\b"
    ),
    "ransom_note": re.compile(
        rb"(?i)(your files (have been|are) encrypted|pay(?:ment)? in bitcoin|"
        rb"send \$?\d+ (?:usd|btc|eur)|decryption key|readme[_\- ]decrypt)"
    ),
    "shadow_copy_delete": re.compile(rb"(?i)vssadmin\s+delete\s+shadows"),
    "wbadmin_delete": re.compile(rb"(?i)wbadmin\s+delete\s+catalog"),
    "bcdedit_recovery": re.compile(rb"(?i)bcdedit.*recoveryenabled"),
    "powershell_obfuscated": re.compile(
        rb"(?i)powershell.*(-enc|-encodedcommand|frombase64string|iex\s*\()"
    ),
    "downloader": re.compile(
        rb"(?i)(invoke-webrequest|certutil\s+-urlcache|bitsadmin\s+/transfer|wget\s+http)"
    ),
    "persistence": re.compile(
        rb"(?i)(\\Run\\|\\RunOnce\\|schtasks\s+/create|reg\s+add.*\\Run)"
    ),
    "tor_onion": re.compile(rb"(?i)[a-z2-7]{16,56}\.onion"),
    "btc_wallet": re.compile(rb"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|\bbc1[ac-hj-np-z02-9]{6,87}\b"),
}

MAX_READ_BYTES = 4 * 1024 * 1024  # 4 MB feature window


@dataclass
class FileFeatures:
    """Structured features fed to the unified detector."""

    file_size: int = 0
    file_ext: str = ""
    sha256: str = ""
    entropy: float = 0.0
    magic_ext: str | None = None
    magic_mismatch: bool = False
    suspicious_ext_score: float = 0.0
    pattern_hits: dict[str, int] = field(default_factory=dict)
    pattern_count: int = 0
    has_high_entropy_block: bool = False
    is_text: bool = False
    error: str | None = None

    def to_vector(self) -> list[float]:
        """Numeric vector (stable order) for sklearn models."""
        return [
            float(min(self.file_size, 50 * 1024 * 1024)) / (50 * 1024 * 1024),
            self.entropy / 8.0,
            1.0 if self.magic_mismatch else 0.0,
            self.suspicious_ext_score,
            min(self.pattern_count, 20) / 20.0,
            1.0 if self.has_high_entropy_block else 0.0,
            float(self.pattern_hits.get("encryption_api", 0) > 0),
            float(self.pattern_hits.get("ransom_note", 0) > 0),
            float(self.pattern_hits.get("shadow_copy_delete", 0) > 0),
            float(self.pattern_hits.get("powershell_obfuscated", 0) > 0),
            float(self.pattern_hits.get("downloader", 0) > 0),
            float(self.pattern_hits.get("persistence", 0) > 0),
            float(self.pattern_hits.get("tor_onion", 0) > 0),
            float(self.pattern_hits.get("btc_wallet", 0) > 0),
        ]

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_size": self.file_size,
            "file_ext": self.file_ext,
            "sha256": self.sha256,
            "entropy": round(self.entropy, 3),
            "magic_ext": self.magic_ext,
            "magic_mismatch": self.magic_mismatch,
            "suspicious_ext_score": self.suspicious_ext_score,
            "pattern_hits": self.pattern_hits,
            "pattern_count": self.pattern_count,
            "has_high_entropy_block": self.has_high_entropy_block,
            "is_text": self.is_text,
        }


# ─── Helpers ──────────────────────────────────────────────────────────────
def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _detect_magic(head: bytes) -> str | None:
    for sig, ext in MAGIC_TABLE.items():
        if head.startswith(sig):
            return ext
    return None


def _looks_like_text(sample: bytes) -> bool:
    if not sample:
        return False
    printable = sum(1 for b in sample if 32 <= b < 127 or b in (9, 10, 13))
    return printable / len(sample) > 0.85


# ─── Public API ───────────────────────────────────────────────────────────
def extract_features(file_path: str | os.PathLike) -> FileFeatures:
    """Extract features from a path on disk. Never raises — returns error in dataclass."""
    path = Path(file_path)
    feats = FileFeatures(file_ext=path.suffix.lower())

    if not path.exists() or not path.is_file():
        feats.error = "file_not_found"
        return feats

    try:
        feats.file_size = path.stat().st_size
        with path.open("rb") as f:
            head = f.read(8)
            f.seek(0)
            data = f.read(MAX_READ_BYTES)
    except OSError as exc:
        feats.error = f"read_error: {exc}"
        return feats

    feats.sha256 = hashlib.sha256(data).hexdigest() if data else ""
    feats.entropy = _shannon_entropy(data)
    feats.magic_ext = _detect_magic(head)
    if feats.magic_ext and feats.file_ext and feats.magic_ext != feats.file_ext:
        feats.magic_mismatch = True
    feats.suspicious_ext_score = SUSPICIOUS_EXT_SCORES.get(feats.file_ext, 0.0)
    feats.is_text = _looks_like_text(data[: 4 * 1024])

    # Block-level entropy: scan 64 KB blocks; flag if any > 7.5
    if data:
        block = 64 * 1024
        for i in range(0, min(len(data), 1024 * 1024), block):
            if _shannon_entropy(data[i : i + block]) > 7.5:
                feats.has_high_entropy_block = True
                break

    # Pattern matching
    hits: dict[str, int] = {}
    for name, regex in SUSPICIOUS_PATTERNS.items():
        n = len(regex.findall(data))
        if n:
            hits[name] = n
    feats.pattern_hits = hits
    feats.pattern_count = sum(hits.values())

    return feats


def extract_features_from_bytes(name: str, data: bytes) -> FileFeatures:
    """Same as extract_features but for in-memory bytes (uploads)."""
    feats = FileFeatures(file_ext=Path(name).suffix.lower())
    feats.file_size = len(data)
    feats.sha256 = hashlib.sha256(data).hexdigest() if data else ""
    feats.entropy = _shannon_entropy(data[:MAX_READ_BYTES])
    feats.magic_ext = _detect_magic(data[:8])
    if feats.magic_ext and feats.file_ext and feats.magic_ext != feats.file_ext:
        feats.magic_mismatch = True
    feats.suspicious_ext_score = SUSPICIOUS_EXT_SCORES.get(feats.file_ext, 0.0)
    feats.is_text = _looks_like_text(data[: 4 * 1024])

    if data:
        block = 64 * 1024
        for i in range(0, min(len(data), 1024 * 1024), block):
            if _shannon_entropy(data[i : i + block]) > 7.5:
                feats.has_high_entropy_block = True
                break

    sample = data[:MAX_READ_BYTES]
    hits: dict[str, int] = {}
    for name_, regex in SUSPICIOUS_PATTERNS.items():
        n = len(regex.findall(sample))
        if n:
            hits[name_] = n
    feats.pattern_hits = hits
    feats.pattern_count = sum(hits.values())

    return feats
