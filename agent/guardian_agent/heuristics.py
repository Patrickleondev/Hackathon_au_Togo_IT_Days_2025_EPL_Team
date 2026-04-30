"""Lightweight on-host heuristic — flags candidates worth uploading."""

from __future__ import annotations

import math
import re
from collections import Counter
from pathlib import Path

from guardian_agent.config import settings

SUSPICIOUS_EXTS = {
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".scr",
    ".pif", ".com", ".hta", ".lnk", ".msi", ".wsf", ".jar",
}

PATTERNS = [
    re.compile(rb"(?i)vssadmin\s+delete\s+shadows"),
    re.compile(rb"(?i)bcdedit.*recoveryenabled"),
    re.compile(rb"(?i)your files (have been|are) encrypted"),
    re.compile(rb"(?i)pay(?:ment)? in bitcoin"),
    re.compile(rb"(?i)readme[_\- ]decrypt"),
    re.compile(rb"(?i)powershell.*(-enc|-encodedcommand|frombase64string)"),
]

# How much of a file we sample for entropy + pattern matching.
_SAMPLE_BYTES = 512 * 1024
# Entropy threshold above which a file is considered packed/encrypted.
_ENTROPY_THRESHOLD = 7.5
# Below this size, high entropy is meaningless (small archives etc).
_MIN_ENTROPY_SIZE = 64 * 1024


def _entropy(b: bytes) -> float:
    if not b:
        return 0.0
    counts = Counter(b)
    n = len(b)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def is_suspicious(path: Path) -> tuple[bool, str]:
    """Cheap local triage to decide whether to upload to the central detector."""
    try:
        size = path.stat().st_size
    except OSError:
        return False, "unreadable"
    max_size = settings.upload_max_mb * 1024 * 1024
    if size == 0 or size > max_size:
        return False, "size"

    ext = path.suffix.lower()
    if ext in SUSPICIOUS_EXTS:
        return True, f"suspicious_extension:{ext}"

    try:
        with path.open("rb") as f:
            data = f.read(_SAMPLE_BYTES)
    except OSError:
        return False, "unreadable"

    if _entropy(data) > _ENTROPY_THRESHOLD and size > _MIN_ENTROPY_SIZE:
        return True, "high_entropy"

    for p in PATTERNS:
        if p.search(data):
            return True, f"pattern:{p.pattern[:30]!r}"

    return False, "clean"

