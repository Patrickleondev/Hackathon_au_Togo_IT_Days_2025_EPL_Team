"""Static-V2 — deep static analysis for the unified detector (Phase B).

This module augments the lightweight feature extractor in :mod:`app.ml.features`
with **deep** static signals that target real-world malware:

* **Fuzzy hashes** — ssdeep, TLSH and imphash. These let us match samples
  against the local TI database (``intel_hashes``) even when a single byte
  has been flipped (one-byte mutation completely changes SHA-256, but the
  fuzzy hash distance stays close to zero).
* **PE deep parser** — section anomalies, suspicious-import categories,
  Rich-header presence, Authenticode signature presence and TLS callbacks.
* **Packer detection** — UPX / Themida / VMProtect / ASPack / Enigma…
  identified through section-name heuristics + byte signatures.

All native dependencies (``pefile``, ``ssdeep``, ``tlsh``) are **optional**.
If a library is missing the related signals are skipped — the detector
keeps working in degraded mode. This is critical so the Docker image can
boot on platforms where ssdeep's libfuzzy is awkward to install.

References
----------
* EMBER feature set — https://github.com/elastic/ember
* pefile docs — https://github.com/erocarrera/pefile
* TLSH — https://tlsh.org/
* ssdeep — https://ssdeep-project.github.io/ssdeep/
* PEiD signatures — https://github.com/wolfram77web/app-peid
* Detect-It-Easy — https://github.com/horsicq/Detect-It-Easy
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from app.core.logging import get_logger

log = get_logger(__name__)

# ─── Optional native deps ────────────────────────────────────────────────
try:  # pragma: no cover — optional
    import pefile  # type: ignore[import-not-found]

    _PEFILE = True
except ImportError:  # pragma: no cover
    pefile = None  # type: ignore[assignment]
    _PEFILE = False

try:  # pragma: no cover — optional
    import ssdeep  # type: ignore[import-not-found]

    _SSDEEP = True
except ImportError:  # pragma: no cover
    ssdeep = None  # type: ignore[assignment]
    _SSDEEP = False

try:  # pragma: no cover — optional
    import tlsh  # type: ignore[import-not-found]

    _TLSH = True
except ImportError:  # pragma: no cover
    tlsh = None  # type: ignore[assignment]
    _TLSH = False


# ─── Suspicious-import taxonomy ───────────────────────────────────────────
# A small, curated mapping. Bigger taxonomies (Mandiant capa, MITRE ATT&CK)
# are integrated separately; this one focuses on the highest-signal APIs.
SUSPICIOUS_IMPORTS: dict[str, set[str]] = {
    "process_injection": {
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
        "NtCreateThreadEx", "QueueUserAPC", "SetThreadContext",
        "NtMapViewOfSection", "NtUnmapViewOfSection", "RtlCreateUserThread",
    },
    "anti_debug": {
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess", "OutputDebugStringA", "NtSetInformationThread",
    },
    "anti_vm": {
        "GetSystemFirmwareTable", "Wow64DisableWow64FsRedirection",
    },
    "crypto": {
        "CryptEncrypt", "CryptDecrypt", "CryptGenKey", "CryptAcquireContextA",
        "BCryptEncrypt", "BCryptDecrypt", "BCryptGenerateSymmetricKey",
    },
    "persistence": {
        "RegSetValueExA", "RegSetValueExW", "CreateServiceA", "CreateServiceW",
        "StartServiceA", "StartServiceW",
    },
    "discovery": {
        "GetUserNameA", "GetComputerNameA", "GetAdaptersInfo",
        "NetUserGetInfo", "NetWkstaGetInfo",
    },
    "network": {
        "InternetOpenA", "InternetOpenUrlA", "HttpSendRequestA",
        "WinHttpOpen", "WinHttpConnect", "URLDownloadToFileA",
        "WSAStartup", "send", "recv", "connect",
    },
    "shadow_copy": {
        # Not directly imported, but DeleteFile + CreateFileW patterns plus
        # vssapi.dll imports are strong signals.
        "DeleteFileA", "DeleteFileW", "MoveFileExA", "MoveFileExW",
    },
    "lolbin_friendly": {
        "ShellExecuteA", "ShellExecuteW", "ShellExecuteExA", "WinExec",
        "CreateProcessA", "CreateProcessW",
    },
}

# Packer fingerprints. Each entry yields a tag when matched.
# Order matters — we stop at the first hit.
PACKER_SECTIONS: list[tuple[str, str]] = [
    ("UPX", "UPX0"), ("UPX", "UPX1"), ("UPX", "UPX!"),
    ("ASPack", ".aspack"), ("ASPack", ".adata"),
    ("Themida", ".themida"), ("Themida", ".vmp0"), ("VMProtect", ".vmp1"),
    ("VMProtect", ".vmp2"),
    ("Enigma", ".enigma1"), ("Enigma", ".enigma2"),
    ("MPRESS", ".MPRESS1"), ("MPRESS", ".MPRESS2"),
    ("PECompact", "pec1"), ("PECompact", "pec2"),
    ("FSG", "FSG!"),
    ("PEtite", ".petite"),
    ("NsPack", ".nsp0"), ("NsPack", ".nsp1"),
]

# Byte signatures (offset 0). Used as a fallback / cross-check.
PACKER_BYTES: list[tuple[str, bytes]] = [
    ("UPX", b"UPX!"),
    ("MPRESS", b"MPRESS"),
]


# ─── Result dataclass ────────────────────────────────────────────────────
@dataclass
class StaticV2Result:
    """Output of :func:`analyze`.

    All fields are JSON-serializable so the result can be embedded directly
    in :class:`app.ml.detector.DetectionResult.indicators`.
    """

    # Multi-hash
    sha1: str | None = None
    md5: str | None = None
    ssdeep: str | None = None
    tlsh: str | None = None
    imphash: str | None = None

    # PE structure
    is_pe: bool = False
    machine: str | None = None
    is_dll: bool = False
    is_driver: bool = False
    has_signature: bool = False
    has_rich_header: bool = False
    has_tls_callbacks: bool = False
    section_count: int = 0
    suspicious_sections: list[str] = field(default_factory=list)

    # Imports
    import_count: int = 0
    suspicious_import_categories: dict[str, list[str]] = field(default_factory=dict)
    apt_score: float = 0.0  # 0..1, derived from suspicious-import categories

    # Packers / obfuscation
    packer: str | None = None
    packer_evidence: list[str] = field(default_factory=list)

    # Errors / capabilities
    parser_error: str | None = None
    capabilities: list[str] = field(default_factory=list)  # human-readable tags

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ─── Public API ──────────────────────────────────────────────────────────
def analyze_path(path: str | os.PathLike) -> StaticV2Result:
    """Run the full Static-V2 pipeline on a file path."""
    p = Path(path)
    if not p.exists() or not p.is_file():
        return StaticV2Result(parser_error="file_not_found")
    try:
        with p.open("rb") as f:
            data = f.read()
    except OSError as exc:
        return StaticV2Result(parser_error=f"read_error: {exc}")
    return analyze_bytes(data)


def analyze_bytes(data: bytes) -> StaticV2Result:
    """Run the full Static-V2 pipeline on in-memory bytes."""
    result = StaticV2Result()
    if not data:
        result.parser_error = "empty_buffer"
        return result

    # Multi-hash — cheap, always run.
    result.sha1 = hashlib.sha1(data).hexdigest()  # noqa: S324 — hash for IOC, not crypto
    result.md5 = hashlib.md5(data).hexdigest()  # noqa: S324 — hash for IOC, not crypto
    result.ssdeep = _ssdeep_hash(data)
    result.tlsh = _tlsh_hash(data)

    # PE parsing — only if MZ header.
    if data[:2] == b"MZ":
        _enrich_pe(result, data)

    # Packer detection — runs even without pefile (byte signatures).
    _detect_packer(result, data)

    # Aggregate human-readable capability tags.
    _summarize_capabilities(result)

    return result


# ─── Fuzzy hashes ────────────────────────────────────────────────────────
def _ssdeep_hash(data: bytes) -> str | None:
    if not _SSDEEP:
        return None
    try:
        return ssdeep.hash(data)  # type: ignore[union-attr]
    except Exception as exc:  # pragma: no cover  # noqa: BLE001
        log.debug("ssdeep.failed", error=str(exc))
        return None


def _tlsh_hash(data: bytes) -> str | None:
    """TLSH requires at least 50 bytes of varied input."""
    if not _TLSH or len(data) < 50:
        return None
    try:
        h = tlsh.hash(data)  # type: ignore[union-attr]
        # TLSH returns "TNULL" or empty for low-entropy input — treat as None.
        if not h or h == "TNULL":
            return None
        return h
    except Exception as exc:  # pragma: no cover  # noqa: BLE001
        log.debug("tlsh.failed", error=str(exc))
        return None


def ssdeep_compare(a: str, b: str) -> int:
    """Return ssdeep similarity 0..100 (or 0 if lib missing or error)."""
    if not _SSDEEP or not a or not b:
        return 0
    try:
        return int(ssdeep.compare(a, b))  # type: ignore[union-attr]
    except Exception:  # noqa: BLE001
        return 0


def tlsh_distance(a: str, b: str) -> int | None:
    """Return TLSH distance (lower is closer); ``None`` if unavailable.

    A distance ≤ 70 is generally considered "very similar"; ≤ 30 is
    almost certainly the same family.
    """
    if not _TLSH or not a or not b:
        return None
    try:
        return int(tlsh.diff(a, b))  # type: ignore[union-attr]
    except Exception:  # noqa: BLE001
        return None


# ─── PE parsing ──────────────────────────────────────────────────────────
def _enrich_pe(result: StaticV2Result, data: bytes) -> None:
    """Populate PE-related fields. Falls back gracefully when pefile is missing."""
    if not _PEFILE:
        result.parser_error = "pefile_unavailable"
        return
    try:
        pe = pefile.PE(data=data, fast_load=True)  # type: ignore[union-attr]
        # Lazy-load directories that we actually need.
        pe.parse_data_directories(  # type: ignore[union-attr]
            directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],  # type: ignore[union-attr]
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"],  # type: ignore[union-attr]
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"],  # type: ignore[union-attr]
            ]
        )
    except Exception as exc:  # noqa: BLE001
        result.parser_error = f"pe_parse_failed: {exc}"
        return

    result.is_pe = True
    machine_map = {0x14C: "i386", 0x8664: "amd64", 0x1C0: "arm", 0xAA64: "arm64"}
    result.machine = machine_map.get(int(pe.FILE_HEADER.Machine), hex(pe.FILE_HEADER.Machine))
    chars = int(pe.FILE_HEADER.Characteristics)
    result.is_dll = bool(chars & 0x2000)
    # IMAGE_FILE_SYSTEM = 0x1000 → kernel driver indicator
    result.is_driver = bool(chars & 0x1000)

    # Sections
    sections = list(pe.sections)
    result.section_count = len(sections)
    suspicious: list[str] = []
    for s in sections:
        name = s.Name.rstrip(b"\x00").decode("latin-1", "replace") or "(empty)"
        # Writable + executable section is highly suspicious.
        if (s.Characteristics & 0x80000000) and (s.Characteristics & 0x20000000):
            suspicious.append(f"{name}:WX")
        # High entropy section (>7.0) often packed.
        try:
            if s.get_entropy() > 7.0:
                suspicious.append(f"{name}:high_entropy({s.get_entropy():.2f})")
        except Exception:  # noqa: BLE001
            pass
    result.suspicious_sections = suspicious

    # Rich header — Microsoft-linker fingerprint, missing in many crafted
    # samples and almost always present in legitimate MSVC builds.
    try:
        rich = pe.parse_rich_header()
        result.has_rich_header = bool(rich)
    except Exception:  # noqa: BLE001
        result.has_rich_header = False

    # Authenticode (digital signature directory non-empty).
    try:
        sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]  # type: ignore[union-attr]
        ]
        result.has_signature = sec_dir.Size > 0
    except Exception:  # noqa: BLE001
        result.has_signature = False

    # TLS callbacks — frequently abused for early code execution.
    result.has_tls_callbacks = hasattr(pe, "DIRECTORY_ENTRY_TLS")

    # imphash + import categorization.
    try:
        result.imphash = pe.get_imphash() or None
    except Exception:  # noqa: BLE001
        result.imphash = None

    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        per_category: dict[str, list[str]] = {}
        total = 0
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name is None:
                    continue
                total += 1
                api = imp.name.decode("latin-1", "replace")
                for cat, apis in SUSPICIOUS_IMPORTS.items():
                    if api in apis:
                        per_category.setdefault(cat, []).append(api)
                        break
        result.import_count = total
        result.suspicious_import_categories = per_category
        # APT score: ratio of *categories* hit, weighted by injection/anti-debug.
        weights = {
            "process_injection": 0.30, "anti_debug": 0.20, "anti_vm": 0.10,
            "crypto": 0.10, "persistence": 0.10, "discovery": 0.05,
            "network": 0.05, "shadow_copy": 0.05, "lolbin_friendly": 0.05,
        }
        score = sum(weights[c] for c in per_category if c in weights)
        result.apt_score = round(min(score, 1.0), 3)


# ─── Packer detection ────────────────────────────────────────────────────
_SECTION_NAME_RE = re.compile(rb"[\x00-\x7e]{1,8}")


def _detect_packer(result: StaticV2Result, data: bytes) -> None:
    """Tag a likely packer using section names, byte sigs and a high-entropy heuristic."""
    evidence: list[str] = []
    detected: str | None = None

    # 1. Section names from the parsed PE (preferred, more reliable).
    if result.is_pe and _PEFILE:
        try:
            pe = pefile.PE(data=data, fast_load=True)  # type: ignore[union-attr]
            names = [s.Name.rstrip(b"\x00").decode("latin-1", "replace") for s in pe.sections]
            for packer, marker in PACKER_SECTIONS:
                if any(n.startswith(marker) for n in names):
                    detected = packer
                    evidence.append(f"section:{marker}")
                    break
        except Exception:  # noqa: BLE001
            pass

    # 2. Byte signatures anywhere in the first 4 KiB (cheap fallback).
    head = data[:4096]
    for packer, sig in PACKER_BYTES:
        if sig in head:
            evidence.append(f"bytes:{sig.decode('latin-1', 'replace')}")
            detected = detected or packer

    # 3. Generic high-entropy + few imports = "likely packed".
    if (
        not detected
        and result.import_count > 0
        and result.import_count < 10
        and any("high_entropy" in s for s in result.suspicious_sections)
    ):
        detected = "generic_packer"
        evidence.append("heuristic:low_imports+high_entropy")

    result.packer = detected
    result.packer_evidence = evidence


# ─── Capability summary ──────────────────────────────────────────────────
def _summarize_capabilities(result: StaticV2Result) -> None:
    caps: list[str] = []
    cats = result.suspicious_import_categories
    if "process_injection" in cats:
        caps.append("T1055 Process Injection")
    if "anti_debug" in cats:
        caps.append("T1622 Debugger Evasion")
    if "anti_vm" in cats:
        caps.append("T1497 Virtualization/Sandbox Evasion")
    if "persistence" in cats:
        caps.append("T1547 Boot/Logon Autostart")
    if "crypto" in cats:
        caps.append("T1486 Data Encrypted for Impact")
    if "shadow_copy" in cats:
        caps.append("T1490 Inhibit System Recovery")
    if "network" in cats:
        caps.append("T1071 Application Layer Protocol")
    if "discovery" in cats:
        caps.append("T1082 System Information Discovery")
    if result.packer:
        caps.append(f"T1027.002 Software Packing ({result.packer})")
    if result.is_pe and not result.has_rich_header:
        caps.append("Missing Rich header (suspicious for MSVC binaries)")
    if result.is_pe and not result.has_signature:
        caps.append("Unsigned binary")
    if result.has_tls_callbacks:
        caps.append("TLS callbacks (early-execution vector)")
    result.capabilities = caps
