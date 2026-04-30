"""Unified ransomware / malware detector.

Combines:
  1. Heuristic scoring (always available, no model needed).
  2. ML scoring via a sklearn ensemble loaded from `models_dir/detector.joblib`.
  3. (Optional) YARA rule matching when `yara` is importable and rules exist.

The final score is a weighted average of the three signals.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib
import numpy as np

from app.core.config import settings
from app.core.logging import get_logger
from app.ml.features import FileFeatures, extract_features, extract_features_from_bytes

log = get_logger(__name__)

try:  # pragma: no cover - optional dep
    import yara  # type: ignore[import-not-found]

    YARA_AVAILABLE = True
except ImportError:  # pragma: no cover
    yara = None  # type: ignore[assignment]
    YARA_AVAILABLE = False


@dataclass
class DetectionResult:
    is_threat: bool
    confidence: float
    severity: str
    threat_type: str
    score_heuristic: float
    score_ml: float | None
    score_yara: float | None
    indicators: dict[str, Any]
    matched_rules: list[str]
    sha256: str
    description: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_threat": self.is_threat,
            "confidence": round(self.confidence, 4),
            "severity": self.severity,
            "threat_type": self.threat_type,
            "score_heuristic": round(self.score_heuristic, 4),
            "score_ml": round(self.score_ml, 4) if self.score_ml is not None else None,
            "score_yara": round(self.score_yara, 4) if self.score_yara is not None else None,
            "indicators": self.indicators,
            "matched_rules": self.matched_rules,
            "sha256": self.sha256,
            "description": self.description,
        }


class UnifiedDetector:
    """Heuristic + ML + YARA detector. Thread-safe for read-only access after load."""

    def __init__(self) -> None:
        self._model: Any | None = None
        self._scaler: Any | None = None
        self._yara_rules: Any | None = None
        self._loaded = False

    # ─── Lifecycle ───────────────────────────────────────────────────────
    def load(self) -> None:
        """Idempotent load of model + YARA rules."""
        if self._loaded:
            return

        models_dir = Path(settings.models_dir)
        bundle_path = models_dir / "detector.joblib"
        if bundle_path.exists():
            try:
                bundle = joblib.load(bundle_path)
                self._model = bundle.get("model")
                self._scaler = bundle.get("scaler")
                log.info("ml.detector.loaded", path=str(bundle_path))
            except Exception as exc:  # pragma: no cover
                log.error("ml.detector.load_failed", error=str(exc))
        else:
            log.warning("ml.detector.no_model", hint="run scripts/train_detector.py")

        # YARA rules (optional)
        if YARA_AVAILABLE:
            rules_dir = Path(settings.rules_dir)
            yara_files = list(rules_dir.rglob("*.yar")) + list(rules_dir.rglob("*.yara"))
            if yara_files:
                try:
                    self._yara_rules = yara.compile(  # type: ignore[union-attr]
                        filepaths={f.stem: str(f) for f in yara_files}
                    )
                    log.info("ml.yara.compiled", count=len(yara_files))
                except Exception as exc:  # pragma: no cover
                    log.error("ml.yara.compile_failed", error=str(exc))

        self._loaded = True

    @property
    def ready(self) -> bool:
        return self._loaded

    # ─── Public analysis ─────────────────────────────────────────────────
    def analyze_path(self, file_path: str | os.PathLike) -> DetectionResult:
        feats = extract_features(file_path)
        return self._score(feats, path=str(file_path))

    def analyze_bytes(self, name: str, data: bytes) -> DetectionResult:
        feats = extract_features_from_bytes(name, data)
        return self._score(feats, raw=data)

    # ─── Internals ───────────────────────────────────────────────────────
    def _score(
        self,
        feats: FileFeatures,
        raw: bytes | None = None,
        path: str | None = None,
    ) -> DetectionResult:
        if feats.error:
            return DetectionResult(
                is_threat=False,
                confidence=0.0,
                severity="low",
                threat_type="unknown",
                score_heuristic=0.0,
                score_ml=None,
                score_yara=None,
                indicators={"error": feats.error},
                matched_rules=[],
                sha256=feats.sha256,
                description=f"Could not analyze: {feats.error}",
            )

        # Threat-Intel lookup short-circuit. A known-bad sha256 is the
        # highest-quality signal we have — overrides everything below.
        ti_hit = _ti_lookup_hash(feats.sha256)
        if ti_hit is not None:
            return DetectionResult(
                is_threat=True,
                confidence=max(0.95, ti_hit["confidence"]),
                severity="critical",
                threat_type=ti_hit.get("family") or "known_malware",
                score_heuristic=self._heuristic_score(feats),
                score_ml=None,
                score_yara=None,
                indicators={**feats.to_dict(), "ti": ti_hit},
                matched_rules=[f"ti:{ti_hit['source']}"],
                sha256=feats.sha256,
                description=(
                    f"SHA-256 matches known-malicious hash from {ti_hit['source']} "
                    f"(family={ti_hit.get('family') or 'unknown'})"
                ),
            )

        # Static-V2 — deep static analysis (multi-hash + PE deep + packers).
        # Then check the local TI DB for fuzzy / imphash matches.
        static_v2 = _static_v2_run(raw=raw, path=path)
        fuzzy_hit = _ti_fuzzy_lookup(static_v2) if static_v2 else None
        if fuzzy_hit is not None:
            return DetectionResult(
                is_threat=True,
                confidence=max(0.92, fuzzy_hit["confidence"]),
                severity="critical",
                threat_type=fuzzy_hit.get("family") or "known_malware_variant",
                score_heuristic=self._heuristic_score(feats),
                score_ml=None,
                score_yara=None,
                indicators={
                    **feats.to_dict(),
                    "static_v2": static_v2.to_dict() if static_v2 else None,
                    "ti_fuzzy": fuzzy_hit,
                },
                matched_rules=[f"ti_fuzzy:{fuzzy_hit['kind']}:{fuzzy_hit['source']}"],
                sha256=feats.sha256,
                description=(
                    f"Variant of known malware ({fuzzy_hit['kind']} match, "
                    f"score={fuzzy_hit['score']}, family={fuzzy_hit.get('family') or 'unknown'})"
                ),
            )

        h = self._heuristic_score(feats)
        m = self._ml_score(feats)
        y, matched = self._yara_score(feats, raw)

        # Static-V2 contributes a structural score (APT-import score + packer + WX section).
        s_static = _static_v2_score(static_v2)

        # Weighted aggregation. ML and YARA only contribute when available.
        weights: list[tuple[float, float]] = [
            (0.40 if (m is not None or y is not None) else 0.85, h)
        ]
        if m is not None:
            weights.append((0.30, m))
        if y is not None:
            weights.append((0.15, y))
        if s_static is not None:
            weights.append((0.15, s_static))
        total_w = sum(w for w, _ in weights)
        confidence = sum(w * s for w, s in weights) / total_w

        # Boost on strong YARA match
        if y is not None and y >= 0.9:
            confidence = max(confidence, 0.9)

        is_threat = confidence >= settings.threshold_low
        severity = self._severity(confidence)
        threat_type = self._classify(feats, matched)
        description = self._describe(feats, matched, severity)

        # Augment indicators with static-v2 + capability tags.
        indicators: dict[str, Any] = feats.to_dict()
        matched_rules = list(matched)
        if static_v2 is not None:
            indicators["static_v2"] = static_v2.to_dict()
            if static_v2.packer:
                matched_rules.append(f"packer:{static_v2.packer}")
            for cap in static_v2.capabilities:
                # ATT&CK technique IDs become rule-style tags.
                if cap.startswith("T") and "." in cap.split(" ", 1)[0] or cap.startswith("T1"):
                    matched_rules.append(f"attack:{cap.split(' ', 1)[0]}")

        return DetectionResult(
            is_threat=is_threat,
            confidence=confidence,
            severity=severity,
            threat_type=threat_type,
            score_heuristic=h,
            score_ml=m,
            score_yara=y,
            indicators=indicators,
            matched_rules=matched_rules,
            sha256=feats.sha256,
            description=description,
        )

    def _heuristic_score(self, feats: FileFeatures) -> float:
        score = 0.0
        # Suspicious extension
        score += feats.suspicious_ext_score * 0.4
        # Magic mismatch is a strong signal
        if feats.magic_mismatch:
            score += 0.45
        # Block-level high entropy (encrypted / packed)
        if feats.has_high_entropy_block:
            score += 0.25
        # Pattern hits — diminishing returns
        score += min(feats.pattern_count, 10) * 0.06
        # Strong indicators
        if feats.pattern_hits.get("ransom_note", 0) > 0:
            score += 0.40
        if feats.pattern_hits.get("shadow_copy_delete", 0) > 0:
            score += 0.35
        if feats.pattern_hits.get("encryption_api", 0) > 0:
            score += 0.20
        return float(min(score, 1.0))

    def _ml_score(self, feats: FileFeatures) -> float | None:
        if self._model is None:
            return None
        try:
            X = np.array([feats.to_vector()], dtype=float)
            if self._scaler is not None:
                X = self._scaler.transform(X)
            if hasattr(self._model, "predict_proba"):
                proba = self._model.predict_proba(X)[0]
                # Class 1 = malicious
                return float(proba[1] if len(proba) > 1 else proba[0])
            pred = self._model.predict(X)[0]
            return float(pred)
        except Exception as exc:  # pragma: no cover
            log.warning("ml.score_failed", error=str(exc))
            return None

    def _yara_score(
        self, feats: FileFeatures, raw: bytes | None
    ) -> tuple[float | None, list[str]]:
        if self._yara_rules is None:
            return None, []
        try:
            if raw is not None:
                matches = self._yara_rules.match(data=raw)
            else:
                # We need a path; reconstructing from feats is impossible — caller of
                # analyze_bytes already passes raw. For path mode we re-read.
                return None, []
            names = [m.rule for m in matches]
            score = min(1.0, 0.5 + 0.15 * len(names)) if names else 0.0
            return score, names
        except Exception as exc:  # pragma: no cover
            log.warning("yara.match_failed", error=str(exc))
            return None, []

    @staticmethod
    def _severity(confidence: float) -> str:
        if confidence >= settings.threshold_high:
            return "critical" if confidence >= 0.95 else "high"
        if confidence >= settings.threshold_medium:
            return "medium"
        if confidence >= settings.threshold_low:
            return "low"
        return "low"

    @staticmethod
    def _classify(feats: FileFeatures, matched_rules: list[str]) -> str:
        if feats.pattern_hits.get("ransom_note", 0) > 0:
            return "ransomware"
        if feats.pattern_hits.get("shadow_copy_delete", 0) > 0:
            return "ransomware"
        if any("ransom" in r.lower() for r in matched_rules):
            return "ransomware"
        if feats.pattern_hits.get("downloader", 0) > 0:
            return "downloader"
        if feats.pattern_hits.get("persistence", 0) > 0:
            return "trojan"
        if feats.has_high_entropy_block and feats.file_ext in {".exe", ".dll", ".scr"}:
            return "obfuscated_executable"
        if feats.magic_mismatch:
            return "file_signature_mismatch"
        if feats.suspicious_ext_score > 0:
            return "suspicious_executable"
        return "unknown"

    @staticmethod
    def _describe(feats: FileFeatures, matched: list[str], severity: str) -> str:
        bits: list[str] = []
        if feats.magic_mismatch:
            bits.append(f"extension {feats.file_ext} mismatches magic {feats.magic_ext}")
        if feats.has_high_entropy_block:
            bits.append(f"high-entropy block ({feats.entropy:.2f})")
        if feats.pattern_hits:
            top = sorted(feats.pattern_hits.items(), key=lambda kv: -kv[1])[:3]
            bits.append("patterns: " + ", ".join(f"{k}({v})" for k, v in top))
        if matched:
            bits.append(f"YARA: {', '.join(matched[:3])}")
        if not bits:
            return f"No strong indicator (severity={severity})."
        return "; ".join(bits)


# Module-level singleton
_detector: UnifiedDetector | None = None


def get_detector() -> UnifiedDetector:
    global _detector
    if _detector is None:
        _detector = UnifiedDetector()
        _detector.load()
    return _detector


def _ti_lookup_hash(sha256: str) -> dict[str, Any] | None:
    """Look up a sha256 in the local TI DB. Returns a dict or ``None``.

    Imported lazily and wrapped in a broad except so a TI-DB outage never
    blocks scoring. The detector path must keep working even with an empty
    or unreachable database.
    """
    if not sha256 or len(sha256) != 64:
        return None
    try:
        from app.db.session import SessionLocal  # local import: avoid cycle
        from app.intel.service import IntelService

        with SessionLocal() as db:
            row = IntelService(db).lookup_hash(sha256)
            if row is None:
                return None
            return {
                "source": row.source,
                "family": row.family,
                "signature": row.signature,
                "tags": list(row.tags or []),
                "confidence": float(row.confidence),
                "first_seen_at": row.first_seen_at.isoformat() if row.first_seen_at else None,
                "last_seen_at": row.last_seen_at.isoformat() if row.last_seen_at else None,
            }
    except Exception as exc:  # noqa: BLE001 — never break scoring
        log.warning("ti.lookup_failed", error=str(exc))
        return None


# ─── Static-V2 integration (Phase B) ─────────────────────────────────────
def _static_v2_run(
    raw: bytes | None = None,
    path: str | None = None,
):  # -> StaticV2Result | None
    """Run Static-V2 deep parsing. Always returns ``None`` on any failure."""
    try:
        from app.ml.static_v2 import analyze_bytes, analyze_path

        if raw is not None:
            return analyze_bytes(raw)
        if path is not None:
            return analyze_path(path)
    except Exception as exc:  # noqa: BLE001 — must never break scoring
        log.warning("static_v2.failed", error=str(exc))
    return None


def _static_v2_score(static_v2) -> float | None:
    """Convert Static-V2 indicators into a 0..1 score for the meta-aggregator."""
    if static_v2 is None or static_v2.parser_error == "file_not_found":
        return None
    score = 0.0
    # APT-import score is already normalized 0..1.
    score += 0.6 * float(static_v2.apt_score)
    if static_v2.packer:
        score += 0.25
    # Writable + executable section is a heavy red flag.
    if any(":WX" in s for s in static_v2.suspicious_sections):
        score += 0.20
    # Unsigned + missing Rich header on a PE = unusual.
    if static_v2.is_pe and not static_v2.has_signature:
        score += 0.05
    if static_v2.is_pe and not static_v2.has_rich_header:
        score += 0.05
    if static_v2.has_tls_callbacks:
        score += 0.10
    return min(score, 1.0)


def _ti_fuzzy_lookup(static_v2) -> dict[str, Any] | None:
    """Look up imphash / ssdeep / tlsh in the local TI DB.

    The detector calls this **after** the exact SHA-256 lookup misses.
    Returns the strongest fuzzy match or ``None``. Wrapped in a broad
    except so TI failures don't break detection.
    """
    if static_v2 is None:
        return None
    if not (static_v2.imphash or static_v2.ssdeep or static_v2.tlsh):
        return None
    try:
        from app.db.session import SessionLocal
        from app.intel.service import IntelService

        with SessionLocal() as db:
            svc = IntelService(db)
            # 1. imphash — exact match, very high precision.
            if static_v2.imphash:
                imp_rows = svc.lookup_imphash(static_v2.imphash)
                if imp_rows:
                    row = imp_rows[0]
                    return {
                        "kind": "imphash",
                        "score": 100,
                        "source": row.source,
                        "family": row.family,
                        "confidence": float(row.confidence),
                        "matched_sha256": row.sha256,
                    }
            # 2. ssdeep / tlsh fuzzy.
            fuzzy = svc.lookup_fuzzy(
                ssdeep_value=static_v2.ssdeep,
                tlsh_value=static_v2.tlsh,
            )
            if not fuzzy:
                return None
            # Keep the strongest hit. ssdeep score is 0-100 (higher better),
            # tlsh distance is lower-better — normalize to a comparable key.
            def _key(item: tuple) -> int:
                _row, kind, score = item
                return score if kind == "ssdeep" else (200 - score)

            row, kind, score = max(fuzzy, key=_key)
            return {
                "kind": kind,
                "score": int(score),
                "source": row.source,
                "family": row.family,
                "confidence": float(row.confidence),
                "matched_sha256": row.sha256,
            }
    except Exception as exc:  # noqa: BLE001
        log.warning("ti.fuzzy_lookup_failed", error=str(exc))
        return None
