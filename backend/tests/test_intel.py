"""Tests for the threat-intelligence subsystem (Phase A).

These tests do **not** make real outbound HTTP calls. They exercise the
local DB primitives (``IntelService``) and the upsert helpers in
``app.intel.base`` with a stub feed.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from sqlalchemy.orm import Session

from app.db.models import IntelHash, IntelIndicator, IntelYaraRule
from app.db.session import Base, SessionLocal, engine
from app.intel.base import Feed
from app.intel.service import IntelService, prune_old_indicators


@pytest.fixture(autouse=True)
def _reset_intel_tables() -> None:
    """Ensure the intel tables exist and are empty for every test."""
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        db.query(IntelHash).delete()
        db.query(IntelIndicator).delete()
        db.query(IntelYaraRule).delete()
        db.commit()


@pytest.fixture
def db() -> Session:  # type: ignore[misc]
    with SessionLocal() as session:
        yield session


def _make_hash(db: Session, sha256: str = "a" * 64, family: str = "test_family") -> IntelHash:
    row = IntelHash(
        sha256=sha256,
        sha1=None,
        md5=None,
        family=family,
        signature="TestSig",
        source="malware_bazaar",
        tags=["apt", "test"],
        confidence=0.95,
        first_seen_at=datetime.now(timezone.utc),
        last_seen_at=datetime.now(timezone.utc),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def test_lookup_hash_hit(db: Session) -> None:
    sha = "f" * 64
    _make_hash(db, sha256=sha, family="lockbit")
    svc = IntelService(db)
    row = svc.lookup_hash(sha)
    assert row is not None
    assert row.family == "lockbit"


def test_lookup_hash_miss(db: Session) -> None:
    svc = IntelService(db)
    assert svc.lookup_hash("0" * 64) is None


def test_lookup_hash_invalid_length(db: Session) -> None:
    svc = IntelService(db)
    # Should not raise; just returns None.
    assert svc.lookup_hash("short") is None


def test_lookup_indicator(db: Session) -> None:
    db.add(
        IntelIndicator(
            indicator_type="ip",
            value="1.2.3.4",
            source="abuseipdb",
            confidence=1.0,
            first_seen_at=datetime.now(timezone.utc),
            last_seen_at=datetime.now(timezone.utc),
        )
    )
    db.commit()
    svc = IntelService(db)
    rows = svc.lookup_indicator("1.2.3.4")
    assert len(rows) == 1
    assert rows[0].indicator_type == "ip"


def test_stats_shape(db: Session) -> None:
    _make_hash(db)
    svc = IntelService(db)
    s = svc.stats()
    assert "hashes" in s
    assert "indicators" in s
    assert "yara_rules" in s
    assert s["hashes"]["total"] >= 1


def test_prune_keeps_recent(db: Session) -> None:
    _make_hash(db)
    deleted = prune_old_indicators(db)
    # Recent rows must not be pruned.
    assert deleted == 0


def test_detector_ti_short_circuits(db: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    """When a sha256 is in the TI DB, the detector must mark it as critical."""
    sha = "9" * 64
    _make_hash(db, sha256=sha, family="emotet")

    from app.ml import detector as detmod

    class _Feats:
        error = None
        sha256 = sha
        file_ext = ".exe"
        magic_ext = ".exe"
        magic_mismatch = False
        has_high_entropy_block = False
        entropy = 0.0
        suspicious_ext_score = 0.0
        pattern_count = 0
        pattern_hits: dict[str, int] = {}

        def to_dict(self) -> dict:
            return {"sha256": self.sha256}

        def to_vector(self) -> list[float]:
            return [0.0]

    det = detmod.UnifiedDetector()
    det._loaded = True  # skip model loading
    result = det._score(_Feats())  # type: ignore[arg-type]

    assert result.is_threat is True
    assert result.severity == "critical"
    assert result.threat_type == "emotet"
    assert any(r.startswith("ti:") for r in result.matched_rules)
