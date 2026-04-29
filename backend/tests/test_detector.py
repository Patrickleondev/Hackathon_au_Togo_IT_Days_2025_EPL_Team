from app.ml.detector import UnifiedDetector


def test_detector_flags_ransom_note():
    payload = (
        b"YOUR FILES HAVE BEEN ENCRYPTED!\n"
        b"Send 1 BTC to bc1qexampleexampleexampleexample0000\n"
        b"vssadmin delete shadows /all /quiet\n"
    )
    d = UnifiedDetector()
    res = d.analyze_bytes("readme_decrypt.txt", payload)
    assert res.is_threat is True
    assert res.confidence >= 0.5
    assert res.severity in ("medium", "high", "critical")


def test_detector_skips_clean_text():
    d = UnifiedDetector()
    res = d.analyze_bytes("notes.txt", b"shopping list: bread, eggs, milk")
    assert res.is_threat is False
    assert res.confidence < 0.5
