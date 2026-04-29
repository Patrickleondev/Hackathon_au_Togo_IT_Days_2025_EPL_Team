from app.ml.features import extract_features_from_bytes


def test_benign_text_features():
    f = extract_features_from_bytes("note.txt", b"hello world\n")
    assert not f.error
    assert f.magic_mismatch is False
    assert f.suspicious_ext_score < 0.3


def test_malicious_bat_features():
    payload = b"vssadmin delete shadows /all /quiet\nbcdedit /set {default} recoveryenabled No\n"
    f = extract_features_from_bytes("ransom.bat", payload)
    assert f.suspicious_ext_score >= 0.5
    assert f.pattern_hits.get("shadow_copy_delete", 0) >= 1
    assert f.pattern_hits.get("bcdedit_recovery", 0) >= 1
    assert f.pattern_count >= 2
