"""Tests for Phase C — Network-V2 detectors and ingest parsers."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from app.network.beaconing import detect_beacon
from app.network.dga import dga_score, is_dga_like
from app.network.ingest import (
    parse_suricata_eve,
    parse_zeek_conn,
    parse_zeek_dns,
    parse_zeek_ssl,
)
from app.network.ja3 import is_known_bad_ja3, normalise_ja3, normalise_ja4


# ─── DGA detector ─────────────────────────────────────────────────────────
def test_dga_benign_domains_score_low() -> None:
    for d in ["google.com", "wikipedia.org", "github.io", "togoitdays.tg"]:
        s = dga_score(d)
        assert s["score"] < 0.55, f"{d} -> {s}"


def test_dga_classic_dga_samples_score_high() -> None:
    # Conficker / Kraken / Locky-style labels — known DGA references.
    samples = [
        "qkjvbprwxchgflyz.com",
        "asdfghjklzxcvbnm.net",
        "xkqlmnzpfwbjydtv.org",
        "kxqzvbnmphdjwlfr.biz",
    ]
    flagged = sum(1 for d in samples if is_dga_like(d, threshold=0.55))
    assert flagged >= 3, f"Only {flagged}/4 flagged"


def test_dga_returns_full_feature_dict() -> None:
    s = dga_score("kxqzvbnmphdjwlfr.com")
    for k in ("score", "entropy", "bigram_logp_mean", "vowel_ratio",
              "max_consonant_run", "digit_ratio", "length", "verdict"):
        assert k in s


def test_dga_handles_garbage_input() -> None:
    assert dga_score("")["score"] == 0.0
    assert dga_score("...")["score"] == 0.0


# ─── Beaconing detector ───────────────────────────────────────────────────
def test_beacon_detects_perfect_periodicity() -> None:
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    # 60s period, 30 events
    ts = [base + timedelta(seconds=60 * i) for i in range(30)]
    res = detect_beacon(ts)
    assert res.verdict in {"beacon_likely", "suspicious"}
    assert res.score > 0.85
    assert res.period_s is not None and 55 < res.period_s < 65


def test_beacon_rejects_random_traffic() -> None:
    import random
    random.seed(42)
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    # Poisson noise
    ts = [base + timedelta(seconds=random.uniform(0, 1800)) for _ in range(40)]
    res = detect_beacon(ts)
    assert res.verdict == "benign"
    assert res.score < 0.65


def test_beacon_short_trace_returns_unknown() -> None:
    res = detect_beacon([datetime.now(timezone.utc)])
    assert res.verdict == "unknown"


# ─── JA3 / JA4 ────────────────────────────────────────────────────────────
def test_normalise_ja3_accepts_md5_hash() -> None:
    h = "a0e9f5d64349fb13191bc781f81f42e1"
    assert normalise_ja3(h) == h
    assert normalise_ja3(h.upper()) == h


def test_normalise_ja3_rejects_garbage() -> None:
    assert normalise_ja3("") == ""
    assert normalise_ja3("not-a-hash") == ""


def test_normalise_ja3_hashes_string_form() -> None:
    s = "771,49195-49199,0-23-65281-10-11,23-24,0"
    h = normalise_ja3(s)
    assert len(h) == 32 and all(c in "0123456789abcdef" for c in h)


def test_normalise_ja4_basic() -> None:
    # JA4 format: <part_a>_<12hex>_<12hex>
    valid = "q13d1516h2_8daaf6152771_e5627efa2ab1"
    assert normalise_ja4(valid) == valid
    assert normalise_ja4("garbage") == ""


def test_known_bad_ja3_cobalt_strike() -> None:
    m = is_known_bad_ja3("a0e9f5d64349fb13191bc781f81f42e1")
    assert m is not None
    assert m.family == "CobaltStrike"


def test_known_bad_ja3_unknown_returns_none() -> None:
    assert is_known_bad_ja3("0" * 32) is None


# ─── Suricata eve.json parser ─────────────────────────────────────────────
def test_parse_suricata_dns_event() -> None:
    rec = {
        "timestamp": "2026-04-30T10:00:00.000000+0000",
        "event_type": "dns",
        "src_ip": "10.0.0.5",
        "dest_ip": "8.8.8.8",
        "src_port": 49152,
        "dest_port": 53,
        "proto": "udp",
        "dns": {"rrname": "Evil.example.com.", "rrtype": "A"},
    }
    ev = parse_suricata_eve(json.dumps(rec))
    assert ev is not None
    assert ev.domain == "evil.example.com"
    assert ev.dst_port == 53
    assert ev.source == "suricata"


def test_parse_suricata_tls_event() -> None:
    rec = {
        "timestamp": "2026-04-30T10:00:00Z",
        "event_type": "tls",
        "src_ip": "10.0.0.5",
        "dest_ip": "1.2.3.4",
        "proto": "TCP",
        "tls": {
            "sni": "victim.local",
            "ja3": {"hash": "a0e9f5d64349fb13191bc781f81f42e1"},
        },
    }
    ev = parse_suricata_eve(rec)
    assert ev is not None
    assert ev.sni == "victim.local"
    assert ev.ja3 == "a0e9f5d64349fb13191bc781f81f42e1"


def test_parse_suricata_skips_unknown_event_types() -> None:
    assert parse_suricata_eve('{"event_type":"stats"}') is None
    assert parse_suricata_eve("not-json") is None


# ─── Zeek parsers ─────────────────────────────────────────────────────────
def test_parse_zeek_conn_row() -> None:
    line = "1714465200.123\tabc123\t10.0.0.5\t49152\t1.2.3.4\t443\ttcp\tssl\t30.5\t1024\t8192"
    ev = parse_zeek_conn(line)
    assert ev is not None
    assert ev.src_ip == "10.0.0.5"
    assert ev.dst_port == 443
    assert ev.bytes_out == 1024
    assert ev.bytes_in == 8192


def test_parse_zeek_dns_json() -> None:
    rec = {
        "ts": "2026-04-30T10:00:00Z",
        "id.orig_h": "10.0.0.5",
        "id.resp_h": "8.8.8.8",
        "id.orig_p": 49152,
        "query": "Evil.example.com.",
    }
    ev = parse_zeek_dns(json.dumps(rec))
    assert ev is not None
    assert ev.domain == "evil.example.com"


def test_parse_zeek_ssl_json() -> None:
    rec = {
        "ts": "2026-04-30T10:00:00Z",
        "id.orig_h": "10.0.0.5",
        "id.resp_h": "1.2.3.4",
        "server_name": "victim.local",
        "ja3": "a0e9f5d64349fb13191bc781f81f42e1",
    }
    ev = parse_zeek_ssl(json.dumps(rec))
    assert ev is not None
    assert ev.ja3 == "a0e9f5d64349fb13191bc781f81f42e1"
    assert ev.sni == "victim.local"


def test_parse_zeek_skips_comments_and_empty() -> None:
    assert parse_zeek_conn("# header") is None
    assert parse_zeek_conn("") is None
