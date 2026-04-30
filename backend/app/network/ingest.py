"""Parsers for Suricata ``eve.json`` and Zeek TSV / JSON logs.

Both Suricata and Zeek are typically run as a *sidecar* alongside the
backend and stream their findings to ``POST /api/network/events``. We
support two ingestion modes:

1. **Pre-parsed** — the sidecar already extracted relevant fields and
   submits a :class:`NetworkEventIn` payload. Cheapest, recommended.
2. **Raw** — the sidecar dumps a single ``eve.json`` line or a Zeek
   ``conn.log`` row and we parse here. Useful for ad-hoc CLI scripts.

This module only handles parsing. Persistence happens in
:mod:`app.network.service`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(slots=True)
class NetworkEventIn:
    """Normalised network event flowing through the pipeline.

    All fields are optional except ``ts``, ``src_ip``, ``dst_ip`` and
    ``proto``. Higher-level analytics (DGA, beaconing, JA3) consume this
    structure and may fill ``risk`` / ``risk_factors`` along the way.
    """

    ts: datetime
    src_ip: str
    dst_ip: str
    proto: str                          # tcp | udp | icmp
    src_port: int | None = None
    dst_port: int | None = None
    bytes_in: int | None = None
    bytes_out: int | None = None
    domain: str | None = None           # DNS query name
    sni: str | None = None              # TLS SNI
    http_host: str | None = None
    http_uri: str | None = None
    http_user_agent: str | None = None
    ja3: str | None = None
    ja4: str | None = None
    suricata_alert: str | None = None
    suricata_severity: int | None = None
    risk: float = 0.0
    risk_factors: list[str] = field(default_factory=list)
    source: str = "agent"               # agent | suricata | zeek | manual

    def to_dict(self) -> dict[str, Any]:
        return {
            "ts": self.ts.isoformat(),
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "proto": self.proto,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "bytes_in": self.bytes_in,
            "bytes_out": self.bytes_out,
            "domain": self.domain,
            "sni": self.sni,
            "http_host": self.http_host,
            "http_uri": self.http_uri,
            "http_user_agent": self.http_user_agent,
            "ja3": self.ja3,
            "ja4": self.ja4,
            "suricata_alert": self.suricata_alert,
            "suricata_severity": self.suricata_severity,
            "risk": self.risk,
            "risk_factors": list(self.risk_factors),
            "source": self.source,
        }


def _parse_ts(s: str) -> datetime:
    """Parse Suricata / Zeek timestamps. Both emit ISO-8601 with 'Z' suffix."""
    if not s:
        return datetime.now(timezone.utc)
    s = s.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        try:
            return datetime.fromtimestamp(float(s), tz=timezone.utc)
        except (ValueError, OSError):
            return datetime.now(timezone.utc)


# ─── Suricata eve.json ────────────────────────────────────────────────────
def parse_suricata_eve(line: str | dict[str, Any]) -> NetworkEventIn | None:
    """Parse one ``eve.json`` line. Returns None for events we don't model.

    Suricata emits one JSON document per network event. Useful event types:
    ``flow``, ``dns``, ``http``, ``tls``, ``alert``. We only persist events
    that carry actionable signal.
    """
    try:
        rec: dict[str, Any] = json.loads(line) if isinstance(line, str) else line
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(rec, dict):
        return None

    etype = rec.get("event_type")
    if etype not in {"flow", "dns", "http", "tls", "alert"}:
        return None

    src_ip = rec.get("src_ip") or ""
    dst_ip = rec.get("dest_ip") or ""
    if not src_ip or not dst_ip:
        return None

    proto = (rec.get("proto") or "").lower() or "tcp"
    ev = NetworkEventIn(
        ts=_parse_ts(rec.get("timestamp", "")),
        src_ip=src_ip,
        dst_ip=dst_ip,
        proto=proto,
        src_port=rec.get("src_port"),
        dst_port=rec.get("dest_port"),
        source="suricata",
    )

    if etype == "flow":
        flow = rec.get("flow") or {}
        ev.bytes_in = flow.get("bytes_toclient")
        ev.bytes_out = flow.get("bytes_toserver")
    elif etype == "dns":
        dns = rec.get("dns") or {}
        ev.domain = (dns.get("rrname") or "").rstrip(".").lower() or None
    elif etype == "http":
        http = rec.get("http") or {}
        ev.http_host = http.get("hostname")
        ev.http_uri = http.get("url")
        ev.http_user_agent = http.get("http_user_agent")
    elif etype == "tls":
        tls = rec.get("tls") or {}
        ev.sni = tls.get("sni")
        ev.ja3 = (tls.get("ja3") or {}).get("hash") if isinstance(tls.get("ja3"), dict) else tls.get("ja3")
        ev.ja4 = tls.get("ja4")
    elif etype == "alert":
        alert = rec.get("alert") or {}
        ev.suricata_alert = alert.get("signature")
        ev.suricata_severity = alert.get("severity")

    return ev


# ─── Zeek TSV / JSON ──────────────────────────────────────────────────────
_ZEEK_CONN_FIELDS = (
    # Standard zeek conn.log column order (subset). Newer versions add fields
    # to the right — we tolerate extras.
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
    "proto", "service", "duration", "orig_bytes", "resp_bytes",
)


def parse_zeek_conn(line: str) -> NetworkEventIn | None:
    """Parse one tab-separated Zeek ``conn.log`` row. Skips header / comments."""
    if not line or line.startswith("#"):
        return None
    parts = line.rstrip("\n").split("\t")
    if len(parts) < len(_ZEEK_CONN_FIELDS):
        return None
    rec = dict(zip(_ZEEK_CONN_FIELDS, parts))
    src_ip = rec.get("id.orig_h") or ""
    dst_ip = rec.get("id.resp_h") or ""
    if not src_ip or not dst_ip:
        return None
    return NetworkEventIn(
        ts=_parse_ts(rec.get("ts", "")),
        src_ip=src_ip,
        dst_ip=dst_ip,
        proto=(rec.get("proto") or "tcp").lower(),
        src_port=_int_or_none(rec.get("id.orig_p")),
        dst_port=_int_or_none(rec.get("id.resp_p")),
        bytes_in=_int_or_none(rec.get("resp_bytes")),
        bytes_out=_int_or_none(rec.get("orig_bytes")),
        source="zeek",
    )


def parse_zeek_dns(line: str) -> NetworkEventIn | None:
    """Parse a Zeek ``dns.log`` JSON row (Zeek's ``json`` plugin output)."""
    if not line or line.startswith("#"):
        return None
    try:
        rec = json.loads(line)
    except json.JSONDecodeError:
        return None
    src_ip = rec.get("id.orig_h") or rec.get("id_orig_h") or ""
    dst_ip = rec.get("id.resp_h") or rec.get("id_resp_h") or ""
    if not src_ip or not dst_ip:
        return None
    return NetworkEventIn(
        ts=_parse_ts(rec.get("ts", "")),
        src_ip=src_ip,
        dst_ip=dst_ip,
        proto="udp",
        src_port=rec.get("id.orig_p") or rec.get("id_orig_p"),
        dst_port=53,
        domain=(rec.get("query") or "").rstrip(".").lower() or None,
        source="zeek",
    )


def parse_zeek_ssl(line: str) -> NetworkEventIn | None:
    """Parse a Zeek ``ssl.log`` JSON row to extract SNI + JA3."""
    if not line or line.startswith("#"):
        return None
    try:
        rec = json.loads(line)
    except json.JSONDecodeError:
        return None
    src_ip = rec.get("id.orig_h") or rec.get("id_orig_h") or ""
    dst_ip = rec.get("id.resp_h") or rec.get("id_resp_h") or ""
    if not src_ip or not dst_ip:
        return None
    return NetworkEventIn(
        ts=_parse_ts(rec.get("ts", "")),
        src_ip=src_ip,
        dst_ip=dst_ip,
        proto="tcp",
        src_port=rec.get("id.orig_p") or rec.get("id_orig_p"),
        dst_port=rec.get("id.resp_p") or rec.get("id_resp_p") or 443,
        sni=rec.get("server_name"),
        ja3=rec.get("ja3"),
        ja4=rec.get("ja4"),
        source="zeek",
    )


def _int_or_none(v: Any) -> int | None:
    try:
        if v in (None, "-", ""):
            return None
        return int(v)
    except (TypeError, ValueError):
        return None
