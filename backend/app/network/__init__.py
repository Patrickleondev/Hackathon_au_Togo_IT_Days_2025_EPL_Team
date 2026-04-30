"""Network-V2 subsystem (Phase C).

Components:

* :mod:`app.network.dga` — Domain-generation-algorithm detector (lexical +
  n-gram) returning a 0..1 score.
* :mod:`app.network.beaconing` — FFT/periodicity detector on inter-arrival
  times of outbound connections.
* :mod:`app.network.ja3` — JA3/JA4 TLS fingerprint normalisation + known-bad
  lookup.
* :mod:`app.network.ingest` — Parsers for Suricata ``eve.json`` and Zeek
  ``conn.log`` / ``dns.log`` / ``ssl.log`` records.
* :mod:`app.network.service` — Orchestrator persisting events, computing
  beaconing scores and exposing read endpoints.

Like :mod:`app.intel`, every public entry-point degrades gracefully if a
native dependency (numpy, scipy) is missing — the detector path must never
break because the network subsystem is unavailable.
"""

from app.network.beaconing import (  # noqa: F401
    BeaconResult,
    detect_beacon,
)
from app.network.dga import dga_score, is_dga_like  # noqa: F401
from app.network.ja3 import (  # noqa: F401
    JA3Match,
    is_known_bad_ja3,
    normalise_ja3,
)

__all__ = [
    "BeaconResult",
    "JA3Match",
    "detect_beacon",
    "dga_score",
    "is_dga_like",
    "is_known_bad_ja3",
    "normalise_ja3",
]
