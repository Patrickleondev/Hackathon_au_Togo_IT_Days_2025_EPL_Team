"""Beaconing detection on outbound connection timestamps.

Goal
----
A typical C2 beacon (Cobalt Strike, Empire, Sliver, Mythic) calls home on a
*regular* schedule with optional jitter. Looking at the timestamps of all
connections from a single ``(src_ip, dst_ip[, dst_port])`` tuple, periodic
behaviour is glaringly obvious in the frequency domain even when the period
itself is unknown.

We use a small custom periodogram instead of pulling in scipy:

1. Compute inter-arrival times Δt₁, Δt₂, …
2. Reject the trace if there are < 6 events or if its total duration is
   < 60 s — too short to be statistically meaningful.
3. For each candidate period ``T`` between 5 s and ``duration / 2`` we
   evaluate the *Rayleigh statistic*
   ``R(T) = | Σ exp(2πi · t_k / T) | / N``
   which is the magnitude of the discrete Fourier transform of the point
   process at frequency ``1/T``. R is in [0, 1]; perfectly periodic input
   gives R = 1, Poisson noise gives R ≈ 1/√N.
4. The best ``T*`` is the one maximising R, and ``score = R(T*)``.
5. Jitter is the standard deviation of ``(t_k mod T*) / T*``, normalised
   so a perfectly periodic stream has jitter = 0 and uniform noise has
   jitter ≈ 0.29.

References
----------
* Brian Wylie — *RITA: Real Intelligence Threat Analytics*,
  https://github.com/activecm/rita (the FFT/periodogram approach is now
  classic SOC tradecraft).
* Mardia & Jupp — *Directional Statistics* (Rayleigh test, ch. 7).
* MITRE ATT&CK T1071 — Application Layer Protocol; T1029 — Scheduled Transfer.

This module is pure-Python + ``math``; no numpy required. Heavy callers can
swap in ``numpy.fft.rfft`` if they want, but for ≤ a few thousand events the
naive O(N·K) periodogram is fine and removes a hard dependency.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, Sequence


@dataclass(slots=True, frozen=True)
class BeaconResult:
    """Beaconing analysis output for a single (src, dst) pair."""

    n_events: int
    duration_s: float
    period_s: float | None
    score: float           # 0..1, Rayleigh statistic at best period
    jitter: float          # 0..0.29 (uniform); 0 = perfect periodicity
    verdict: str           # benign | suspicious | beacon_likely | unknown


def _to_epoch(ts: datetime | float | int) -> float:
    if isinstance(ts, datetime):
        return ts.timestamp()
    return float(ts)


def _periodogram_at(ts: Sequence[float], period: float) -> float:
    """Rayleigh statistic at frequency 1/period — no numpy."""
    if period <= 0 or len(ts) < 2:
        return 0.0
    omega = 2.0 * math.pi / period
    cs = 0.0
    sn = 0.0
    for t in ts:
        cs += math.cos(omega * t)
        sn += math.sin(omega * t)
    n = len(ts)
    return math.sqrt(cs * cs + sn * sn) / n


def _candidate_periods(duration: float) -> list[float]:
    """Logarithmically spaced trial periods in [5 s, duration/2]."""
    lo = 5.0
    hi = max(lo + 1.0, duration / 2.0)
    if hi <= lo:
        return []
    # ~64 candidates — fine resolution while staying O(N·K) cheap.
    n = 64
    log_lo = math.log(lo)
    log_hi = math.log(hi)
    step = (log_hi - log_lo) / (n - 1)
    return [math.exp(log_lo + i * step) for i in range(n)]


def _refine(ts: Sequence[float], around: float) -> tuple[float, float]:
    """Local refinement around the best candidate (golden-section style)."""
    lo = max(1.0, around * 0.85)
    hi = around * 1.15
    best_p, best_r = around, _periodogram_at(ts, around)
    for _ in range(20):
        mid_lo = lo + (hi - lo) / 3
        mid_hi = hi - (hi - lo) / 3
        r_lo = _periodogram_at(ts, mid_lo)
        r_hi = _periodogram_at(ts, mid_hi)
        if r_lo > r_hi:
            hi = mid_hi
            if r_lo > best_r:
                best_p, best_r = mid_lo, r_lo
        else:
            lo = mid_lo
            if r_hi > best_r:
                best_p, best_r = mid_hi, r_hi
    return best_p, best_r


def _phase_jitter(ts: Sequence[float], period: float) -> float:
    """Std-dev of phase ``(t_k mod period) / period`` after centring."""
    if period <= 0 or len(ts) < 2:
        return 1.0
    phases = [(t % period) / period for t in ts]
    # Circular mean, then mean angular distance to it.
    s = sum(math.sin(2 * math.pi * p) for p in phases) / len(phases)
    c = sum(math.cos(2 * math.pi * p) for p in phases) / len(phases)
    mu = math.atan2(s, c)
    diffs = []
    for p in phases:
        ang = 2 * math.pi * p
        d = abs(((ang - mu + math.pi) % (2 * math.pi)) - math.pi)
        diffs.append(d / (2 * math.pi))
    if not diffs:
        return 1.0
    mean = sum(diffs) / len(diffs)
    var = sum((d - mean) ** 2 for d in diffs) / len(diffs)
    return math.sqrt(var)


def _verdict(score: float, n: int) -> str:
    if n < 6:
        return "unknown"
    if score >= 0.85:
        return "beacon_likely"
    if score >= 0.65:
        return "suspicious"
    return "benign"


# ─── Public API ───────────────────────────────────────────────────────────
def detect_beacon(
    timestamps: Iterable[datetime | float],
    *,
    min_events: int = 6,
    min_duration_s: float = 60.0,
) -> BeaconResult:
    """Analyse a sequence of connection timestamps for beaconing periodicity.

    The input must come from a *single* logical channel — e.g. all SYNs from
    one ``(src_ip, dst_ip, dst_port)`` tuple over the past hour. Mixing
    channels destroys periodicity.
    """
    ts = sorted(_to_epoch(x) for x in timestamps)
    n = len(ts)
    if n == 0:
        return BeaconResult(0, 0.0, None, 0.0, 1.0, "unknown")

    duration = ts[-1] - ts[0]
    if n < min_events or duration < min_duration_s:
        return BeaconResult(n, duration, None, 0.0, 1.0, "unknown")

    # Normalise t_0 = 0 — improves numerical stability.
    t0 = ts[0]
    ts = [t - t0 for t in ts]

    candidates = _candidate_periods(duration)
    scored = [(c, _periodogram_at(ts, c)) for c in candidates]
    if not scored:
        return BeaconResult(n, duration, None, 0.0, 1.0, "unknown")

    # A perfectly periodic point process produces equally-strong peaks at
    # every divisor of its true period T (a Dirac comb's spectrum is itself
    # a comb). Naively picking ``argmax`` therefore lands on the smallest
    # candidate that happens to divide T, which is wrong. We instead:
    #   1. Identify the maximum Rayleigh statistic ``R*``.
    #   2. Walk integer multiples ``k·c`` of every near-best candidate
    #      and keep those whose statistic is still within 5 % of ``R*``.
    #   3. Pick the *largest* surviving period — the fundamental.
    best_r = max(r for _, r in scored)
    threshold = best_r * 0.95
    near_best = [c for c, r in scored if r >= threshold]

    extended: list[tuple[float, float]] = []
    seen: set[float] = set()
    for c in near_best:
        k = 1
        while True:
            T = c * k
            if T > duration:
                break
            key = round(T, 2)
            if key in seen:
                k += 1
                continue
            seen.add(key)
            r = _periodogram_at(ts, T)
            if r >= threshold:
                extended.append((T, r))
            k += 1

    if extended:
        best_p, best_r = max(extended, key=lambda x: x[0])
    else:
        best_p, best_r = max(scored, key=lambda x: x[1])

    if best_p > 0:
        best_p, best_r = _refine(ts, best_p)

    jitter = _phase_jitter(ts, best_p) if best_p > 0 else 1.0
    return BeaconResult(
        n_events=n,
        duration_s=duration,
        period_s=round(best_p, 3) if best_p > 0 else None,
        score=round(best_r, 4),
        jitter=round(jitter, 4),
        verdict=_verdict(best_r, n),
    )
