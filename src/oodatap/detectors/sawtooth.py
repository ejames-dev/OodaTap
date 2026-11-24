"""Detector 1: Encrypted Context-Growth Sawtooth & SSE Decode Cadence detector."""

from __future__ import annotations

from collections import defaultdict

import numpy as np

from oodatap.policy import PolicyConfig
from oodatap.schemas import SawtoothEvidence, TlsBurstEvent


def _kendall_tau_trend(values: np.ndarray) -> float:
    """Compute Kendall's tau rank correlation of a series against monotonic time index."""
    n = len(values)
    if n < 2:
        return 0.0
    concordant = 0
    discordant = 0
    for i in range(n - 1):
        diffs = values[i + 1 :] - values[i]
        concordant += int(np.sum(diffs > 64.0))
        discordant += int(np.sum(diffs < -64.0))
    denom = n * (n - 1) / 2.0
    return float((concordant - discordant) / denom) if denom > 0 else 0.0


def _score_endpoint_bursts(
    bursts: list[TlsBurstEvent],
    min_turns: int,
) -> SawtoothEvidence:
    ordered = sorted(bursts, key=lambda b: b.timestamp)
    n = len(ordered)
    if n < min_turns:
        return SawtoothEvidence(score=0.0, turn_count=n)

    uplinks = np.array([float(b.uplink_bytes) for b in ordered], dtype=np.float64)

    # Identify compaction / context-reset cliffs (>35% sharp drop from >=4KB context).
    cliff_indices: list[int] = []
    cliff_timestamps: list[float] = []
    for idx in range(1, n):
        prev_u = uplinks[idx - 1]
        cur_u = uplinks[idx]
        if prev_u >= 4000.0 and cur_u < 0.65 * prev_u:
            cliff_indices.append(idx)
            cliff_timestamps.append(ordered[idx].timestamp)

    # Split uplink series into contiguous growing segments between compaction cliffs.
    boundaries = [0, *cliff_indices, n]
    seg_taus: list[tuple[float, int]] = []
    seg_mono_ratios: list[tuple[float, int]] = []
    max_growth = 1.0

    for start, end in zip(boundaries[:-1], boundaries[1:], strict=False):
        seg = uplinks[start:end]
        if len(seg) < 3:
            continue
        seg_len = len(seg)
        seg_taus.append((_kendall_tau_trend(seg), seg_len))
        step_diffs = np.diff(seg)
        mono_ratio = float(np.mean(step_diffs > 64.0))
        seg_mono_ratios.append((mono_ratio, seg_len))
        seg_min = max(float(np.min(seg)), 1.0)
        seg_max = float(np.max(seg))
        max_growth = max(max_growth, seg_max / seg_min)

    if not seg_taus:
        weighted_tau = _kendall_tau_trend(uplinks)
        mono_ratio_weighted = float(np.mean(np.diff(uplinks) > 64.0)) if n > 1 else 0.0
        max_growth = float(np.max(uplinks)) / max(float(np.min(uplinks)), 1.0)
    else:
        total_w = sum(w for _, w in seg_taus)
        weighted_tau = sum(val * w for val, w in seg_taus) / total_w
        mono_ratio_weighted = sum(val * w for val, w in seg_mono_ratios) / total_w

    # Score SSE / token-streaming downlink framing characteristics.
    sse_hits = 0
    for b in ordered:
        mean_rec = b.downlink_bytes / max(1, b.downlink_record_count)
        plausible_ttft = 0.12 <= b.ttft_seconds <= 15.0
        streaming_records = b.downlink_record_count >= 4 and mean_rec <= 1800.0
        streaming_duration = b.decode_duration_seconds >= 0.15
        if plausible_ttft and (streaming_records or streaming_duration):
            sse_hits += 1
    sse_ratio = sse_hits / n

    tau_norm = float(np.clip((weighted_tau + 0.10) / 1.05, 0.0, 1.0))
    mono_norm = float(np.clip((mono_ratio_weighted - 0.30) / 0.60, 0.0, 1.0))
    growth_norm = float(np.clip((max_growth - 1.15) / 2.20, 0.0, 1.0))
    cliff_bonus = 0.08 if cliff_timestamps else 0.0
    known_llm = any(b.is_llm_endpoint for b in ordered)
    endpoint_bonus = 0.07 if known_llm else 0.0

    # Damp score if uplink volume barely grows (e.g., flat heartbeat/polling traffic).
    raw_score = (
        0.34 * tau_norm
        + 0.24 * mono_norm
        + 0.20 * growth_norm
        + 0.22 * sse_ratio
        + cliff_bonus
        + endpoint_bonus
    )
    if max_growth < 1.12:
        raw_score *= 0.35

    score = float(np.clip(raw_score, 0.0, 1.0))
    endpoint_label = ordered[0].sni or f"{ordered[0].dst_ip}:{ordered[0].dst_port}"
    return SawtoothEvidence(
        score=round(score, 4),
        turn_count=n,
        kendall_tau=round(weighted_tau, 4),
        monotonic_step_ratio=round(mono_ratio_weighted, 4),
        max_growth_ratio=round(max_growth, 3),
        compaction_cliffs=[round(ts, 3) for ts in cliff_timestamps],
        sse_stream_ratio=round(sse_ratio, 4),
        matched_endpoints=[endpoint_label] if score >= 0.30 else [],
    )


def analyze_sawtooth(
    tls_bursts: list[TlsBurstEvent],
    policy: PolicyConfig | None = None,
) -> SawtoothEvidence:
    """Detect multi-turn context-growth sawtooths and SSE cadence across a host's TLS bursts."""
    cfg = policy or PolicyConfig()
    if not tls_bursts:
        return SawtoothEvidence(score=0.0)

    grouped: dict[str, list[TlsBurstEvent]] = defaultdict(list)
    for burst in tls_bursts:
        key = burst.sni or f"{burst.dst_ip}:{burst.dst_port}"
        grouped[key].append(burst)

    candidates: list[SawtoothEvidence] = []
    matched_endpoints: list[str] = []
    for _key, endpoint_bursts in grouped.items():
        ev = _score_endpoint_bursts(endpoint_bursts, min_turns=cfg.scoring.min_turns_for_sawtooth)
        candidates.append(ev)
        matched_endpoints.extend(ev.matched_endpoints)

    if not candidates:
        return SawtoothEvidence(score=0.0)

    best = max(candidates, key=lambda item: (item.score, item.turn_count))
    deduped_endpoints = sorted(set(matched_endpoints))
    return best.model_copy(update={"matched_endpoints": deduped_endpoints})
