"""Detector 3: Session Kinematics, Parallel Tool Fan-Out, and Human<->Agent Handoff Detection."""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from oodatap.policy import PolicyConfig
from oodatap.schemas import (
    ActionEvent,
    DirectionClass,
    HandoffEvent,
    KinematicsEvidence,
    RegimeSegment,
    RegimeType,
)


@dataclass
class _ActionBurst:
    start_ts: float
    end_ts: float
    actions: list[ActionEvent]

    @property
    def width(self) -> int:
        return len(self.actions)

    @property
    def bytes_in_total(self) -> int:
        return sum(a.bytes_in for a in self.actions)


def _cluster_action_bursts(
    actions: list[ActionEvent],
    fanout_window_s: float,
) -> list[_ActionBurst]:
    """Group nearly simultaneous actions (parallel tool calls) into unified bursts."""
    if not actions:
        return []
    ordered = sorted(actions, key=lambda a: a.timestamp)
    bursts: list[_ActionBurst] = []
    cur = _ActionBurst(
        start_ts=ordered[0].timestamp, end_ts=ordered[0].end_ts, actions=[ordered[0]]
    )

    for act in ordered[1:]:
        if (act.timestamp - cur.start_ts) <= fanout_window_s:
            cur.actions.append(act)
            cur.end_ts = max(cur.end_ts, act.end_ts)
        else:
            bursts.append(cur)
            cur = _ActionBurst(start_ts=act.timestamp, end_ts=act.end_ts, actions=[act])
    bursts.append(cur)
    return bursts


def _optimal_partition_changepoints(
    matrix: np.ndarray,
    min_seg_size: int = 5,
    penalty_factor: float = 2.0,
) -> list[int]:
    """Exact BIC-penalized L2 optimal partitioning (PELT/DP) for multivariate change-points.

    Unlike greedy binary segmentation, exact dynamic programming reliably detects
    non-monotonic A -> B -> A regime transitions (e.g., Agent -> Human -> Agent).
    """
    n, dims = matrix.shape
    if n < 2 * min_seg_size:
        return []

    # Standardize columns so latency and fan-out contribute comparably.
    stds = np.std(matrix, axis=0)
    stds = np.where(stds < 1e-6, 1.0, stds)
    z = (matrix - np.mean(matrix, axis=0)) / stds

    # Prefix sums for O(1) L2 segment cost evaluation.
    csum = np.vstack([np.zeros((1, dims), dtype=np.float64), np.cumsum(z, axis=0)])
    csq = np.concatenate([[0.0], np.cumsum(np.sum(z * z, axis=1))])

    def seg_cost(start: int, end: int) -> float:
        length = end - start
        if length <= 1:
            return 0.0
        sum_vec = csum[end] - csum[start]
        sq_sum = float(csq[end] - csq[start])
        return max(0.0, sq_sum - float(np.dot(sum_vec, sum_vec)) / length)

    penalty = penalty_factor * dims * float(np.log(n))
    dp = np.full(n + 1, np.inf, dtype=np.float64)
    prev = np.full(n + 1, -1, dtype=np.int64)
    dp[0] = -penalty

    for end in range(min_seg_size, n + 1):
        best_cost = np.inf
        best_start = -1
        # Candidate split starts: 0 (single segment) or >= min_seg_size with valid prefix.
        candidates = [0, *range(min_seg_size, end - min_seg_size + 1)]
        for start in candidates:
            if not np.isfinite(dp[start]):
                continue
            cand_cost = dp[start] + seg_cost(start, end) + penalty
            if cand_cost < best_cost:
                best_cost = cand_cost
                best_start = start
        dp[end] = best_cost
        prev[end] = best_start

    # Backtrack optimal split indices.
    change_points: list[int] = []
    cursor = int(prev[n])
    while cursor > 0:
        change_points.append(cursor)
        cursor = int(prev[cursor])
    return sorted(change_points)


def _classify_segment(
    gaps: np.ndarray,
    fanout_flags: np.ndarray,
) -> tuple[RegimeType, float, float, float]:
    median_gap = float(np.median(gaps)) if len(gaps) else 0.0
    mean_gap = float(np.mean(gaps)) if len(gaps) else 0.0
    std_gap = float(np.std(gaps)) if len(gaps) else 0.0
    cv = (std_gap / mean_gap) if mean_gap > 1e-6 else 0.0
    fanout_ratio = float(np.mean(fanout_flags)) if len(fanout_flags) else 0.0

    # Classic rapid scripted scanner: sub-second inter-burst intervals with low variance.
    if median_gap < 0.45 and cv < 0.85 and fanout_ratio < 0.85:
        return RegimeType.SCRIPTED_SCANNER, median_gap, cv, fanout_ratio

    # Autonomous agent: tight inference-scale pacing (0.6s-8.5s) and/or parallel fan-out.
    if (0.55 <= median_gap <= 8.5 and cv <= 0.72) or (
        fanout_ratio >= 0.25 and 0.45 <= median_gap <= 10.0
    ):
        return RegimeType.AUTONOMOUS_AGENT, median_gap, cv, fanout_ratio

    # Human operator: slower or higher-variance erratic pauses with negligible parallel fan-out.
    if median_gap >= 7.5 or (median_gap >= 3.0 and cv > 0.72 and fanout_ratio < 0.15):
        return RegimeType.HUMAN_OPERATOR, median_gap, cv, fanout_ratio

    return RegimeType.IDLE_OR_MIXED, median_gap, cv, fanout_ratio


def _safe_pearson(x: np.ndarray, y: np.ndarray) -> float:
    if len(x) < 4:
        return 0.0
    if float(np.std(x)) < 1e-9 or float(np.std(y)) < 1e-9:
        return 0.0
    val = float(np.corrcoef(x, y)[0, 1])
    return 0.0 if (np.isnan(val) or np.isinf(val)) else float(np.clip(val, -1.0, 1.0))


def analyze_kinematics(
    actions: list[ActionEvent],
    policy: PolicyConfig | None = None,
) -> KinematicsEvidence:
    """Analyze session timing kinematics, parallel tool fan-out, and human<->agent handoffs."""
    cfg = policy or PolicyConfig()
    relevant = sorted(
        [
            a
            for a in actions
            if a.direction_class
            in {
                DirectionClass.EAST_WEST_INTERNAL,
                DirectionClass.DEV_LOCAL,
                DirectionClass.REMOTE_INBOUND,
            }
        ],
        key=lambda a: a.timestamp,
    )
    if len(relevant) < 4:
        return KinematicsEvidence(score=0.0, action_count=len(relevant))

    bursts = _cluster_action_bursts(relevant, fanout_window_s=cfg.scoring.fanout_window_seconds)
    if len(bursts) < 3:
        # Handle rapid scanner where everything fell into 1-2 dense bursts.
        raw_gaps = np.diff([a.timestamp for a in relevant])
        med_raw = float(np.median(raw_gaps)) if len(raw_gaps) else 0.0
        scanner_score = 0.90 if med_raw < 0.25 else 0.0
        return KinematicsEvidence(
            score=0.0,
            action_count=len(relevant),
            scanner_regularity_score=round(scanner_score, 4),
        )

    # Compute inter-burst think pauses and previous-burst response volumes.
    gaps_list: list[float] = []
    prev_bytes_list: list[float] = []
    fanout_flags_list: list[float] = []
    burst_widths = [b.width for b in bursts]

    for idx in range(1, len(bursts)):
        gap = max(0.0, bursts[idx].start_ts - bursts[idx - 1].end_ts)
        gaps_list.append(gap)
        prev_bytes_list.append(float(bursts[idx - 1].bytes_in_total))
        fanout_flags_list.append(1.0 if bursts[idx].width >= 2 else 0.0)

    gaps = np.array(gaps_list, dtype=np.float64)
    prev_bytes = np.array(prev_bytes_list, dtype=np.float64)
    fanout_flags = np.array(fanout_flags_list, dtype=np.float64)

    # Check raw scanner regularity (very fast, uniform non-LLM probing).
    raw_gaps = np.diff([a.timestamp for a in relevant])
    raw_median = float(np.median(raw_gaps))
    raw_mean = float(np.mean(raw_gaps))
    raw_cv = float(np.std(raw_gaps)) / raw_mean if raw_mean > 1e-6 else 0.0
    scanner_regularity = 0.0
    if raw_median < 0.35 and raw_cv < 0.85:
        scanner_regularity = float(
            np.clip((0.35 - raw_median) / 0.35 * 0.65 + (0.85 - raw_cv) / 0.85 * 0.35, 0.0, 1.0)
        )

    # Exact L2 optimal partitioning for human <-> agent handoffs (handles A -> B -> A).
    features = np.column_stack([np.log1p(gaps), fanout_flags * 1.5])
    cp_indices = _optimal_partition_changepoints(features, min_seg_size=5, penalty_factor=2.0)
    boundaries = [0, *cp_indices, len(gaps)]

    segments: list[RegimeSegment] = []
    for start, end in zip(boundaries[:-1], boundaries[1:], strict=False):
        seg_gaps = gaps[start:end]
        seg_fan = fanout_flags[start:end]
        regime, med_g, cv_g, fan_r = _classify_segment(seg_gaps, seg_fan)
        seg_start_ts = bursts[start].start_ts
        seg_end_ts = bursts[min(end, len(bursts) - 1)].end_ts
        seg_action_count = sum(b.width for b in bursts[start : end + 1])
        segments.append(
            RegimeSegment(
                start_ts=round(seg_start_ts, 3),
                end_ts=round(seg_end_ts, 3),
                action_count=seg_action_count,
                regime=regime,
                median_inter_action_s=round(med_g, 3),
                inter_action_cv=round(cv_g, 3),
                fanout_burst_ratio=round(fan_r, 3),
            )
        )

    # Detect Agent <-> Human handoffs across adjacent segments.
    handoffs: list[HandoffEvent] = []
    pair_set = {RegimeType.AUTONOMOUS_AGENT, RegimeType.HUMAN_OPERATOR}
    for seg_a, seg_b in zip(segments[:-1], segments[1:], strict=False):
        if {seg_a.regime, seg_b.regime} == pair_set:
            gap_ratio = max(seg_a.median_inter_action_s, seg_b.median_inter_action_s) / max(
                0.2, min(seg_a.median_inter_action_s, seg_b.median_inter_action_s)
            )
            fan_diff = abs(seg_a.fanout_burst_ratio - seg_b.fanout_burst_ratio)
            conf = float(np.clip(0.45 + 0.12 * np.log1p(gap_ratio) + 0.35 * fan_diff, 0.5, 0.99))
            rationale = (
                f"Median pause shifted {seg_a.median_inter_action_s:.2f}s -> "
                f"{seg_b.median_inter_action_s:.2f}s "
                f"(CV {seg_a.inter_action_cv:.2f} -> {seg_b.inter_action_cv:.2f}, "
                f"fan-out {seg_a.fanout_burst_ratio:.0%} -> {seg_b.fanout_burst_ratio:.0%})."
            )
            handoffs.append(
                HandoffEvent(
                    timestamp=seg_b.start_ts,
                    from_regime=seg_a.regime,
                    to_regime=seg_b.regime,
                    confidence=round(conf, 3),
                    rationale=rationale,
                )
            )

    # Parallel fan-out & response-size-to-pause kinematics.
    parallel_bursts = sum(1 for w in burst_widths if w >= 2)
    max_fanout = max(burst_widths) if burst_widths else 1
    fanout_ratio_overall = parallel_bursts / max(1, len(bursts))

    # Measure size-to-pause correlation across plausible inference-scale gaps (0.5s - 15s).
    inf_mask = (gaps >= 0.5) & (gaps <= 15.0)
    size_pause_corr = (
        _safe_pearson(prev_bytes[inf_mask], gaps[inf_mask]) if int(np.sum(inf_mask)) >= 4 else 0.0
    )

    agent_action_share = sum(
        s.action_count for s in segments if s.regime == RegimeType.AUTONOMOUS_AGENT
    ) / max(1, sum(s.action_count for s in segments))

    fanout_norm = float(np.clip(fanout_ratio_overall / 0.45, 0.0, 1.0))
    corr_norm = float(np.clip(size_pause_corr / 0.70, 0.0, 1.0))
    handoff_bonus = 0.15 if handoffs else 0.0

    raw_kin = 0.40 * agent_action_share + 0.30 * fanout_norm + 0.25 * corr_norm + handoff_bonus
    # Suppress kinematics score if traffic strongly resembles a flat scripted scanner.
    if scanner_regularity >= 0.65:
        raw_kin *= 1.0 - 0.85 * scanner_regularity

    score = float(np.clip(raw_kin, 0.0, 1.0))
    return KinematicsEvidence(
        score=round(score, 4),
        action_count=len(relevant),
        parallel_fanout_bursts=parallel_bursts,
        max_fanout_width=max_fanout,
        size_to_pause_correlation=round(size_pause_corr, 4),
        scanner_regularity_score=round(scanner_regularity, 4),
        segments=segments,
        handoffs=handoffs,
    )
