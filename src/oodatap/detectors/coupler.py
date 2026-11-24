"""Detector 2: Cross-Flow Causal Coupler (North-South TLS <-> East-West Actions)."""

from __future__ import annotations

import numpy as np

from oodatap.policy import PolicyConfig
from oodatap.schemas import ActionEvent, CouplerEvidence, DirectionClass, TlsBurstEvent


def _safe_pearson(x: np.ndarray, y: np.ndarray) -> float:
    if len(x) < 3 or len(y) < 3:
        return 0.0
    std_x = float(np.std(x))
    std_y = float(np.std(y))
    if std_x < 1e-9 or std_y < 1e-9:
        return 0.0
    corr = float(np.corrcoef(x, y)[0, 1])
    if np.isnan(corr) or np.isinf(corr):
        return 0.0
    return float(np.clip(corr, -1.0, 1.0))


def _granger_f_statistic(
    cause: np.ndarray,
    effect: np.ndarray,
    max_lag: int = 4,
) -> float:
    """Compute OLS Granger-causality F-statistic testing whether `cause` predicts `effect`."""
    n = len(effect)
    if n <= 2 * max_lag + 4:
        return 0.0
    if float(np.std(cause)) < 1e-9 or float(np.std(effect)) < 1e-9:
        return 0.0

    rows = n - max_lag
    y = effect[max_lag:]

    # Restricted design matrix: intercept + lagged effect values.
    x_r_cols = [np.ones(rows, dtype=np.float64)]
    for lag in range(1, max_lag + 1):
        x_r_cols.append(effect[max_lag - lag : n - lag])
    x_r = np.column_stack(x_r_cols)

    # Unrestricted design matrix: restricted + lagged cause values.
    x_u_cols = list(x_r_cols)
    for lag in range(1, max_lag + 1):
        x_u_cols.append(cause[max_lag - lag : n - lag])
    x_u = np.column_stack(x_u_cols)

    beta_r, *_ = np.linalg.lstsq(x_r, y, rcond=None)
    beta_u, *_ = np.linalg.lstsq(x_u, y, rcond=None)

    rss_r = float(np.sum((y - x_r @ beta_r) ** 2))
    rss_u = float(np.sum((y - x_u @ beta_u) ** 2))
    df_denom = rows - x_u.shape[1]
    if df_denom <= 0 or rss_u <= 1e-9 or rss_r <= rss_u:
        return 0.0

    f_stat = ((rss_r - rss_u) / max_lag) / (rss_u / df_denom)
    if np.isnan(f_stat) or np.isinf(f_stat):
        return 0.0
    return max(0.0, float(f_stat))


def _select_primary_llm_stream(bursts: list[TlsBurstEvent]) -> list[TlsBurstEvent]:
    """Select known LLM bursts if present; otherwise select the busiest HTTPS endpoint."""
    known = [b for b in bursts if b.is_llm_endpoint]
    if len(known) >= 3:
        return sorted(known, key=lambda b: b.timestamp)

    by_endpoint: dict[str, list[TlsBurstEvent]] = {}
    for b in bursts:
        key = b.sni or f"{b.dst_ip}:{b.dst_port}"
        by_endpoint.setdefault(key, []).append(b)
    if not by_endpoint:
        return []
    busiest = max(by_endpoint.values(), key=len)
    return sorted(busiest, key=lambda b: b.timestamp)


def analyze_coupling(
    tls_bursts: list[TlsBurstEvent],
    actions: list[ActionEvent],
    policy: PolicyConfig | None = None,
) -> CouplerEvidence:
    """Measure phase-locked causal coupling between North-South LLM bursts and host actions."""
    cfg = policy or PolicyConfig()
    llm_turns = _select_primary_llm_stream(tls_bursts)

    relevant_actions = sorted(
        [
            a
            for a in actions
            if a.direction_class in {DirectionClass.EAST_WEST_INTERNAL, DirectionClass.DEV_LOCAL}
        ],
        key=lambda a: a.timestamp,
    )

    if len(llm_turns) < 3 or len(relevant_actions) < 2:
        return CouplerEvidence(score=0.0, total_llm_turns=len(llm_turns))

    max_obs_lag = cfg.scoring.max_obs_lag_seconds
    max_dispatch_lag = cfg.scoring.max_dispatch_lag_seconds

    obs_lags: list[float] = []
    dispatch_lags: list[float] = []
    obs_matches = 0
    dispatch_matches = 0
    coupled_cycles = 0

    ew_bytes_samples: list[float] = []
    uplink_delta_samples: list[float] = []
    coupled_targets: set[str] = set()
    coupled_protocols: set[str] = set()
    coupled_links: list[dict[str, float | str | int]] = []

    inter_turn_count = len(llm_turns) - 1

    for idx in range(1, len(llm_turns)):
        prev_turn = llm_turns[idx - 1]
        cur_turn = llm_turns[idx]

        # Actions occurring between previous LLM downlink finish and current LLM uplink start.
        window_actions = [
            a
            for a in relevant_actions
            if (prev_turn.downlink_end_ts - 0.05) <= a.timestamp <= cur_turn.timestamp
        ]
        if not window_actions:
            continue

        first_action = window_actions[0]
        last_action = max(window_actions, key=lambda a: a.end_ts)

        dispatch_lag = max(0.0, first_action.timestamp - prev_turn.downlink_end_ts)
        obs_lag = max(0.0, cur_turn.timestamp - last_action.end_ts)

        dispatch_ok = dispatch_lag <= max_dispatch_lag
        obs_ok = obs_lag <= max_obs_lag

        if dispatch_ok:
            dispatch_matches += 1
            dispatch_lags.append(dispatch_lag)
        if obs_ok:
            obs_matches += 1
            obs_lags.append(obs_lag)

        if dispatch_ok and obs_ok:
            coupled_cycles += 1
            for act in window_actions:
                coupled_targets.add(act.dst_ip)
                coupled_protocols.add(act.protocol)

            ew_in_total = sum(a.bytes_in for a in window_actions)
            uplink_delta = cur_turn.uplink_bytes - prev_turn.uplink_bytes

            # Exclude compaction-reset turns when measuring byte-proportional injection.
            is_compaction = (
                prev_turn.uplink_bytes >= 4000
                and cur_turn.uplink_bytes < 0.65 * prev_turn.uplink_bytes
            )
            if not is_compaction and uplink_delta > 0:
                ew_bytes_samples.append(float(ew_in_total))
                uplink_delta_samples.append(float(uplink_delta))

            coupled_links.append(
                {
                    "turn_index": idx,
                    "llm_prev_end_ts": round(prev_turn.downlink_end_ts, 3),
                    "llm_next_start_ts": round(cur_turn.timestamp, 3),
                    "first_action_ts": round(first_action.timestamp, 3),
                    "last_action_end_ts": round(last_action.end_ts, 3),
                    "dispatch_lag_s": round(dispatch_lag, 3),
                    "obs_lag_s": round(obs_lag, 3),
                    "ew_bytes_in": ew_in_total,
                    "uplink_delta": uplink_delta,
                    "dst_ip": first_action.dst_ip,
                    "protocol": first_action.protocol,
                    "action_count": len(window_actions),
                }
            )

    obs_ratio = obs_matches / max(1, inter_turn_count)
    dispatch_ratio = dispatch_matches / max(1, inter_turn_count)
    byte_corr = _safe_pearson(
        np.array(ew_bytes_samples, dtype=np.float64),
        np.array(uplink_delta_samples, dtype=np.float64),
    )

    # Binned time-series Granger causality test (bin width = 0.5s, lags up to 2.0s).
    t_min = min(llm_turns[0].timestamp, relevant_actions[0].timestamp)
    t_max = max(llm_turns[-1].downlink_end_ts, relevant_actions[-1].end_ts)
    bin_w = 0.5
    n_bins = int(np.ceil((t_max - t_min) / bin_w)) + 2
    granger_f = 0.0
    if 16 <= n_bins <= 20000:
        ns_done = np.zeros(n_bins, dtype=np.float64)
        ew_start = np.zeros(n_bins, dtype=np.float64)
        for turn in llm_turns:
            b_idx = int((turn.downlink_end_ts - t_min) / bin_w)
            if 0 <= b_idx < n_bins:
                ns_done[b_idx] += 1.0
        for act in relevant_actions:
            b_idx = int((act.timestamp - t_min) / bin_w)
            if 0 <= b_idx < n_bins:
                ew_start[b_idx] += 1.0
        granger_f = _granger_f_statistic(ns_done, ew_start, max_lag=4)

    granger_norm = float(1.0 - np.exp(-granger_f / 6.0))
    byte_corr_norm = max(0.0, byte_corr)

    raw_score = (
        0.30 * obs_ratio + 0.30 * dispatch_ratio + 0.22 * byte_corr_norm + 0.18 * granger_norm
    )

    # Scale smoothly when fewer than min_actions_for_coupling complete cycles were observed.
    min_cycles = max(1, cfg.scoring.min_actions_for_coupling)
    sample_scale = min(1.0, coupled_cycles / min_cycles)
    final_score = float(np.clip(raw_score * (0.35 + 0.65 * sample_scale), 0.0, 1.0))
    if coupled_cycles == 0:
        final_score = 0.0

    return CouplerEvidence(
        score=round(final_score, 4),
        coupled_cycle_count=coupled_cycles,
        total_llm_turns=len(llm_turns),
        obs_lag_match_ratio=round(obs_ratio, 4),
        dispatch_lag_match_ratio=round(dispatch_ratio, 4),
        median_obs_lag_s=round(float(np.median(obs_lags)), 3) if obs_lags else None,
        median_dispatch_lag_s=round(float(np.median(dispatch_lags)), 3) if dispatch_lags else None,
        byte_delta_correlation=round(byte_corr, 4),
        granger_f_stat=round(granger_f, 3),
        coupled_target_hosts=sorted(coupled_targets),
        coupled_protocols=sorted(coupled_protocols),
        coupled_links=coupled_links,
    )
