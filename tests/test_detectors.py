"""Unit tests for Sawtooth, Cross-Flow Coupler, and Kinematics/Handoff detectors."""

from __future__ import annotations

from oodatap.benchmark.generator import generate_scenario
from oodatap.detectors.coupler import analyze_coupling
from oodatap.detectors.kinematics import analyze_kinematics
from oodatap.detectors.sawtooth import analyze_sawtooth
from oodatap.schemas import ActionEvent, RegimeType, TlsBurstEvent


def test_sawtooth_detects_monotonic_growth_and_compaction_cliff() -> None:
    sc = generate_scenario("autonomous_agent_intrusion", seed=11)
    tls_bursts = [e for e in sc.events if isinstance(e, TlsBurstEvent)]
    ev = analyze_sawtooth(tls_bursts)

    assert ev.score >= 0.75
    assert ev.kendall_tau >= 0.80
    assert len(ev.compaction_cliffs) >= 1
    assert ev.sse_stream_ratio >= 0.80


def test_sawtooth_ignores_flat_https_traffic() -> None:
    bursts = [
        TlsBurstEvent(
            timestamp=100.0 + i * 10.0,
            src_ip="10.0.0.5",
            dst_ip="151.101.1.69",
            dst_port=443,
            sni="cdn.example.com",
            uplink_bytes=820 + (i % 3) * 15,
            downlink_bytes=16000,
            uplink_end_ts=100.0 + i * 10.0 + 0.01,
            downlink_start_ts=100.0 + i * 10.0 + 0.03,
            downlink_end_ts=100.0 + i * 10.0 + 0.08,
            downlink_record_count=1,
        )
        for i in range(12)
    ]
    ev = analyze_sawtooth(bursts)
    assert ev.score < 0.25


def test_coupler_detects_byte_proportional_causal_loop() -> None:
    sc = generate_scenario("autonomous_agent_intrusion", seed=19)
    tls_bursts = [e for e in sc.events if isinstance(e, TlsBurstEvent)]
    actions = [e for e in sc.events if isinstance(e, ActionEvent)]
    ev = analyze_coupling(tls_bursts, actions)

    assert ev.score >= 0.70
    assert ev.coupled_cycle_count >= 12
    assert ev.byte_delta_correlation >= 0.50
    assert ev.granger_f_stat > 1.0


def test_coupler_returns_low_score_for_uncoupled_human_admin() -> None:
    sc = generate_scenario("human_admin", seed=23)
    tls_bursts = [e for e in sc.events if isinstance(e, TlsBurstEvent)]
    actions = [e for e in sc.events if isinstance(e, ActionEvent)]
    ev = analyze_coupling(tls_bursts, actions)

    assert ev.score < 0.25


def test_kinematics_detects_handoffs_in_hybrid_intrusion() -> None:
    sc = generate_scenario("hybrid_human_agent_intrusion", seed=31)
    actions = [e for e in sc.events if isinstance(e, ActionEvent)]
    ev = analyze_kinematics(actions)

    assert ev.parallel_fanout_bursts >= 4
    assert len(ev.handoffs) >= 1
    regimes = {s.regime for s in ev.segments}
    assert RegimeType.AUTONOMOUS_AGENT in regimes
    assert RegimeType.HUMAN_OPERATOR in regimes


def test_kinematics_separates_scripted_scanner() -> None:
    sc = generate_scenario("scripted_scanner", seed=41)
    actions = [e for e in sc.events if isinstance(e, ActionEvent)]
    ev = analyze_kinematics(actions)

    assert ev.scanner_regularity_score >= 0.70
    assert ev.score < 0.30
