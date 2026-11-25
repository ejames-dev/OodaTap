"""Tests for pure-Python .pcap/.pcapng reading & writing, IPv6, TLS SNI, and multi-host captures."""

from __future__ import annotations

from pathlib import Path

from oodatap.benchmark.generator import generate_mixed_enterprise_events, generate_scenario
from oodatap.detectors.engine import OodaTapEngine
from oodatap.ingest.base import detect_format, load_events
from oodatap.ingest.pcap import (
    _build_tls_client_hello,
    parse_tls_client_hello_sni,
    read_pcap,
    write_pcap_from_events,
    write_pcapng_from_events,
)
from oodatap.policy import PolicyConfig
from oodatap.schemas import ActionEvent, TlsBurstEvent, VerdictLevel


def test_tls_client_hello_sni_roundtrip() -> None:
    hello = _build_tls_client_hello("api.anthropic.com")
    assert parse_tls_client_hello_sni(hello) == "api.anthropic.com"


def test_pcap_roundtrip_preserves_sni_bursts_and_detection(tmp_path: Path) -> None:
    scenario = generate_scenario("hybrid_human_agent_intrusion", seed=77)
    pcap_path = write_pcap_from_events(scenario.events, tmp_path / "hybrid.pcap")

    assert detect_format(pcap_path) == "pcap"
    parsed = read_pcap(pcap_path, policy=PolicyConfig())

    tls_events = [e for e in parsed if isinstance(e, TlsBurstEvent)]
    action_events = [e for e in parsed if isinstance(e, ActionEvent)]

    assert len(tls_events) >= 16
    assert any(b.sni == "api.openai.com" for b in tls_events)
    assert len(action_events) >= 20

    engine = OodaTapEngine()
    report = engine.analyze_events(parsed, source_path=str(pcap_path), adapter="pcap")
    verdict = report.host_verdicts[0]
    assert verdict.host_ip == scenario.primary_host
    assert verdict.verdict in {
        VerdictLevel.HYBRID_HUMAN_AGENT_INTRUSION,
        VerdictLevel.AGENTIC_OODA_INTRUSION,
    }
    assert verdict.scores.sawtooth.score >= 0.60
    assert verdict.scores.coupler.score >= 0.55


def test_pcapng_roundtrip_and_auto_detection(tmp_path: Path) -> None:
    scenario = generate_scenario("autonomous_agent_intrusion", seed=91)
    pcapng_path = write_pcapng_from_events(scenario.events, tmp_path / "autonomous.pcapng")

    assert detect_format(pcapng_path) == "pcapng"
    fmt, parsed = load_events(pcapng_path, policy=PolicyConfig())
    assert fmt == "pcapng"

    engine = OodaTapEngine()
    report = engine.analyze_events(parsed, source_path=str(pcapng_path), adapter=fmt)
    assert len(report.host_verdicts) == 1
    hv = report.host_verdicts[0]
    assert hv.host_ip == scenario.primary_host
    assert hv.verdict == VerdictLevel.AGENTIC_OODA_INTRUSION
    assert hv.scores.sawtooth.score >= 0.75
    assert hv.scores.coupler.score >= 0.70


def test_ipv6_pcapng_detection(tmp_path: Path) -> None:
    """Verify full IPv6 (Ethertype 0x86DD) TLS SNI + ULA lateral movement detection."""
    scenario = generate_scenario("autonomous_agent_intrusion", seed=105)
    v6_src = "fd00:10:20::44"
    v6_llm = "2606:4700::6812:7c0"
    v6_targets = {
        "10.0.5.10": "fd00:10:5::10",
        "10.0.5.11": "fd00:10:5::11",
        "10.0.5.14": "fd00:10:5::14",
        "10.0.5.20": "fd00:10:5::20",
        "10.0.5.22": "fd00:10:5::22",
        "10.0.5.30": "fd00:10:5::30",
    }

    v6_events = []
    for ev in scenario.events:
        if isinstance(ev, TlsBurstEvent):
            v6_events.append(ev.model_copy(update={"src_ip": v6_src, "dst_ip": v6_llm}))
        else:
            v6_events.append(
                ev.model_copy(
                    update={"src_ip": v6_src, "dst_ip": v6_targets.get(ev.dst_ip, "fd00:10:5::99")}
                )
            )

    pcapng_path = write_pcapng_from_events(v6_events, tmp_path / "ipv6_intrusion.pcapng")
    fmt, parsed = load_events(pcapng_path, policy=PolicyConfig())
    assert fmt == "pcapng"
    assert any(isinstance(e, TlsBurstEvent) and e.src_ip == v6_src for e in parsed)
    assert any(
        isinstance(e, ActionEvent) and e.dst_ip.startswith("fd00:") and e.is_sensitive_lateral
        for e in parsed
    )

    report = OodaTapEngine().analyze_events(parsed, source_path=str(pcapng_path), adapter=fmt)
    assert len(report.alerting_hosts) == 1
    assert report.alerting_hosts[0].host_ip == v6_src
    assert report.alerting_hosts[0].verdict == VerdictLevel.AGENTIC_OODA_INTRUSION


def test_mixed_enterprise_multihost_pcapng_isolates_all_five_hosts(tmp_path: Path) -> None:
    """Confirm OodaTap cleanly classifies all 5 concurrent hosts inside one noisy .pcapng."""
    events, expected_by_host = generate_mixed_enterprise_events(seed=404)
    pcapng_path = write_pcapng_from_events(events, tmp_path / "mixed.pcapng")

    fmt, parsed = load_events(pcapng_path, policy=PolicyConfig())
    report = OodaTapEngine().analyze_events(parsed, source_path=str(pcapng_path), adapter=fmt)

    verdict_by_host = {hv.host_ip: hv.verdict for hv in report.host_verdicts}
    assert set(verdict_by_host) == set(expected_by_host)
    for host_ip, expected_verdict in expected_by_host.items():
        assert verdict_by_host[host_ip] == expected_verdict, (
            f"Host {host_ip}: expected {expected_verdict}, got {verdict_by_host[host_ip]}"
        )
    # Exactly 2 alerting intrusion hosts out of 5 concurrent hosts.
    assert len(report.alerting_hosts) == 2
