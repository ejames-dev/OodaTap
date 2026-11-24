"""Tests for pure-Python binary .pcap reading, writing, and TLS ClientHello SNI parsing."""

from __future__ import annotations

from pathlib import Path

from oodatap.benchmark.generator import generate_scenario
from oodatap.detectors.engine import OodaTapEngine
from oodatap.ingest.base import detect_format
from oodatap.ingest.pcap import (
    _build_tls_client_hello,
    parse_tls_client_hello_sni,
    read_pcap,
    write_pcap_from_events,
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
