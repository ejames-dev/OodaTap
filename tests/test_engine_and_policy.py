"""End-to-end engine, dev-agent allowlist suppression, ECS export, and HTML report tests."""

from __future__ import annotations

import json
from pathlib import Path

from oodatap.benchmark.generator import generate_scenario
from oodatap.detectors.engine import OodaTapEngine
from oodatap.policy import load_policy
from oodatap.report.ecs import write_ecs_jsonl
from oodatap.report.html import write_html_report
from oodatap.schemas import VerdictLevel


def test_benign_dev_agent_is_suppressed_by_default_policy() -> None:
    policy = load_policy()
    sc = generate_scenario("benign_dev_agent", seed=55, policy=policy)
    engine = OodaTapEngine(policy=policy)
    report = engine.analyze_events(sc.events, source_path="dev.jsonl")

    hv = report.host_verdicts[0]
    assert hv.verdict == VerdictLevel.BENIGN_DEV_AGENT
    assert hv.suppressed_as_dev_agent is True
    assert hv.sensitive_lateral_actions == 0
    assert hv.dev_allowlisted_actions > 0
    assert report.alerting_hosts == []


def test_hybrid_intrusion_exports_ecs_and_offline_html(tmp_path: Path) -> None:
    policy = load_policy()
    sc = generate_scenario("hybrid_human_agent_intrusion", seed=88, policy=policy)
    engine = OodaTapEngine(policy=policy)
    report = engine.analyze_events(sc.events, source_path="hybrid.pcap", adapter="pcap")

    assert len(report.alerting_hosts) == 1
    hv = report.alerting_hosts[0]
    assert hv.verdict == VerdictLevel.HYBRID_HUMAN_AGENT_INTRUSION

    ecs_path = write_ecs_jsonl(report, tmp_path / "alerts.jsonl")
    lines = ecs_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    doc = json.loads(lines[0])
    assert doc["event"]["module"] == "oodatap"
    assert doc["source"]["ip"] == sc.primary_host
    assert doc["oodatap"]["verdict"] == VerdictLevel.HYBRID_HUMAN_AGENT_INTRUSION.value

    html_path = write_html_report(report, tmp_path / "timeline.html")
    html = html_path.read_text(encoding="utf-8")
    assert "OodaTap" in html
    assert sc.primary_host in html
    # Confirm offline-capable HTML (no external CDN script tags).
    assert "https://" not in html
