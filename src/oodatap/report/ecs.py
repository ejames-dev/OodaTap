"""Elastic Common Schema (ECS) alert serializer for SIEM / Elastic / Splunk ingestion."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from oodatap.schemas import AnalysisReport, HostVerdict, VerdictLevel

_SEVERITY_MAP: dict[VerdictLevel, int] = {
    VerdictLevel.HYBRID_HUMAN_AGENT_INTRUSION: 90,
    VerdictLevel.AGENTIC_OODA_INTRUSION: 85,
    VerdictLevel.SUSPICIOUS_LOOP: 55,
    VerdictLevel.SCRIPTED_AUTOMATION: 35,
    VerdictLevel.BENIGN_DEV_AGENT: 10,
    VerdictLevel.BENIGN: 0,
}


def host_verdict_to_ecs(hv: HostVerdict, source_path: str) -> dict[str, Any]:
    """Convert a HostVerdict into an ECS-compatible security alert document."""
    first_ts = None
    if hv.tls_bursts or hv.actions:
        ts_candidates = [b.timestamp for b in hv.tls_bursts] + [a.timestamp for a in hv.actions]
        first_ts = min(ts_candidates)
    iso_ts = (
        datetime.fromtimestamp(first_ts, tz=UTC).isoformat()
        if first_ts is not None
        else datetime.now(tz=UTC).isoformat()
    )
    return {
        "@timestamp": iso_ts,
        "ecs": {"version": "8.11.0"},
        "event": {
            "kind": "alert"
            if hv.verdict
            in {
                VerdictLevel.AGENTIC_OODA_INTRUSION,
                VerdictLevel.HYBRID_HUMAN_AGENT_INTRUSION,
                VerdictLevel.SUSPICIOUS_LOOP,
            }
            else "event",
            "category": ["network", "intrusion_detection"],
            "module": "oodatap",
            "action": hv.verdict.value,
            "severity": _SEVERITY_MAP.get(hv.verdict, 0),
            "risk_score": round(hv.scores.composite * 100.0, 2),
        },
        "source": {"ip": hv.host_ip},
        "destination": {
            "ip": hv.scores.coupler.coupled_target_hosts,
            "domain": hv.scores.sawtooth.matched_endpoints,
        },
        "network": {"protocol": hv.scores.coupler.coupled_protocols},
        "message": hv.summary,
        "oodatap": {
            "source_file": source_path,
            "verdict": hv.verdict.value,
            "confidence": hv.confidence,
            "suppressed_as_dev_agent": hv.suppressed_as_dev_agent,
            "scores": {
                "composite": hv.scores.composite,
                "sawtooth": hv.scores.sawtooth.score,
                "coupler": hv.scores.coupler.score,
                "kinematics": hv.scores.kinematics.score,
            },
            "evidence": {
                "kendall_tau": hv.scores.sawtooth.kendall_tau,
                "compaction_cliffs": len(hv.scores.sawtooth.compaction_cliffs),
                "coupled_cycles": hv.scores.coupler.coupled_cycle_count,
                "byte_delta_correlation": hv.scores.coupler.byte_delta_correlation,
                "granger_f_stat": hv.scores.coupler.granger_f_stat,
                "parallel_fanout_bursts": hv.scores.kinematics.parallel_fanout_bursts,
                "handoffs": [h.model_dump() for h in hv.scores.kinematics.handoffs],
            },
        },
    }


def report_to_ecs_alerts(
    report: AnalysisReport,
    include_benign: bool = False,
) -> list[dict[str, Any]]:
    """Serialize all alerting (or all) host verdicts in a report to ECS dicts."""
    verdicts = report.host_verdicts if include_benign else report.alerting_hosts
    return [host_verdict_to_ecs(hv, report.source_path) for hv in verdicts]


def write_ecs_jsonl(
    report: AnalysisReport,
    path: Path | str,
    include_benign: bool = False,
) -> Path:
    """Write ECS alerts as JSONL ready for Elastic / Splunk / SIEM ingestion."""
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    alerts = report_to_ecs_alerts(report, include_benign=include_benign)
    with out_path.open("w", encoding="utf-8") as fh:
        for alert in alerts:
            fh.write(json.dumps(alert) + "\n")
    return out_path
