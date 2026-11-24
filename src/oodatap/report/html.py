"""Self-contained, offline-capable interactive HTML timeline report generator."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from oodatap.report.ecs import host_verdict_to_ecs
from oodatap.schemas import AnalysisReport, HostVerdict, VerdictLevel

_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
_JINJA_ENV = Environment(
    loader=FileSystemLoader(_TEMPLATE_DIR),
    autoescape=select_autoescape(["html", "xml"]),
)

_BADGE_CLASS: dict[VerdictLevel, str] = {
    VerdictLevel.HYBRID_HUMAN_AGENT_INTRUSION: "badge-crit",
    VerdictLevel.AGENTIC_OODA_INTRUSION: "badge-high",
    VerdictLevel.SUSPICIOUS_LOOP: "badge-warn",
    VerdictLevel.BENIGN_DEV_AGENT: "badge-dev",
    VerdictLevel.SCRIPTED_AUTOMATION: "badge-info",
    VerdictLevel.BENIGN: "badge-ok",
}


def _chart_payload(hv: HostVerdict) -> tuple[float, dict[str, Any]]:
    all_ts = [b.timestamp for b in hv.tls_bursts] + [a.timestamp for a in hv.actions]
    all_end = [b.downlink_end_ts for b in hv.tls_bursts] + [a.end_ts for a in hv.actions]
    t0 = min(all_ts) if all_ts else 0.0
    t_end = max(all_end) if all_end else t0 + 1.0
    duration = max(1.0, t_end - t0)
    max_uplink = max((b.uplink_bytes for b in hv.tls_bursts), default=1024)

    payload = {
        "duration": round(duration, 3),
        "max_uplink": max_uplink,
        "tls": [
            {
                "t_rel": round(b.timestamp - t0, 3),
                "uplink": b.uplink_bytes,
                "downlink": b.downlink_bytes,
                "records": b.downlink_record_count,
                "ttft": round(b.ttft_seconds, 3),
                "sni": b.sni or f"{b.dst_ip}:{b.dst_port}",
                "is_llm": b.is_llm_endpoint,
            }
            for b in hv.tls_bursts
        ],
        "actions": [
            {
                "t_rel": round(a.timestamp - t0, 3),
                "dst_ip": a.dst_ip,
                "dst_port": a.dst_port,
                "proto": a.protocol,
                "bytes_in": a.bytes_in,
                "sensitive": a.is_sensitive_lateral,
                "dir": a.direction_class.value,
            }
            for a in hv.actions
        ],
        "cliffs": [round(ts - t0, 3) for ts in hv.scores.sawtooth.compaction_cliffs],
        "links": [
            {"act_rel": round(float(lk["first_action_ts"]) - t0, 3)}
            for lk in hv.scores.coupler.coupled_links
        ],
        "segments": [
            {
                "start_rel": round(max(0.0, s.start_ts - t0), 3),
                "end_rel": round(max(0.0, s.end_ts - t0), 3),
                "regime": s.regime.value,
            }
            for s in hv.scores.kinematics.segments
        ],
        "handoffs": [
            {"t_rel": round(max(0.0, h.timestamp - t0), 3)} for h in hv.scores.kinematics.handoffs
        ],
    }
    return t0, payload


def render_html_report(report: AnalysisReport) -> str:
    """Render an offline-ready interactive HTML timeline report."""
    template = _JINJA_ENV.get_template("timeline.html.j2")
    host_items: list[dict[str, Any]] = []
    charts: list[dict[str, Any]] = []

    for hv in report.host_verdicts:
        t0, chart = _chart_payload(hv)
        charts.append(chart)
        ecs_doc = host_verdict_to_ecs(hv, report.source_path)
        host_items.append(
            {
                "verdict": hv,
                "t0": t0,
                "badge_class": _BADGE_CLASS.get(hv.verdict, "badge-ok"),
                "ecs_json": json.dumps(ecs_doc, indent=2),
            }
        )

    return template.render(
        report=report,
        host_items=host_items,
        charts_json=json.dumps(charts),
    )


def write_html_report(report: AnalysisReport, path: Path | str) -> Path:
    """Write the rendered HTML timeline report to disk."""
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(render_html_report(report), encoding="utf-8")
    return out_path
