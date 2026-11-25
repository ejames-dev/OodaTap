"""Generate a data-driven dark-mode SVG preview of OodaTap's dual-track timeline for README."""

from __future__ import annotations

from pathlib import Path
from xml.sax.saxutils import escape

from oodatap.detectors.engine import OodaTapEngine
from oodatap.ingest.base import load_events
from oodatap.policy import load_policy
from oodatap.schemas import HostVerdict, RegimeType

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INPUT = ROOT / "examples" / "sample_traces" / "hybrid_intrusion.pcap"
DEFAULT_OUTPUT = ROOT / "docs" / "timeline_preview.svg"


def _tag(name: str, attrs: dict[str, str | int | float], text: str | None = None) -> str:
    attr_str = " ".join(f'{k}="{v}"' for k, v in attrs.items())
    if text is None:
        return f"  <{name} {attr_str} />"
    return f"  <{name} {attr_str}>{escape(text)}</{name}>"


def build_timeline_svg(hv: HostVerdict, source_label: str) -> str:
    """Render a standalone GitHub-friendly SVG card showing Sawtooth + Actions + Handoffs."""
    all_ts = [b.timestamp for b in hv.tls_bursts] + [a.timestamp for a in hv.actions]
    all_end = [b.downlink_end_ts for b in hv.tls_bursts] + [a.end_ts for a in hv.actions]
    t0 = min(all_ts) if all_ts else 0.0
    duration = max(1.0, (max(all_end) if all_end else t0 + 1.0) - t0)
    max_u = max((b.uplink_bytes for b in hv.tls_bursts), default=1024)
    max_in = max((a.bytes_in for a in hv.actions), default=1000)

    w, h = 1120, 430
    pad_l, pad_r = 72, 30
    chart_top, top_h = 132, 138
    bot_y, bot_h = 296, 86
    chart_h = bot_y + bot_h - chart_top + 14

    def sx(t_abs: float) -> float:
        return pad_l + ((t_abs - t0) / duration) * (w - pad_l - pad_r)

    def sy_up(uplink: int) -> float:
        return chart_top + 14 + (1.0 - uplink / max_u) * (top_h - 24)

    sni_text = ", ".join(hv.scores.sawtooth.matched_endpoints) or "unknown"
    verdict_text = hv.verdict.value.upper().replace("_", " ")

    lines: list[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="{w}" height="{h}">',
        "  <defs>",
        '    <linearGradient id="sawFill" x1="0" y1="0" x2="0" y2="1">',
        '      <stop offset="0%" stop-color="#38bdf8" stop-opacity="0.22" />',
        '      <stop offset="100%" stop-color="#38bdf8" stop-opacity="0.01" />',
        "    </linearGradient>",
        "    <style>",
        "      .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }",
        "      .sans { font-family: -apple-system, Segoe UI, Inter, sans-serif; }",
        "    </style>",
        "  </defs>",
        _tag(
            "rect",
            {
                "x": 0,
                "y": 0,
                "width": w,
                "height": h,
                "rx": 14,
                "fill": "#0b0f17",
                "stroke": "#232d42",
                "stroke-width": 1.5,
            },
        ),
        _tag(
            "text",
            {
                "x": 28,
                "y": 38,
                "fill": "#38bdf8",
                "class": "mono",
                "font-size": 20,
                "font-weight": 700,
            },
            "OodaTap",
        ),
        _tag(
            "text",
            {
                "x": 128,
                "y": 38,
                "fill": "#e6edf7",
                "class": "sans",
                "font-size": 16,
                "font-weight": 600,
            },
            f"Dual-Track Encrypted OODA Timeline — {hv.host_ip}",
        ),
        _tag(
            "text",
            {"x": 28, "y": 58, "fill": "#8b9bb4", "class": "mono", "font-size": 12},
            f"Source: {source_label} • Zero TLS Decryption • SNI: {sni_text}",
        ),
        _tag(
            "rect",
            {
                "x": 838,
                "y": 18,
                "width": 254,
                "height": 30,
                "rx": 15,
                "fill": "#f43f5e",
                "fill-opacity": 0.18,
                "stroke": "#f43f5e",
                "stroke-width": 1.2,
            },
        ),
        _tag(
            "text",
            {
                "x": 965,
                "y": 37,
                "text-anchor": "middle",
                "fill": "#fb7185",
                "class": "mono",
                "font-size": 11.5,
                "font-weight": 700,
            },
            verdict_text,
        ),
    ]

    kpis = [
        ("COMPOSITE", f"{hv.scores.composite:.2f}", "#fb7185"),
        ("SAWTOOTH (N-S)", f"{hv.scores.sawtooth.score:.2f}", "#38bdf8"),
        ("COUPLER (N-S↔E-W)", f"{hv.scores.coupler.score:.2f}", "#a78bfa"),
        ("KINEMATICS", f"{hv.scores.kinematics.score:.2f}", "#fbbf24"),
        ("COUPLED CYCLES", str(hv.scores.coupler.coupled_cycle_count), "#e6edf7"),
        ("BYTE-Δ CORR (r)", f"{hv.scores.coupler.byte_delta_correlation:.2f}", "#34d399"),
        ("GRANGER F", f"{hv.scores.coupler.granger_f_stat:.1f}", "#34d399"),
        ("HANDOFFS", str(len(hv.scores.kinematics.handoffs)), "#fb7185"),
    ]
    for idx, (label, val, color) in enumerate(kpis):
        bx = 28 + idx * 134
        lines.append(
            _tag(
                "rect",
                {
                    "x": bx,
                    "y": 72,
                    "width": 126,
                    "height": 46,
                    "rx": 7,
                    "fill": "#121826",
                    "stroke": "#232d42",
                },
            )
        )
        lines.append(
            _tag(
                "text",
                {"x": bx + 10, "y": 88, "fill": "#8b9bb4", "class": "mono", "font-size": 9.5},
                label,
            )
        )
        lines.append(
            _tag(
                "text",
                {
                    "x": bx + 10,
                    "y": 109,
                    "fill": color,
                    "class": "mono",
                    "font-size": 16,
                    "font-weight": 700,
                },
                val,
            )
        )

    lines.append(
        _tag(
            "rect",
            {
                "x": pad_l,
                "y": chart_top,
                "width": w - pad_l - pad_r,
                "height": chart_h,
                "rx": 8,
                "fill": "#090d14",
                "stroke": "#1e293b",
            },
        )
    )

    for seg in hv.scores.kinematics.segments:
        x1 = max(float(pad_l), sx(seg.start_ts))
        x2 = min(float(w - pad_r), sx(seg.end_ts))
        if seg.regime == RegimeType.AUTONOMOUS_AGENT:
            fill, label_col, lbl, op = "#38bdf8", "#38bdf8", "AUTONOMOUS AGENT", 0.07
        elif seg.regime == RegimeType.HUMAN_OPERATOR:
            fill, label_col, lbl, op = "#f59e0b", "#fbbf24", "HUMAN OPERATOR", 0.09
        else:
            fill, label_col, lbl, op = "#94a3b8", "#94a3b8", seg.regime.value.upper(), 0.05
        lines.append(
            _tag(
                "rect",
                {
                    "x": f"{x1:.1f}",
                    "y": chart_top,
                    "width": f"{max(2.0, x2 - x1):.1f}",
                    "height": chart_h,
                    "fill": fill,
                    "fill-opacity": op,
                },
            )
        )
        lines.append(
            _tag(
                "text",
                {
                    "x": f"{(x1 + x2) / 2:.1f}",
                    "y": bot_y + bot_h + 10,
                    "text-anchor": "middle",
                    "fill": label_col,
                    "class": "mono",
                    "font-size": 10,
                    "font-weight": 600,
                },
                lbl,
            )
        )

    div_y = chart_top + top_h + 10
    lines.extend(
        [
            _tag(
                "line",
                {
                    "x1": pad_l,
                    "y1": div_y,
                    "x2": w - pad_r,
                    "y2": div_y,
                    "stroke": "#1e293b",
                    "stroke-width": 1,
                },
            ),
            _tag(
                "text",
                {
                    "x": pad_l - 8,
                    "y": chart_top + 20,
                    "text-anchor": "end",
                    "fill": "#8b9bb4",
                    "class": "mono",
                    "font-size": 10,
                },
                f"{max_u / 1024:.0f} KB",
            ),
            _tag(
                "text",
                {
                    "x": pad_l - 8,
                    "y": chart_top + top_h - 4,
                    "text-anchor": "end",
                    "fill": "#8b9bb4",
                    "class": "mono",
                    "font-size": 10,
                },
                "0 KB",
            ),
            _tag(
                "text",
                {
                    "x": pad_l - 8,
                    "y": f"{chart_top + top_h / 2:.0f}",
                    "text-anchor": "end",
                    "fill": "#38bdf8",
                    "class": "mono",
                    "font-size": 9.5,
                },
                "N-S TLS",
            ),
            _tag(
                "text",
                {
                    "x": pad_l - 8,
                    "y": f"{bot_y + bot_h / 2:.0f}",
                    "text-anchor": "end",
                    "fill": "#fb7185",
                    "class": "mono",
                    "font-size": 9.5,
                },
                "E-W Acts",
            ),
        ]
    )

    for lk in hv.scores.coupler.coupled_links:
        x = f"{sx(float(lk['first_action_ts'])):.1f}"
        lines.append(
            _tag(
                "line",
                {
                    "x1": x,
                    "y1": chart_top + top_h,
                    "x2": x,
                    "y2": bot_y + 12,
                    "stroke": "#a78bfa",
                    "stroke-opacity": 0.45,
                    "stroke-dasharray": "3,3",
                    "stroke-width": 1.2,
                },
            )
        )

    if len(hv.tls_bursts) > 1:
        pts = [(sx(b.timestamp), sy_up(b.uplink_bytes)) for b in hv.tls_bursts]
        poly_str = " ".join(f"{x:.1f},{y:.1f}" for x, y in pts)
        base_y = chart_top + top_h - 4
        area_str = f"{pts[0][0]:.1f},{base_y} {poly_str} {pts[-1][0]:.1f},{base_y}"
        lines.append(_tag("polygon", {"points": area_str, "fill": "url(#sawFill)"}))
        lines.append(
            _tag(
                "polyline",
                {"points": poly_str, "fill": "none", "stroke": "#38bdf8", "stroke-width": 2.2},
            )
        )
        for x, y in pts:
            lines.append(
                _tag(
                    "circle",
                    {
                        "cx": f"{x:.1f}",
                        "cy": f"{y:.1f}",
                        "r": 3.8,
                        "fill": "#38bdf8",
                        "stroke": "#0b0f17",
                        "stroke-width": 1.2,
                    },
                )
            )

    for cliff_ts in hv.scores.sawtooth.compaction_cliffs:
        cx = sx(cliff_ts)
        lines.append(
            _tag(
                "line",
                {
                    "x1": f"{cx:.1f}",
                    "y1": chart_top + 4,
                    "x2": f"{cx:.1f}",
                    "y2": chart_top + top_h + 4,
                    "stroke": "#f59e0b",
                    "stroke-dasharray": "4,3",
                    "stroke-width": 1.5,
                },
            )
        )
        lines.append(
            _tag(
                "text",
                {
                    "x": f"{cx + 5:.1f}",
                    "y": chart_top + 16,
                    "fill": "#fbbf24",
                    "class": "mono",
                    "font-size": 9.5,
                },
                "COMPACTION CLIFF",
            )
        )

    for h_ev in hv.scores.kinematics.handoffs:
        hx = sx(h_ev.timestamp)
        rel_s = h_ev.timestamp - t0
        lines.append(
            _tag(
                "line",
                {
                    "x1": f"{hx:.1f}",
                    "y1": chart_top,
                    "x2": f"{hx:.1f}",
                    "y2": bot_y + bot_h + 12,
                    "stroke": "#f43f5e",
                    "stroke-width": 2,
                },
            )
        )
        lines.append(
            _tag(
                "text",
                {
                    "x": f"{hx + 5:.1f}",
                    "y": chart_top + 30,
                    "fill": "#fb7185",
                    "class": "mono",
                    "font-size": 10,
                    "font-weight": 700,
                },
                f"HANDOFF +{rel_s:.0f}s",
            )
        )

    for act in hv.actions:
        ax = sx(act.timestamp)
        bar_h = max(8.0, (act.bytes_in / max_in) * (bot_h - 14))
        color = "#f43f5e" if act.is_sensitive_lateral else "#10b981"
        lines.append(
            _tag(
                "rect",
                {
                    "x": f"{ax - 2.6:.1f}",
                    "y": f"{bot_y + bot_h - bar_h:.1f}",
                    "width": 5.2,
                    "height": f"{bar_h:.1f}",
                    "rx": 1.5,
                    "fill": color,
                },
            )
        )

    leg_y = h - 14
    legend_items = [
        (76, "#38bdf8", "Encrypted N-S TLS Uplink (Sawtooth)"),
        (332, "#f43f5e", "Sensitive East-West Action (LDAP/SMB/SSH/K8s/Vault)"),
        (690, "#a78bfa", "Causal Coupling Link"),
        (852, "#f59e0b", "Compaction Cliff / Regime Shift"),
    ]
    for lx, col, txt in legend_items:
        lines.append(_tag("circle", {"cx": lx, "cy": leg_y - 4, "r": 4, "fill": col}))
        lines.append(
            _tag(
                "text",
                {"x": lx + 10, "y": leg_y, "fill": "#8b9bb4", "class": "mono", "font-size": 10.5},
                txt,
            )
        )

    lines.append("</svg>")
    return "\n".join(lines) + "\n"


def main() -> None:
    policy = load_policy()
    adapter, events = load_events(DEFAULT_INPUT, policy=policy)
    report = OodaTapEngine(policy=policy).analyze_events(
        events, source_path=DEFAULT_INPUT.name, adapter=adapter
    )
    hv = report.host_verdicts[0]
    DEFAULT_OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    DEFAULT_OUTPUT.write_text(build_timeline_svg(hv, DEFAULT_INPUT.name), encoding="utf-8")
    print(f"Wrote {DEFAULT_OUTPUT}")


if __name__ == "__main__":
    main()
