"""Suricata EVE JSON (flow + tls) telemetry adapter."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from oodatap.policy import PolicyConfig
from oodatap.schemas import ActionEvent, TelemetryEvent, TlsBurstEvent


def _parse_iso_ts(value: str | float | int | None) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    if not value:
        return 0.0
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    # Handle Suricata +0000 timezone format without colon.
    if len(text) >= 5 and text[-5] in {"+", "-"} and text[-3] != ":":
        text = text[:-2] + ":" + text[-2:]
    return datetime.fromisoformat(text).timestamp()


def read_suricata_eve(
    path: Path | str,
    policy: PolicyConfig | None = None,
) -> list[TelemetryEvent]:
    """Read Suricata eve.json records into normalized OodaTap TelemetryEvents."""
    cfg = policy or PolicyConfig()
    file_path = Path(path)
    raw_records: list[dict[str, Any]] = []
    sni_by_flow: dict[Any, str] = {}

    with file_path.open("r", encoding="utf-8") as fh:
        for raw in fh:
            stripped = raw.strip()
            if not stripped:
                continue
            rec = json.loads(stripped)
            raw_records.append(rec)
            if rec.get("event_type") == "tls" and rec.get("flow_id") is not None:
                sni = (rec.get("tls") or {}).get("sni")
                if sni:
                    sni_by_flow[rec["flow_id"]] = str(sni)

    events: list[TelemetryEvent] = []
    for rec in raw_records:
        if rec.get("event_type") != "flow":
            continue
        flow = rec.get("flow") or {}
        src_ip = str(rec.get("src_ip") or "")
        dst_ip = str(rec.get("dest_ip") or "")
        if not src_ip or not dst_ip:
            continue

        src_port = int(rec.get("src_port") or 0)
        dst_port = int(rec.get("dest_port") or 0)
        start_ts = _parse_iso_ts(flow.get("start") or rec.get("timestamp"))
        end_ts = max(start_ts, _parse_iso_ts(flow.get("end") or rec.get("timestamp")))
        duration = max(0.0, end_ts - start_ts)
        bytes_toserver = int(flow.get("bytes_toserver") or 0)
        bytes_toclient = int(flow.get("bytes_toclient") or 0)
        pkts_toclient = max(1, int(flow.get("pkts_toclient") or 1))
        app_proto = str(rec.get("app_proto") or rec.get("proto") or "tcp").lower()
        flow_id = rec.get("flow_id")
        sni = sni_by_flow.get(flow_id)

        is_tls_llm = (
            app_proto == "tls"
            or dst_port == 443
            or cfg.is_known_llm_endpoint(sni, dst_ip, dst_port)
        ) and (not cfg.is_internal_ip(dst_ip) or cfg.is_known_llm_endpoint(sni, dst_ip, dst_port))

        if is_tls_llm:
            up_end = start_ts + min(0.08, duration * 0.1)
            ttft = min(max(0.2, duration * 0.35), max(0.0, duration - 0.05))
            down_start = min(end_ts, up_end + ttft)
            burst = TlsBurstEvent(
                timestamp=start_ts,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                sni=sni,
                flow_id=str(flow_id or f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"),
                uplink_bytes=bytes_toserver,
                downlink_bytes=bytes_toclient,
                uplink_end_ts=up_end,
                downlink_start_ts=down_start,
                downlink_end_ts=end_ts,
                downlink_record_count=pkts_toclient,
            )
            events.append(cfg.classify_tls_burst(burst))
        else:
            action = ActionEvent(
                timestamp=start_ts,
                end_ts=end_ts,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=app_proto
                if app_proto not in {"failed", "unknown", ""}
                else cfg.protocol_name(dst_port),
                bytes_out=bytes_toserver,
                bytes_in=bytes_toclient,
            )
            events.append(cfg.classify_action(action))

    events.sort(key=lambda ev: ev.timestamp)
    return events
