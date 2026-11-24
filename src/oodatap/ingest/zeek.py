"""Zeek conn.log (JSON or TSV) + optional ssl.log adapter."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from oodatap.policy import PolicyConfig
from oodatap.schemas import ActionEvent, TelemetryEvent, TlsBurstEvent


def _parse_zeek_records(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    fields: list[str] = []
    sep = "\t"

    with path.open("r", encoding="utf-8") as fh:
        for raw in fh:
            line = raw.rstrip("\r\n")
            if not line:
                continue
            if line.startswith("{"):
                records.append(json.loads(line))
                continue
            if line.startswith("#separator"):
                token = line.split(" ", 1)[1].strip()
                sep = bytes(token, "utf-8").decode("unicode_escape")
                continue
            if line.startswith("#fields"):
                fields = line.split(sep)[1:]
                continue
            if line.startswith("#"):
                continue
            if fields:
                values = line.split(sep)
                row = {
                    field: (None if val in {"-", "(empty)"} else val)
                    for field, val in zip(fields, values, strict=False)
                }
                records.append(row)
    return records


def _to_float(val: Any, default: float = 0.0) -> float:
    if val is None or val == "-":
        return default
    try:
        return float(val)
    except (TypeError, ValueError):
        return default


def _to_int(val: Any, default: int = 0) -> int:
    if val is None or val == "-":
        return default
    try:
        return int(float(val))
    except (TypeError, ValueError):
        return default


def read_zeek_logs(
    conn_log_path: Path | str,
    ssl_log_path: Path | str | None = None,
    policy: PolicyConfig | None = None,
) -> list[TelemetryEvent]:
    """Read Zeek conn.log (and optional sibling ssl.log) into normalized TelemetryEvents."""
    cfg = policy or PolicyConfig()
    conn_path = Path(conn_log_path)

    # Auto-discover sibling ssl.log if present and not explicitly provided.
    sni_by_uid: dict[str, str] = {}
    candidate_ssl = Path(ssl_log_path) if ssl_log_path else conn_path.with_name("ssl.log")
    if candidate_ssl.exists() and candidate_ssl != conn_path:
        for rec in _parse_zeek_records(candidate_ssl):
            uid = rec.get("uid")
            server_name = rec.get("server_name")
            if uid and server_name:
                sni_by_uid[str(uid)] = str(server_name)

    events: list[TelemetryEvent] = []
    for rec in _parse_zeek_records(conn_path):
        src_ip = str(rec.get("id.orig_h") or rec.get("src_ip") or "")
        dst_ip = str(rec.get("id.resp_h") or rec.get("dst_ip") or "")
        if not src_ip or not dst_ip:
            continue

        ts = _to_float(rec.get("ts"))
        duration = max(0.0, _to_float(rec.get("duration")))
        src_port = _to_int(rec.get("id.orig_p"))
        dst_port = _to_int(rec.get("id.resp_p"))
        orig_bytes = _to_int(rec.get("orig_bytes") or rec.get("orig_ip_bytes"))
        resp_bytes = _to_int(rec.get("resp_bytes") or rec.get("resp_ip_bytes"))
        resp_pkts = max(1, _to_int(rec.get("resp_pkts"), default=1))
        service = str(rec.get("service") or rec.get("proto") or "tcp").lower()
        uid = str(rec.get("uid") or f"{src_ip}:{src_port}->{dst_ip}:{dst_port}")
        sni = rec.get("server_name") or sni_by_uid.get(uid)

        is_tls_llm = (
            service == "ssl" or dst_port == 443 or cfg.is_known_llm_endpoint(sni, dst_ip, dst_port)
        ) and (not cfg.is_internal_ip(dst_ip) or cfg.is_known_llm_endpoint(sni, dst_ip, dst_port))

        if is_tls_llm:
            # Approximate uplink/TTFT/downlink boundaries from Zeek flow summary.
            up_end = ts + min(0.08, duration * 0.1)
            ttft = min(max(0.2, duration * 0.35), max(0.0, duration - 0.05))
            down_start = min(ts + duration, up_end + ttft)
            burst = TlsBurstEvent(
                timestamp=ts,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                sni=str(sni) if sni else None,
                flow_id=uid,
                uplink_bytes=orig_bytes,
                downlink_bytes=resp_bytes,
                uplink_end_ts=up_end,
                downlink_start_ts=down_start,
                downlink_end_ts=ts + duration,
                downlink_record_count=resp_pkts,
            )
            events.append(cfg.classify_tls_burst(burst))
        else:
            action = ActionEvent(
                timestamp=ts,
                end_ts=ts + duration,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=service if service not in {"-", ""} else cfg.protocol_name(dst_port),
                bytes_out=orig_bytes,
                bytes_in=resp_bytes,
            )
            events.append(cfg.classify_action(action))

    events.sort(key=lambda ev: ev.timestamp)
    return events
