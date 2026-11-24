"""Tests for Zeek (JSON & TSV), Suricata EVE JSON, JSONL, and format auto-detection."""

from __future__ import annotations

import json
from pathlib import Path

from oodatap.ingest.base import detect_format, load_events
from oodatap.ingest.jsonl import read_jsonl, write_jsonl
from oodatap.policy import PolicyConfig
from oodatap.schemas import ActionEvent, TlsBurstEvent


def test_jsonl_roundtrip(tmp_path: Path) -> None:
    events = [
        TlsBurstEvent(
            timestamp=1000.0,
            src_ip="10.0.1.5",
            dst_ip="160.79.104.10",
            src_port=51234,
            dst_port=443,
            sni="api.anthropic.com",
            uplink_bytes=4200,
            downlink_bytes=1200,
            uplink_end_ts=1000.04,
            downlink_start_ts=1000.8,
            downlink_end_ts=1002.1,
            downlink_record_count=10,
        ),
        ActionEvent(
            timestamp=1002.2,
            end_ts=1002.35,
            src_ip="10.0.1.5",
            dst_ip="10.0.1.10",
            dst_port=445,
            protocol="smb",
            bytes_out=220,
            bytes_in=1900,
        ),
    ]
    out = write_jsonl(events, tmp_path / "events.jsonl")
    assert detect_format(out) == "jsonl"
    loaded = read_jsonl(out, policy=PolicyConfig())
    assert len(loaded) == 2
    assert isinstance(loaded[0], TlsBurstEvent)
    assert loaded[0].is_llm_endpoint is True
    assert isinstance(loaded[1], ActionEvent)
    assert loaded[1].is_sensitive_lateral is True


def test_zeek_tsv_with_sibling_ssl_log(tmp_path: Path) -> None:
    ssl_log = tmp_path / "ssl.log"
    ssl_log.write_text(
        "#separator \\x09\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tserver_name\n"
        "1700000000.0\tCuid01\t10.0.2.5\t50001\t104.18.7.192\t443\tapi.openai.com\n",
        encoding="utf-8",
    )
    conn_log = tmp_path / "conn.log"
    conn_log.write_text(
        "#separator \\x09\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tresp_pkts\n"
        "1700000000.0\tCuid01\t10.0.2.5\t50001\t104.18.7.192\t443\ttcp\tssl\t2.4\t5200\t1400\t12\n"
        "1700000002.6\tCuid02\t10.0.2.5\t50002\t10.0.2.99\t389\ttcp\tldap\t0.15\t240\t3100\t4\n",
        encoding="utf-8",
    )

    assert detect_format(conn_log) == "zeek"
    fmt, events = load_events(conn_log, policy=PolicyConfig())
    assert fmt == "zeek"
    assert len(events) == 2
    assert isinstance(events[0], TlsBurstEvent)
    assert events[0].sni == "api.openai.com"
    assert events[0].is_llm_endpoint is True
    assert isinstance(events[1], ActionEvent)
    assert events[1].protocol == "ldap"
    assert events[1].is_sensitive_lateral is True


def test_suricata_eve_json_adapter(tmp_path: Path) -> None:
    eve_path = tmp_path / "eve.json"
    records = [
        {
            "timestamp": "2026-11-24T12:00:00.000000+0000",
            "flow_id": 9001,
            "event_type": "tls",
            "src_ip": "10.0.3.7",
            "dest_ip": "160.79.104.10",
            "tls": {"sni": "api.anthropic.com"},
        },
        {
            "timestamp": "2026-11-24T12:00:02.500000+0000",
            "flow_id": 9001,
            "event_type": "flow",
            "src_ip": "10.0.3.7",
            "src_port": 54000,
            "dest_ip": "160.79.104.10",
            "dest_port": 443,
            "proto": "TCP",
            "app_proto": "tls",
            "flow": {
                "start": "2026-11-24T12:00:00.000000+0000",
                "end": "2026-11-24T12:00:02.400000+0000",
                "bytes_toserver": 6100,
                "bytes_toclient": 1700,
                "pkts_toclient": 14,
            },
        },
        {
            "timestamp": "2026-11-24T12:00:02.800000+0000",
            "flow_id": 9002,
            "event_type": "flow",
            "src_ip": "10.0.3.7",
            "src_port": 54001,
            "dest_ip": "10.0.3.40",
            "dest_port": 6443,
            "proto": "TCP",
            "app_proto": "http",
            "flow": {
                "start": "2026-11-24T12:00:02.550000+0000",
                "end": "2026-11-24T12:00:02.750000+0000",
                "bytes_toserver": 310,
                "bytes_toclient": 4200,
                "pkts_toclient": 5,
            },
        },
    ]
    eve_path.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")

    assert detect_format(eve_path) == "suricata"
    fmt, events = load_events(eve_path, policy=PolicyConfig())
    assert fmt == "suricata"
    assert len(events) == 2
    assert isinstance(events[0], TlsBurstEvent)
    assert events[0].sni == "api.anthropic.com"
    assert isinstance(events[1], ActionEvent)
    assert events[1].dst_port == 6443
    assert events[1].is_sensitive_lateral is True
