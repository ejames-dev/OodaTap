"""Generate committed offline demo traces (.pcap, normalized JSONL, and Zeek JSON conn.log)."""

from __future__ import annotations

import json
from pathlib import Path

from oodatap.benchmark.generator import generate_mixed_enterprise_events, generate_scenario
from oodatap.ingest.jsonl import write_jsonl
from oodatap.ingest.pcap import write_pcap_from_events, write_pcapng_from_events
from oodatap.schemas import ActionEvent, TlsBurstEvent

SAMPLE_DIR = Path(__file__).resolve().parent / "sample_traces"


def _write_zeek_json_sample(events: list[TlsBurstEvent | ActionEvent], out_path: Path) -> None:
    lines: list[str] = []
    for idx, ev in enumerate(events):
        uid = f"Cooda{idx:05d}"
        if isinstance(ev, TlsBurstEvent):
            rec = {
                "ts": ev.timestamp,
                "uid": uid,
                "id.orig_h": ev.src_ip,
                "id.orig_p": ev.src_port,
                "id.resp_h": ev.dst_ip,
                "id.resp_p": ev.dst_port,
                "proto": "tcp",
                "service": "ssl",
                "server_name": ev.sni,
                "duration": round(max(0.01, ev.downlink_end_ts - ev.timestamp), 4),
                "orig_bytes": ev.uplink_bytes,
                "resp_bytes": ev.downlink_bytes,
                "resp_pkts": ev.downlink_record_count,
            }
        else:
            rec = {
                "ts": ev.timestamp,
                "uid": uid,
                "id.orig_h": ev.src_ip,
                "id.orig_p": ev.src_port,
                "id.resp_h": ev.dst_ip,
                "id.resp_p": ev.dst_port,
                "proto": "tcp",
                "service": ev.protocol,
                "duration": round(max(0.01, ev.end_ts - ev.timestamp), 4),
                "orig_bytes": ev.bytes_out,
                "resp_bytes": ev.bytes_in,
                "resp_pkts": 3,
            }
        lines.append(json.dumps(rec))
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    SAMPLE_DIR.mkdir(parents=True, exist_ok=True)

    hybrid = generate_scenario("hybrid_human_agent_intrusion", seed=2026)
    write_jsonl(hybrid.events, SAMPLE_DIR / "hybrid_intrusion.jsonl")
    write_pcap_from_events(hybrid.events, SAMPLE_DIR / "hybrid_intrusion.pcap")

    dev_agent = generate_scenario("benign_dev_agent", seed=2027)
    write_pcap_from_events(dev_agent.events, SAMPLE_DIR / "benign_dev_agent.pcap")

    autonomous = generate_scenario("autonomous_agent_intrusion", seed=2028)
    _write_zeek_json_sample(autonomous.events, SAMPLE_DIR / "zeek_sample_conn.log")

    mixed_events, _expected = generate_mixed_enterprise_events(seed=2029)
    write_pcapng_from_events(mixed_events, SAMPLE_DIR / "mixed_enterprise.pcapng")

    print(f"Wrote sample traces into {SAMPLE_DIR}")


if __name__ == "__main__":
    main()
