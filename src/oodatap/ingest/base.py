"""Format auto-detection and unified telemetry loader."""

from __future__ import annotations

import json
import struct
from pathlib import Path

from oodatap.ingest.jsonl import read_jsonl
from oodatap.ingest.pcap import (
    PCAP_MAGIC_NSEC_BE,
    PCAP_MAGIC_NSEC_LE,
    PCAP_MAGIC_USEC_BE,
    PCAP_MAGIC_USEC_LE,
    PCAPNG_SHB_TYPE,
    read_pcap,
)
from oodatap.ingest.suricata import read_suricata_eve
from oodatap.ingest.zeek import read_zeek_logs
from oodatap.policy import PolicyConfig
from oodatap.schemas import TelemetryEvent


def detect_format(path: Path | str) -> str:
    """Detect input telemetry format: pcap, pcapng, zeek, suricata, or jsonl."""
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Telemetry file not found: {file_path}")

    header = file_path.read_bytes()[:4]
    if len(header) == 4:
        magic = struct.unpack("<I", header)[0]
        if magic == PCAPNG_SHB_TYPE:
            return "pcapng"
        if magic in {
            PCAP_MAGIC_USEC_LE,
            PCAP_MAGIC_USEC_BE,
            PCAP_MAGIC_NSEC_LE,
            PCAP_MAGIC_NSEC_BE,
        }:
            return "pcap"

    with file_path.open("r", encoding="utf-8", errors="ignore") as fh:
        for raw in fh:
            line = raw.strip()
            if not line:
                continue
            if line.startswith("#separator") or line.startswith("#fields"):
                return "zeek"
            if line.startswith("{"):
                obj = json.loads(line)
                if obj.get("kind") in {"tls_burst", "action"}:
                    return "jsonl"
                if "event_type" in obj and ("dest_ip" in obj or "flow" in obj):
                    return "suricata"
                if "id.orig_h" in obj or "orig_bytes" in obj:
                    return "zeek"
                break

    suffix = file_path.suffix.lower()
    if suffix == ".pcapng":
        return "pcapng"
    if suffix == ".pcap":
        return "pcap"
    if suffix == ".log":
        return "zeek"
    if suffix in {".jsonl", ".ndjson"}:
        return "jsonl"
    raise ValueError(f"Could not determine telemetry format for {file_path}")


def load_events(
    path: Path | str,
    fmt: str = "auto",
    policy: PolicyConfig | None = None,
    ssl_log: Path | str | None = None,
) -> tuple[str, list[TelemetryEvent]]:
    """Load telemetry events using auto-detected or explicit adapter format."""
    chosen = detect_format(path) if fmt == "auto" else fmt.lower()
    if chosen in {"pcap", "pcapng"}:
        return chosen, read_pcap(path, policy=policy)
    if chosen == "zeek":
        return "zeek", read_zeek_logs(path, ssl_log_path=ssl_log, policy=policy)
    if chosen == "suricata":
        return "suricata", read_suricata_eve(path, policy=policy)
    if chosen == "jsonl":
        return "jsonl", read_jsonl(path, policy=policy)
    raise ValueError(f"Unknown adapter format: {chosen!r}")
