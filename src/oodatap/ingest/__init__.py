"""Telemetry ingestion adapters for pcap, Zeek, Suricata EVE, and normalized JSONL."""

from oodatap.ingest.base import detect_format, load_events
from oodatap.ingest.jsonl import read_jsonl, write_jsonl
from oodatap.ingest.pcap import read_pcap, write_pcap_from_events, write_pcapng_from_events
from oodatap.ingest.suricata import read_suricata_eve
from oodatap.ingest.zeek import read_zeek_logs

__all__ = [
    "detect_format",
    "load_events",
    "read_jsonl",
    "write_jsonl",
    "read_pcap",
    "write_pcap_from_events",
    "write_pcapng_from_events",
    "read_suricata_eve",
    "read_zeek_logs",
]
