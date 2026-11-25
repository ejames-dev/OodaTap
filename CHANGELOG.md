# Changelog

All notable changes to **OodaTap** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-24

### Added
- **Pure-Python zero-driver capture engine** (`oodatap.ingest.pcap`):
  - Reads and synthesizes both classic **`.pcap`** (LE/BE, microsecond & nanosecond) and Wireshark-default **`.pcapng`** (`SHB`/`IDB`/`EPB`/`SPB` with `if_tsresol`/`if_tsoffset`).
  - Supports Ethernet, 802.1Q VLAN, Linux SLL, Raw IP, **IPv4 and IPv6 (`0x86DD`)** with IPv6 extension-header walking, TCP/UDP, **TLS ClientHello SNI (`0x0000`) extraction**, and **TLS `0x17` Application Data burst framing**.
- **Enterprise log adapters:** Zeek JSON/TSV `conn.log` + auto-discovered `ssl.log`, Suricata `eve.json` (`flow` + `tls`), and OodaTap's canonical normalized JSONL event contract.
- **Three-signal passive OODA detection engine** (`oodatap.detectors`):
  - **Context-Growth Sawtooth:** Kendall's $\tau$ monotonic uplink staircase, compaction-cliff detection, and SSE downlink streaming cadence.
  - **Cross-Flow Causal Coupler:** East-West `bytes_in` ↔ North-South encrypted uplink growth ($\Delta U$) Pearson correlation, observation/dispatch lag matching, and OLS Granger-causality F-test.
  - **Session Kinematics & Handoff Detector:** Parallel tool fan-out clustering + exact BIC-penalized L2 optimal partitioning (dynamic programming) detecting non-monotonic `Agent ↔ Human` takeover transitions while separating classic scripted scanners.
- **Policy & benign dev-agent false-positive suppression** (`policies/default_policy.yaml`): Distinguishes allowlisted developer coding agents (`127.0.0.0/8`, `::1/128`, dev ports/hosts) from lateral movement over sensitive internal protocols.
- **Reporting & CLI (`oodatap`):**
  - Typer + Rich CLI (`analyze`, `ingest`, `benchmark`, `generate-corpus`, `version`).
  - Zero-CDN offline interactive dual-track HTML timeline reports (`--html`) and Elastic Common Schema (ECS) JSONL alert exports (`--ecs-out`).
- **Reproducible 5-class benchmark harness & offline sample traces** (`examples/sample_traces/`), including a 5-host concurrent enterprise capture (`mixed_enterprise.pcapng`).
