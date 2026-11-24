"""Reproducible 5-class synthetic telemetry and .pcap corpus generator for OodaTap."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import numpy as np

from oodatap.ingest.jsonl import write_jsonl
from oodatap.ingest.pcap import write_pcap_from_events
from oodatap.policy import PolicyConfig
from oodatap.schemas import ActionEvent, TelemetryEvent, TlsBurstEvent, VerdictLevel

ScenarioClass = Literal[
    "human_admin",
    "scripted_scanner",
    "benign_dev_agent",
    "autonomous_agent_intrusion",
    "hybrid_human_agent_intrusion",
]

SCENARIO_CLASSES: tuple[ScenarioClass, ...] = (
    "human_admin",
    "scripted_scanner",
    "benign_dev_agent",
    "autonomous_agent_intrusion",
    "hybrid_human_agent_intrusion",
)

EXPECTED_ALERT_CLASSES: set[ScenarioClass] = {
    "autonomous_agent_intrusion",
    "hybrid_human_agent_intrusion",
}

EXPECTED_VERDICT_MAP: dict[ScenarioClass, VerdictLevel] = {
    "human_admin": VerdictLevel.BENIGN,
    "scripted_scanner": VerdictLevel.SCRIPTED_AUTOMATION,
    "benign_dev_agent": VerdictLevel.BENIGN_DEV_AGENT,
    "autonomous_agent_intrusion": VerdictLevel.AGENTIC_OODA_INTRUSION,
    "hybrid_human_agent_intrusion": VerdictLevel.HYBRID_HUMAN_AGENT_INTRUSION,
}


@dataclass
class GeneratedScenario:
    """Labeled synthetic network telemetry trace."""

    name: str
    scenario_class: ScenarioClass
    seed: int
    primary_host: str
    expected_alert: bool
    expected_handoff: bool
    expected_verdict: VerdictLevel
    events: list[TelemetryEvent]


def _make_llm_turn(
    rng: np.random.Generator,
    ts: float,
    src_ip: str,
    dst_ip: str,
    sni: str,
    src_port: int,
    uplink_bytes: int,
    downlink_bytes: int,
    ttft: float,
    decode_s: float,
    sse_records: int,
) -> TlsBurstEvent:
    up_dur = float(rng.uniform(0.015, 0.065))
    up_end = ts + up_dur
    down_start = up_end + ttft
    down_end = down_start + decode_s
    return TlsBurstEvent(
        timestamp=round(ts, 4),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=443,
        sni=sni,
        flow_id=f"{src_ip}:{src_port}->{dst_ip}:443",
        uplink_bytes=int(uplink_bytes),
        downlink_bytes=int(downlink_bytes),
        uplink_end_ts=round(up_end, 4),
        downlink_start_ts=round(down_start, 4),
        downlink_end_ts=round(down_end, 4),
        downlink_record_count=max(4, int(sse_records)),
        is_llm_endpoint=True,
    )


def _gen_human_admin(
    rng: np.random.Generator,
    base_ts: float,
    host_ip: str,
) -> list[TelemetryEvent]:
    """Normal sysadmin: erratic manual SSH/HTTP checks + uncoupled occasional browser Q&A."""
    events: list[TelemetryEvent] = []
    t = base_ts
    targets = [("10.0.1.10", 22, "ssh"), ("10.0.1.15", 80, "http"), ("10.0.1.20", 5432, "postgres")]

    # Manual admin commands with high-variance human think times (8s - 65s).
    for idx in range(12):
        dst_ip, dst_port, proto = targets[idx % len(targets)]
        dur = float(rng.uniform(0.08, 0.45))
        events.append(
            ActionEvent(
                timestamp=round(t, 4),
                end_ts=round(t + dur, 4),
                src_ip=host_ip,
                dst_ip=dst_ip,
                src_port=41000 + idx,
                dst_port=dst_port,
                protocol=proto,
                bytes_out=int(rng.integers(90, 420)),
                bytes_in=int(rng.integers(300, 4800)),
            )
        )
        # Irregular heavy-tailed human pause.
        pause = float(rng.lognormal(mean=2.8, sigma=0.85))
        t += dur + max(4.5, min(70.0, pause))

    # Background normal HTTPS web traffic (flat sizes, non-sawtooth).
    web_t = base_ts + 5.0
    for idx in range(10):
        up_b = int(rng.integers(600, 1400))
        dn_b = int(rng.integers(8000, 32000))
        events.append(
            TlsBurstEvent(
                timestamp=round(web_t, 4),
                src_ip=host_ip,
                dst_ip="151.101.1.69",
                src_port=52100 + idx,
                dst_port=443,
                sni="docs.python.org",
                flow_id=f"{host_ip}:{52100 + idx}->151.101.1.69:443",
                uplink_bytes=up_b,
                downlink_bytes=dn_b,
                uplink_end_ts=round(web_t + 0.02, 4),
                downlink_start_ts=round(web_t + 0.06, 4),
                downlink_end_ts=round(web_t + 0.14, 4),
                downlink_record_count=2,
            )
        )
        web_t += float(rng.uniform(18.0, 45.0))

    # Occasional uncoupled browser chat with an LLM (only 3 casual turns, far from SSH times).
    chat_t = base_ts + 35.0
    ctx = 2400
    for _ in range(3):
        turn = _make_llm_turn(
            rng,
            chat_t,
            host_ip,
            "104.18.7.192",
            "api.openai.com",
            53010,
            uplink_bytes=ctx,
            downlink_bytes=int(rng.integers(1400, 2600)),
            ttft=float(rng.uniform(0.7, 1.5)),
            decode_s=float(rng.uniform(1.8, 3.5)),
            sse_records=int(rng.integers(10, 20)),
        )
        events.append(turn)
        ctx += int(rng.integers(900, 1600))
        chat_t = turn.downlink_end_ts + float(rng.uniform(55.0, 110.0))

    return events


def _gen_scripted_scanner(
    rng: np.random.Generator,
    base_ts: float,
    host_ip: str,
) -> list[TelemetryEvent]:
    """Classic automated port/service scanner: uniform rapid probes, zero LLM stream."""
    events: list[TelemetryEvent] = []
    t = base_ts
    ports = [22, 80, 135, 139, 389, 445, 3389, 5432, 6443, 8080]
    for idx in range(36):
        target_ip = f"10.0.2.{10 + (idx // len(ports))}"
        port = ports[idx % len(ports)]
        dur = float(rng.uniform(0.008, 0.025))
        events.append(
            ActionEvent(
                timestamp=round(t, 4),
                end_ts=round(t + dur, 4),
                src_ip=host_ip,
                dst_ip=target_ip,
                src_port=45000 + idx,
                dst_port=port,
                protocol="tcp",
                bytes_out=int(rng.integers(64, 180)),
                bytes_in=int(rng.integers(64, 240)),
            )
        )
        t += dur + float(rng.uniform(0.04, 0.11))
    return events


def _gen_benign_dev_agent(
    rng: np.random.Generator,
    base_ts: float,
    host_ip: str,
) -> list[TelemetryEvent]:
    """Legitimate coding agent (Claude Code / Cursor): true OODA loop, strictly dev-local."""
    events: list[TelemetryEvent] = []
    t = base_ts
    ctx = 4200
    sni = "api.anthropic.com"
    llm_ip = "160.79.104.10"
    dev_targets = [
        ("127.0.0.1", 3000, "http"),
        ("127.0.0.1", 5173, "http"),
        ("10.0.10.50", 9418, "git"),
    ]

    for turn_idx in range(16):
        if turn_idx == 10:
            # Context compaction cliff
            ctx = int(ctx * 0.36)

        dn_bytes = int(rng.integers(900, 2200))
        ttft = float(rng.uniform(0.45, 1.15))
        decode_s = float(rng.uniform(0.85, 2.2))
        turn = _make_llm_turn(
            rng,
            t,
            host_ip,
            llm_ip,
            sni,
            54110,
            uplink_bytes=ctx,
            downlink_bytes=dn_bytes,
            ttft=ttft,
            decode_s=decode_s,
            sse_records=int(rng.integers(8, 18)),
        )
        events.append(turn)

        # Agent immediately invokes local dev server / git check.
        dispatch_lag = float(rng.uniform(0.05, 0.25))
        act_t = turn.downlink_end_ts + dispatch_lag
        n_tools = 2 if turn_idx % 4 == 0 else 1
        ew_in_total = 0
        last_end = act_t

        for j in range(n_tools):
            dst_ip, dst_port, proto = dev_targets[(turn_idx + j) % len(dev_targets)]
            a_start = act_t + j * float(rng.uniform(0.01, 0.05))
            a_dur = float(rng.uniform(0.05, 0.22))
            b_in = int(rng.integers(600, 3400))
            ew_in_total += b_in
            last_end = max(last_end, a_start + a_dur)
            events.append(
                ActionEvent(
                    timestamp=round(a_start, 4),
                    end_ts=round(a_start + a_dur, 4),
                    src_ip=host_ip,
                    dst_ip=dst_ip,
                    src_port=48000 + turn_idx * 4 + j,
                    dst_port=dst_port,
                    protocol=proto,
                    bytes_out=int(rng.integers(140, 480)),
                    bytes_in=b_in,
                )
            )

        obs_lag = float(rng.uniform(0.06, 0.30))
        t = last_end + obs_lag
        ctx += dn_bytes + int(ew_in_total * float(rng.uniform(0.95, 1.15))) + 180

    return events


def _gen_autonomous_agent_intrusion(
    rng: np.random.Generator,
    base_ts: float,
    host_ip: str,
) -> list[TelemetryEvent]:
    """Compromised host running an autonomous offensive LLM agent across internal targets."""
    events: list[TelemetryEvent] = []
    t = base_ts
    ctx = 5600
    sni = "api.anthropic.com"
    llm_ip = "160.79.104.10"
    lateral_targets = [
        ("10.0.5.10", 389, "ldap"),
        ("10.0.5.11", 445, "smb"),
        ("10.0.5.14", 22, "ssh"),
        ("10.0.5.20", 6443, "k8s_api"),
        ("10.0.5.22", 5985, "winrm"),
        ("10.0.5.30", 5432, "postgres"),
    ]

    last_ew_in = 1200
    for turn_idx in range(20):
        if turn_idx == 12:
            # Mid-operation context compaction cliff
            ctx = int(ctx * 0.34)

        dn_bytes = int(rng.integers(950, 2600))
        # Inference duration scales modestly with context + previous tool output.
        ttft = float(rng.uniform(0.45, 0.95) + 0.00025 * min(last_ew_in, 8000))
        decode_s = float(rng.uniform(0.85, 2.0) + 0.00018 * min(last_ew_in, 8000))
        turn = _make_llm_turn(
            rng,
            t,
            host_ip,
            llm_ip,
            sni,
            55200,
            uplink_bytes=ctx,
            downlink_bytes=dn_bytes,
            ttft=ttft,
            decode_s=decode_s,
            sse_records=int(rng.integers(9, 22)),
        )
        events.append(turn)

        # Tight autonomous dispatch into East-West targets with parallel tool fan-out.
        dispatch_lag = float(rng.uniform(0.05, 0.28))
        act_t = turn.downlink_end_ts + dispatch_lag
        fanout_width = int(rng.choice([1, 2, 3], p=[0.40, 0.40, 0.20]))
        ew_in_total = 0
        last_end = act_t

        for j in range(fanout_width):
            dst_ip, dst_port, proto = lateral_targets[(turn_idx + j) % len(lateral_targets)]
            a_start = act_t + j * float(rng.uniform(0.015, 0.055))
            a_dur = float(rng.uniform(0.05, 0.26))
            b_in = int(rng.integers(700, 5200))
            ew_in_total += b_in
            last_end = max(last_end, a_start + a_dur)
            events.append(
                ActionEvent(
                    timestamp=round(a_start, 4),
                    end_ts=round(a_start + a_dur, 4),
                    src_ip=host_ip,
                    dst_ip=dst_ip,
                    src_port=49200 + turn_idx * 5 + j,
                    dst_port=dst_port,
                    protocol=proto,
                    bytes_out=int(rng.integers(180, 620)),
                    bytes_in=b_in,
                )
            )

        obs_lag = float(rng.uniform(0.06, 0.34))
        t = last_end + obs_lag
        last_ew_in = ew_in_total
        ctx += dn_bytes + int(ew_in_total * float(rng.uniform(0.98, 1.12))) + 220

    return events


def _gen_hybrid_human_agent_intrusion(
    rng: np.random.Generator,
    base_ts: float,
    host_ip: str,
) -> list[TelemetryEvent]:
    """Human+Agentic intrusion: autonomous recon -> human manual takeover -> agentic sweep."""
    events: list[TelemetryEvent] = []
    t = base_ts
    ctx = 5200
    sni = "api.openai.com"
    llm_ip = "104.18.7.192"
    lateral_targets = [
        ("10.0.8.10", 389, "ldap"),
        ("10.0.8.12", 445, "smb"),
        ("10.0.8.15", 22, "ssh"),
        ("10.0.8.20", 6443, "k8s_api"),
        ("10.0.8.25", 8200, "vault"),
    ]

    # Phase 1: Autonomous offensive agentic recon (12 tight coupled OODA turns with fan-out).
    last_ew_in = 1400
    for turn_idx in range(12):
        if turn_idx == 8:
            ctx = int(ctx * 0.38)
        dn_bytes = int(rng.integers(900, 2100))
        ttft = float(rng.uniform(0.45, 0.90) + 0.0002 * min(last_ew_in, 7000))
        decode_s = float(rng.uniform(0.80, 1.75) + 0.00015 * min(last_ew_in, 7000))
        turn = _make_llm_turn(
            rng,
            t,
            host_ip,
            llm_ip,
            sni,
            56100,
            uplink_bytes=ctx,
            downlink_bytes=dn_bytes,
            ttft=ttft,
            decode_s=decode_s,
            sse_records=int(rng.integers(9, 20)),
        )
        events.append(turn)

        act_t = turn.downlink_end_ts + float(rng.uniform(0.05, 0.25))
        fanout = 2 if turn_idx % 2 == 0 else 3 if turn_idx % 3 == 0 else 1
        ew_in_total = 0
        last_end = act_t
        for j in range(fanout):
            dst_ip, dst_port, proto = lateral_targets[(turn_idx + j) % len(lateral_targets)]
            a_start = act_t + j * float(rng.uniform(0.012, 0.048))
            a_dur = float(rng.uniform(0.05, 0.22))
            b_in = int(rng.integers(800, 4800))
            ew_in_total += b_in
            last_end = max(last_end, a_start + a_dur)
            events.append(
                ActionEvent(
                    timestamp=round(a_start, 4),
                    end_ts=round(a_start + a_dur, 4),
                    src_ip=host_ip,
                    dst_ip=dst_ip,
                    src_port=50100 + turn_idx * 5 + j,
                    dst_port=dst_port,
                    protocol=proto,
                    bytes_out=int(rng.integers(160, 580)),
                    bytes_in=b_in,
                )
            )
        t = last_end + float(rng.uniform(0.06, 0.28))
        last_ew_in = ew_in_total
        ctx += dn_bytes + int(ew_in_total * float(rng.uniform(0.98, 1.12))) + 200

    # Phase 2: Human operator takes over manually (9 erratic, slow, single-command exploits).
    t += float(rng.uniform(16.0, 26.0))
    for h_idx in range(9):
        dst_ip, dst_port, proto = (
            ("10.0.8.15", 22, "ssh")
            if h_idx % 2 == 0
            else (
                "10.0.8.25",
                8200,
                "vault",
            )
        )
        a_dur = float(rng.uniform(0.12, 0.65))
        events.append(
            ActionEvent(
                timestamp=round(t, 4),
                end_ts=round(t + a_dur, 4),
                src_ip=host_ip,
                dst_ip=dst_ip,
                src_port=51200 + h_idx,
                dst_port=dst_port,
                protocol=proto,
                bytes_out=int(rng.integers(90, 380)),
                bytes_in=int(rng.integers(350, 3200)),
            )
        )
        human_pause = float(rng.uniform(12.0, 42.0)) * float(rng.choice([0.75, 1.0, 1.6]))
        t += a_dur + human_pause

    # Phase 3: Human hands back to autonomous agent for post-exploitation sweep (8 turns).
    ctx = 6100
    for turn_idx in range(8):
        dn_bytes = int(rng.integers(850, 1900))
        ttft = float(rng.uniform(0.45, 0.90))
        decode_s = float(rng.uniform(0.80, 1.65))
        turn = _make_llm_turn(
            rng,
            t,
            host_ip,
            llm_ip,
            sni,
            56100,
            uplink_bytes=ctx,
            downlink_bytes=dn_bytes,
            ttft=ttft,
            decode_s=decode_s,
            sse_records=int(rng.integers(8, 18)),
        )
        events.append(turn)

        act_t = turn.downlink_end_ts + float(rng.uniform(0.05, 0.25))
        fanout = 2 if turn_idx % 2 == 0 else 1
        ew_in_total = 0
        last_end = act_t
        for j in range(fanout):
            dst_ip, dst_port, proto = lateral_targets[(turn_idx + j + 2) % len(lateral_targets)]
            a_start = act_t + j * float(rng.uniform(0.015, 0.05))
            a_dur = float(rng.uniform(0.05, 0.20))
            b_in = int(rng.integers(900, 4200))
            ew_in_total += b_in
            last_end = max(last_end, a_start + a_dur)
            events.append(
                ActionEvent(
                    timestamp=round(a_start, 4),
                    end_ts=round(a_start + a_dur, 4),
                    src_ip=host_ip,
                    dst_ip=dst_ip,
                    src_port=52300 + turn_idx * 4 + j,
                    dst_port=dst_port,
                    protocol=proto,
                    bytes_out=int(rng.integers(180, 520)),
                    bytes_in=b_in,
                )
            )
        t = last_end + float(rng.uniform(0.06, 0.28))
        ctx += dn_bytes + int(ew_in_total * float(rng.uniform(0.98, 1.12))) + 200

    return events


def generate_scenario(
    scenario_class: ScenarioClass,
    seed: int = 42,
    base_ts: float = 1_760_000_000.0,
    policy: PolicyConfig | None = None,
) -> GeneratedScenario:
    """Generate a single deterministic labeled telemetry scenario."""
    rng = np.random.default_rng(seed)
    cfg = policy or PolicyConfig()
    host_ip = {
        "human_admin": "10.0.10.11",
        "scripted_scanner": "10.0.10.22",
        "benign_dev_agent": "10.0.10.33",
        "autonomous_agent_intrusion": "10.0.20.44",
        "hybrid_human_agent_intrusion": "10.0.20.55",
    }[scenario_class]

    raw_events = {
        "human_admin": _gen_human_admin,
        "scripted_scanner": _gen_scripted_scanner,
        "benign_dev_agent": _gen_benign_dev_agent,
        "autonomous_agent_intrusion": _gen_autonomous_agent_intrusion,
        "hybrid_human_agent_intrusion": _gen_hybrid_human_agent_intrusion,
    }[scenario_class](rng, base_ts, host_ip)

    classified: list[TelemetryEvent] = []
    for ev in raw_events:
        if isinstance(ev, TlsBurstEvent):
            classified.append(cfg.classify_tls_burst(ev))
        else:
            classified.append(cfg.classify_action(ev))
    classified.sort(key=lambda ev: ev.timestamp)

    return GeneratedScenario(
        name=f"{scenario_class}_seed{seed}",
        scenario_class=scenario_class,
        seed=seed,
        primary_host=host_ip,
        expected_alert=scenario_class in EXPECTED_ALERT_CLASSES,
        expected_handoff=scenario_class == "hybrid_human_agent_intrusion",
        expected_verdict=EXPECTED_VERDICT_MAP[scenario_class],
        events=classified,
    )


def generate_corpus(
    output_dir: Path | str,
    seeds_per_class: int = 3,
    write_pcaps: bool = True,
    base_seed: int = 100,
) -> list[GeneratedScenario]:
    """Generate a full labeled JSONL (+ optional binary .pcap) benchmark corpus on disk."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    scenarios: list[GeneratedScenario] = []
    manifest: list[dict[str, object]] = []

    for cls_idx, scenario_class in enumerate(SCENARIO_CLASSES):
        for offset in range(seeds_per_class):
            seed = base_seed + cls_idx * 100 + offset
            sc = generate_scenario(scenario_class, seed=seed)
            scenarios.append(sc)
            jsonl_path = write_jsonl(sc.events, out / f"{sc.name}.jsonl")
            pcap_rel = None
            if write_pcaps:
                pcap_path = write_pcap_from_events(sc.events, out / f"{sc.name}.pcap")
                pcap_rel = pcap_path.name
            manifest.append(
                {
                    "name": sc.name,
                    "scenario_class": sc.scenario_class,
                    "seed": sc.seed,
                    "primary_host": sc.primary_host,
                    "expected_alert": sc.expected_alert,
                    "expected_handoff": sc.expected_handoff,
                    "expected_verdict": sc.expected_verdict.value,
                    "jsonl": jsonl_path.name,
                    "pcap": pcap_rel,
                    "event_count": len(sc.events),
                }
            )

    (out / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return scenarios
