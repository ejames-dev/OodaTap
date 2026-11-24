"""Pure-Python binary .pcap reader/writer with TLS ClientHello SNI and AppData burst framing."""

from __future__ import annotations

import ipaddress
import socket
import struct
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from oodatap.policy import PolicyConfig
from oodatap.schemas import ActionEvent, TelemetryEvent, TlsBurstEvent

PCAP_MAGIC_USEC_LE = 0xA1B2C3D4
PCAP_MAGIC_USEC_BE = 0xD4C3B2A1
PCAP_MAGIC_NSEC_LE = 0xA1B23C4D
PCAP_MAGIC_NSEC_BE = 0x4D3CB2A1

DLT_EN10MB = 1
DLT_RAW = 101
DLT_LINUX_SLL = 113

TLS_HANDSHAKE = 0x16
TLS_APP_DATA = 0x17
TLS_CLIENT_HELLO = 0x01


@dataclass
class _PacketRecord:
    ts: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: int  # 6=TCP, 17=UDP
    tcp_flags: int
    payload: bytes


@dataclass
class _FlowPacket:
    ts: float
    from_client: bool
    payload_len: int
    tls_app_records: int
    tls_app_bytes: int


@dataclass
class _FlowState:
    client_ip: str
    server_ip: str
    client_port: int
    server_port: int
    proto: int
    sni: str | None = None
    saw_tls: bool = False
    packets: list[_FlowPacket] = field(default_factory=list)


def _ipv4_checksum(header: bytes) -> int:
    if len(header) % 2 == 1:
        header += b"\x00"
    total = 0
    for idx in range(0, len(header), 2):
        total += (header[idx] << 8) | header[idx + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def parse_tls_client_hello_sni(payload: bytes) -> str | None:
    """Extract the Server Name Indication (SNI) hostname from a TLS ClientHello record."""
    if len(payload) < 43 or payload[0] != TLS_HANDSHAKE:
        return None
    record_len = struct.unpack("!H", payload[3:5])[0]
    hs = payload[5 : 5 + record_len]
    if len(hs) < 38 or hs[0] != TLS_CLIENT_HELLO:
        return None

    pos = 4 + 2 + 32  # handshake header (4) + version (2) + random (32)
    if pos >= len(hs):
        return None
    session_id_len = hs[pos]
    pos += 1 + session_id_len
    if pos + 2 > len(hs):
        return None

    cipher_suites_len = struct.unpack("!H", hs[pos : pos + 2])[0]
    pos += 2 + cipher_suites_len
    if pos >= len(hs):
        return None

    comp_methods_len = hs[pos]
    pos += 1 + comp_methods_len
    if pos + 2 > len(hs):
        return None

    extensions_len = struct.unpack("!H", hs[pos : pos + 2])[0]
    pos += 2
    end_ext = min(len(hs), pos + extensions_len)

    while pos + 4 <= end_ext:
        ext_type, ext_len = struct.unpack("!HH", hs[pos : pos + 4])
        pos += 4
        if ext_type == 0x0000 and pos + ext_len <= end_ext:
            ext_data = hs[pos : pos + ext_len]
            if len(ext_data) >= 5:
                list_len = struct.unpack("!H", ext_data[0:2])[0]
                s_pos = 2
                s_end = min(len(ext_data), 2 + list_len)
                while s_pos + 3 <= s_end:
                    name_type = ext_data[s_pos]
                    name_len = struct.unpack("!H", ext_data[s_pos + 1 : s_pos + 3])[0]
                    s_pos += 3
                    if name_type == 0x00 and s_pos + name_len <= s_end:
                        try:
                            return ext_data[s_pos : s_pos + name_len].decode("ascii")
                        except UnicodeDecodeError:
                            return None
                    s_pos += name_len
            return None
        pos += ext_len
    return None


def inspect_tls_app_data(payload: bytes) -> tuple[int, int]:
    """Count TLS Application Data (0x17) records and payload bytes within a TCP segment."""
    pos = 0
    records = 0
    total_bytes = 0
    n = len(payload)
    while pos + 5 <= n:
        content_type = payload[pos]
        ver_major = payload[pos + 1]
        rec_len = struct.unpack("!H", payload[pos + 3 : pos + 5])[0]
        if content_type not in (0x14, 0x15, 0x16, 0x17) or ver_major != 0x03 or rec_len > 18432:
            break
        if content_type == TLS_APP_DATA:
            records += 1
            total_bytes += rec_len
        pos += 5 + rec_len
        if pos > n:
            break
    return records, total_bytes


def _parse_frame(frame: bytes, link_type: int, ts: float) -> _PacketRecord | None:
    if link_type == DLT_EN10MB:
        if len(frame) < 14:
            return None
        ethertype = struct.unpack("!H", frame[12:14])[0]
        offset = 14
        if ethertype == 0x8100 and len(frame) >= 18:
            ethertype = struct.unpack("!H", frame[16:18])[0]
            offset = 18
        if ethertype != 0x0800:
            return None
    elif link_type == DLT_LINUX_SLL:
        if len(frame) < 16:
            return None
        ethertype = struct.unpack("!H", frame[14:16])[0]
        if ethertype != 0x0800:
            return None
        offset = 16
    elif link_type == DLT_RAW:
        offset = 0
    else:
        return None

    if len(frame) < offset + 20:
        return None
    ver_ihl = frame[offset]
    if (ver_ihl >> 4) != 4:
        return None
    ihl = (ver_ihl & 0x0F) * 4
    total_len = struct.unpack("!H", frame[offset + 2 : offset + 4])[0]
    proto = frame[offset + 9]
    src_ip = socket.inet_ntoa(frame[offset + 12 : offset + 16])
    dst_ip = socket.inet_ntoa(frame[offset + 16 : offset + 20])
    l4_start = offset + ihl
    l4_end = min(len(frame), offset + total_len)

    if proto == 6 and l4_end >= l4_start + 20:  # TCP
        src_port, dst_port = struct.unpack("!HH", frame[l4_start : l4_start + 4])
        data_offset = (frame[l4_start + 12] >> 4) * 4
        tcp_flags = frame[l4_start + 13]
        payload = frame[l4_start + data_offset : l4_end]
        return _PacketRecord(ts, src_ip, dst_ip, src_port, dst_port, 6, tcp_flags, payload)

    if proto == 17 and l4_end >= l4_start + 8:  # UDP
        src_port, dst_port = struct.unpack("!HH", frame[l4_start : l4_start + 4])
        payload = frame[l4_start + 8 : l4_end]
        return _PacketRecord(ts, src_ip, dst_ip, src_port, dst_port, 17, 0, payload)

    return None


def _extract_tls_bursts(
    flow: _FlowState,
    policy: PolicyConfig,
    uplink_merge_gap_s: float = 0.25,
) -> list[TlsBurstEvent]:
    """Reconstruct turn-by-turn client uplink -> server downlink TLS bursts."""
    bursts: list[TlsBurstEvent] = []
    pkts = [p for p in flow.packets if p.payload_len > 0]
    if not pkts:
        return bursts

    flow_id = f"{flow.client_ip}:{flow.client_port}->{flow.server_ip}:{flow.server_port}"
    idx = 0
    n = len(pkts)

    while idx < n:
        if not pkts[idx].from_client:
            idx += 1
            continue

        # Accumulate contiguous client uplink segments for this turn.
        up_start = pkts[idx].ts
        up_end = up_start
        up_bytes = pkts[idx].tls_app_bytes or pkts[idx].payload_len
        idx += 1
        while idx < n and pkts[idx].from_client and (pkts[idx].ts - up_end) <= uplink_merge_gap_s:
            up_end = pkts[idx].ts
            up_bytes += pkts[idx].tls_app_bytes or pkts[idx].payload_len
            idx += 1

        # Accumulate subsequent server downlink segments until the next client burst.
        if idx >= n or pkts[idx].from_client:
            continue

        down_start = pkts[idx].ts
        down_end = down_start
        down_bytes = 0
        down_records = 0
        while idx < n and not pkts[idx].from_client:
            down_end = pkts[idx].ts
            down_bytes += pkts[idx].tls_app_bytes or pkts[idx].payload_len
            down_records += max(1, pkts[idx].tls_app_records)
            idx += 1

        if up_bytes > 0 and down_bytes > 0:
            burst = TlsBurstEvent(
                timestamp=up_start,
                src_ip=flow.client_ip,
                dst_ip=flow.server_ip,
                src_port=flow.client_port,
                dst_port=flow.server_port,
                sni=flow.sni,
                flow_id=flow_id,
                uplink_bytes=up_bytes,
                downlink_bytes=down_bytes,
                uplink_end_ts=up_end,
                downlink_start_ts=down_start,
                downlink_end_ts=down_end,
                downlink_record_count=max(1, down_records),
            )
            bursts.append(policy.classify_tls_burst(burst))
    return bursts


def _extract_action_events(
    flow: _FlowState,
    policy: PolicyConfig,
    turn_gap_s: float = 0.35,
) -> list[ActionEvent]:
    """Convert non-TLS internal/external request-response flows into ActionEvent turns."""
    pkts = [p for p in flow.packets if p.payload_len > 0]
    if not pkts:
        return []

    events: list[ActionEvent] = []
    cur_start = pkts[0].ts
    cur_end = pkts[0].ts
    bytes_out = 0
    bytes_in = 0
    saw_reply = False

    def flush() -> None:
        if bytes_out == 0 and bytes_in == 0:
            return
        proto_fallback = "udp" if flow.proto == 17 else "tcp"
        ev = ActionEvent(
            timestamp=cur_start,
            end_ts=max(cur_start, cur_end),
            src_ip=flow.client_ip,
            dst_ip=flow.server_ip,
            src_port=flow.client_port,
            dst_port=flow.server_port,
            protocol=policy.protocol_name(flow.server_port, fallback=proto_fallback),
            bytes_out=bytes_out,
            bytes_in=bytes_in,
        )
        events.append(policy.classify_action(ev))

    for pkt in pkts:
        is_new_turn = pkt.from_client and saw_reply and (pkt.ts - cur_end) >= turn_gap_s
        if is_new_turn:
            flush()
            cur_start = pkt.ts
            cur_end = pkt.ts
            bytes_out = 0
            bytes_in = 0
            saw_reply = False

        cur_end = pkt.ts
        if pkt.from_client:
            bytes_out += pkt.payload_len
        else:
            bytes_in += pkt.payload_len
            saw_reply = True

    flush()
    return events


def read_pcap(
    path: Path | str,
    policy: PolicyConfig | None = None,
) -> list[TelemetryEvent]:
    """Read a standard .pcap file and normalize packets into TLS bursts and ActionEvents."""
    cfg = policy or PolicyConfig()
    data = Path(path).read_bytes()
    if len(data) < 24:
        raise ValueError(f"File {path} is too small to be a valid .pcap capture.")

    magic = struct.unpack("<I", data[:4])[0]
    if magic == PCAP_MAGIC_USEC_LE:
        endian, ts_div = "<", 1_000_000.0
    elif magic == PCAP_MAGIC_USEC_BE:
        endian, ts_div = ">", 1_000_000.0
    elif magic == PCAP_MAGIC_NSEC_LE:
        endian, ts_div = "<", 1_000_000_000.0
    elif magic == PCAP_MAGIC_NSEC_BE:
        endian, ts_div = ">", 1_000_000_000.0
    else:
        raise ValueError(f"Unsupported pcap magic header: 0x{magic:08x}")

    _vmaj, _vmin, _tz, _sig, _snaplen, link_type = struct.unpack(f"{endian}HHiIII", data[4:24])
    pos = 24
    flows: dict[tuple[str, int, str, int, int], _FlowState] = {}

    while pos + 16 <= len(data):
        ts_sec, ts_sub, incl_len, _orig_len = struct.unpack(f"{endian}IIII", data[pos : pos + 16])
        pos += 16
        if pos + incl_len > len(data):
            break
        frame = data[pos : pos + incl_len]
        pos += incl_len

        ts = ts_sec + (ts_sub / ts_div)
        pkt = _parse_frame(frame, link_type, ts)
        if pkt is None:
            continue

        fwd_key = (pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port, pkt.proto)
        rev_key = (pkt.dst_ip, pkt.dst_port, pkt.src_ip, pkt.src_port, pkt.proto)

        if fwd_key in flows:
            flow = flows[fwd_key]
            from_client = True
        elif rev_key in flows:
            flow = flows[rev_key]
            from_client = False
        else:
            # First packet seen defines client -> server direction.
            flow = _FlowState(
                client_ip=pkt.src_ip,
                server_ip=pkt.dst_ip,
                client_port=pkt.src_port,
                server_port=pkt.dst_port,
                proto=pkt.proto,
            )
            flows[fwd_key] = flow
            from_client = True

        if not pkt.payload:
            continue

        sni = parse_tls_client_hello_sni(pkt.payload) if from_client else None
        if sni:
            flow.sni = sni
            flow.saw_tls = True
            # ClientHello is handshake metadata, not an application-data turn.
            continue

        if pkt.payload[0] == TLS_HANDSHAKE and len(pkt.payload) >= 5 and pkt.payload[1] == 0x03:
            flow.saw_tls = True
            continue

        app_recs, app_bytes = inspect_tls_app_data(pkt.payload)
        if app_recs > 0:
            flow.saw_tls = True

        flow.packets.append(
            _FlowPacket(
                ts=ts,
                from_client=from_client,
                payload_len=len(pkt.payload),
                tls_app_records=app_recs,
                tls_app_bytes=app_bytes,
            )
        )

    events: list[TelemetryEvent] = []
    for flow in flows.values():
        is_tls_or_llm = (
            flow.saw_tls
            or flow.server_port == 443
            or cfg.is_known_llm_endpoint(flow.sni, flow.server_ip, flow.server_port)
        )
        if is_tls_or_llm and (
            not cfg.is_internal_ip(flow.server_ip)
            or cfg.is_known_llm_endpoint(flow.sni, flow.server_ip, flow.server_port)
        ):
            events.extend(_extract_tls_bursts(flow, cfg))
        else:
            events.extend(_extract_action_events(flow, cfg))

    events.sort(key=lambda ev: ev.timestamp)
    return events


def _build_tls_client_hello(sni: str) -> bytes:
    """Construct a minimal RFC-compliant TLS ClientHello carrying the given SNI hostname."""
    sni_bytes = sni.encode("ascii")
    # SNI extension: type(2)=0x0000, ext_len(2), list_len(2), name_type(1)=0x00, name_len(2), name
    sni_entry = struct.pack("!BH", 0, len(sni_bytes)) + sni_bytes
    sni_list = struct.pack("!H", len(sni_entry)) + sni_entry
    sni_ext = struct.pack("!HH", 0x0000, len(sni_list)) + sni_list
    extensions = struct.pack("!H", len(sni_ext)) + sni_ext

    client_version = b"\x03\x03"
    random_bytes = b"\x42" * 32
    session_id = b"\x00"
    cipher_suites = struct.pack("!HH", 2, 0x1301)  # TLS_AES_128_GCM_SHA256
    compression = b"\x01\x00"

    body = client_version + random_bytes + session_id + cipher_suites + compression + extensions
    handshake = struct.pack("!B", TLS_CLIENT_HELLO) + len(body).to_bytes(3, "big") + body
    return struct.pack("!BBBH", TLS_HANDSHAKE, 0x03, 0x01, len(handshake)) + handshake


def _build_tls_app_record(payload_len: int) -> bytes:
    body_len = max(1, min(payload_len, 16384))
    return struct.pack("!BBBH", TLS_APP_DATA, 0x03, 0x03, body_len) + (b"\xa5" * body_len)


def _build_eth_ipv4_tcp_frame(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    seq: int,
    ack: int,
    payload: bytes,
    flags: int = 0x18,  # PSH + ACK
) -> bytes:
    eth = b"\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00"
    tcp_hdr = struct.pack(
        "!HHIIBBHHH",
        src_port & 0xFFFF,
        dst_port & 0xFFFF,
        seq & 0xFFFFFFFF,
        ack & 0xFFFFFFFF,
        0x50,  # data offset = 5 (20 bytes)
        flags,
        65535,
        0,
        0,
    )
    total_len = 20 + len(tcp_hdr) + len(payload)
    src_b = ipaddress.IPv4Address(src_ip).packed
    dst_b = ipaddress.IPv4Address(dst_ip).packed
    ip_hdr_no_csum = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_len,
        0x1234,
        0x4000,
        64,
        6,
        0,
        src_b,
        dst_b,
    )
    csum = _ipv4_checksum(ip_hdr_no_csum)
    ip_hdr = ip_hdr_no_csum[:10] + struct.pack("!H", csum) + ip_hdr_no_csum[12:]
    return eth + ip_hdr + tcp_hdr + payload


def write_pcap_from_events(events: Iterable[TelemetryEvent], path: Path | str) -> Path:
    """Serialize TelemetryEvents into a valid Wireshark-openable binary .pcap capture."""
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    raw_packets: list[tuple[float, bytes]] = []
    seq_tracker: dict[tuple[str, int, str, int], int] = defaultdict(lambda: 1000)
    emitted_client_hellos: set[tuple[str, int, str, int]] = set()
    next_ephemeral_port = 49152

    def emit_tcp(
        ts: float,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        payload: bytes,
    ) -> None:
        fwd = (src_ip, src_port, dst_ip, dst_port)
        rev = (dst_ip, dst_port, src_ip, src_port)
        seq = seq_tracker[fwd]
        ack = seq_tracker[rev]
        frame = _build_eth_ipv4_tcp_frame(src_ip, dst_ip, src_port, dst_port, seq, ack, payload)
        seq_tracker[fwd] = (seq + len(payload)) & 0xFFFFFFFF
        raw_packets.append((ts, frame))

    for ev in sorted(events, key=lambda item: item.timestamp):
        if isinstance(ev, TlsBurstEvent):
            src_port = ev.src_port or 51443
            flow_key = (ev.src_ip, src_port, ev.dst_ip, ev.dst_port)
            if flow_key not in emitted_client_hellos:
                emitted_client_hellos.add(flow_key)
                sni = ev.sni or "api.openai.com"
                hello_ts = max(0.0, ev.timestamp - 0.12)
                emit_tcp(
                    hello_ts,
                    ev.src_ip,
                    ev.dst_ip,
                    src_port,
                    ev.dst_port,
                    _build_tls_client_hello(sni),
                )

            # Chunk uplink bytes across TLS AppData records (<= 1380 B per packet).
            remaining_up = max(1, ev.uplink_bytes)
            up_chunks: list[int] = []
            while remaining_up > 0:
                chunk = min(1380, remaining_up)
                up_chunks.append(chunk)
                remaining_up -= chunk

            up_span = max(0.001, ev.uplink_end_ts - ev.timestamp)
            for idx, chunk in enumerate(up_chunks):
                frac = idx / max(1, len(up_chunks) - 1) if len(up_chunks) > 1 else 0.0
                emit_tcp(
                    ev.timestamp + frac * up_span,
                    ev.src_ip,
                    ev.dst_ip,
                    src_port,
                    ev.dst_port,
                    _build_tls_app_record(chunk),
                )

            # Emit server downlink SSE/AppData records across decode window.
            rec_count = max(1, ev.downlink_record_count)
            base_rec = max(1, ev.downlink_bytes // rec_count)
            rem = max(0, ev.downlink_bytes - base_rec * rec_count)
            down_span = max(0.001, ev.downlink_end_ts - ev.downlink_start_ts)
            for idx in range(rec_count):
                rec_size = base_rec + (1 if idx < rem else 0)
                frac = idx / max(1, rec_count - 1) if rec_count > 1 else 0.0
                emit_tcp(
                    ev.downlink_start_ts + frac * down_span,
                    ev.dst_ip,
                    ev.src_ip,
                    ev.dst_port,
                    src_port,
                    _build_tls_app_record(rec_size),
                )

        elif isinstance(ev, ActionEvent):
            src_port = ev.src_port or next_ephemeral_port
            if not ev.src_port:
                next_ephemeral_port = 49152 + ((next_ephemeral_port - 49151) % 15000)
            dst_port = ev.dst_port or 80

            req_rem = max(1, ev.bytes_out)
            req_t = ev.timestamp
            while req_rem > 0:
                chunk = min(1400, req_rem)
                emit_tcp(req_t, ev.src_ip, ev.dst_ip, src_port, dst_port, b"Q" * chunk)
                req_rem -= chunk
                req_t += 0.0005

            resp_rem = max(1, ev.bytes_in)
            resp_chunks: list[int] = []
            while resp_rem > 0:
                chunk = min(1400, resp_rem)
                resp_chunks.append(chunk)
                resp_rem -= chunk
            resp_start = max(req_t + 0.001, ev.end_ts - 0.001 * max(1, len(resp_chunks) - 1))
            for idx, chunk in enumerate(resp_chunks):
                t_resp = ev.end_ts if idx == len(resp_chunks) - 1 else resp_start + idx * 0.001
                emit_tcp(t_resp, ev.dst_ip, ev.src_ip, dst_port, src_port, b"R" * chunk)

    raw_packets.sort(key=lambda item: item[0])

    with out_path.open("wb") as fh:
        # Global PCAP header (little-endian microsecond precision, Ethernet DLT=1)
        fh.write(struct.pack("<IHHiIII", PCAP_MAGIC_USEC_LE, 2, 4, 0, 0, 65535, DLT_EN10MB))
        for ts, frame in raw_packets:
            ts_sec = int(ts)
            ts_usec = int(round((ts - ts_sec) * 1_000_000))
            if ts_usec >= 1_000_000:
                ts_sec += 1
                ts_usec -= 1_000_000
            fh.write(struct.pack("<IIII", ts_sec, ts_usec, len(frame), len(frame)))
            fh.write(frame)

    return out_path
