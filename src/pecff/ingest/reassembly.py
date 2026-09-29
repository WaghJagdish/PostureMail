"""High-performance, safety-critical TCP stream reassembly and IP defragmentation engine.

BSD First-Received Overlap Resolution Policy:
---------------------------------------------
When overlapping TCP segments contain conflicting payload bytes for the same
sequence space, this engine follows BSD semantics (FIRST-RECEIVED wins).
The existing buffered bytes are preserved, and an `ANOMALY_TCP_OVERLAP` finding
is recorded with full byte-level evidence to audit potential IDS/IPS evasion attempts.

Sequence Arithmetic Rule:
-------------------------
TCP sequence numbers operate in modulo 2^32 space (RFC 793, RFC 1323).
All sequence comparisons MUST use `seq_lt`, `seq_lte`, `seq_gt`, `seq_gte`, and `seq_diff`.
RAW `<` OR `>` COMPARISONS ON SEQUENCE INTEGERS ARE FORBIDDEN.
"""

from __future__ import annotations

import heapq
import ipaddress
import socket
import struct
from collections import OrderedDict
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Final

from pecff.config import settings
from pecff.ingest.reader import RawPacket

# =============================================================================
# WARNING TO MAINTAINERS: NEVER USE < OR > ON TCP SEQUENCE NUMBERS!
# TCP Sequence numbers wrap modulo 2^32 (RFC 793, RFC 1323).
# Use seq_lt(), seq_lte(), seq_gt(), seq_gte(), and seq_diff() exclusively.
# =============================================================================


def seq_lt(a: int, b: int) -> bool:
    """Wraparound-safe sequence number strictly-less-than (a < b)."""
    return ((a - b) & 0xFFFFFFFF) > 0x7FFFFFFF


def seq_lte(a: int, b: int) -> bool:
    """Wraparound-safe sequence number less-than-or-equal (a <= b)."""
    return a == b or seq_lt(a, b)


def seq_gt(a: int, b: int) -> bool:
    """Wraparound-safe sequence number strictly-greater-than (a > b)."""
    return seq_lt(b, a)


def seq_gte(a: int, b: int) -> bool:
    """Wraparound-safe sequence number greater-than-or-equal (a >= b)."""
    return a == b or seq_gt(a, b)


def seq_diff(a: int, b: int) -> int:
    """Returns signed distance from b to a (a - b) in modulo 2^32 arithmetic."""
    d = (a - b) & 0xFFFFFFFF
    if d > 0x7FFFFFFF:
        return d - 0x100000000
    return d


# -----------------------------------------------------------------------------
# Data Models
# -----------------------------------------------------------------------------

# Canonical 4-tuple Flow Key: (min_endpoint, max_endpoint, vlan_id)
# where endpoint is (packed_ip_bytes, port)
FlowKey = tuple[tuple[bytes, int], tuple[bytes, int], int | None]


@dataclass(frozen=True, slots=True)
class ReassemblyFinding:
    """Auditable finding or anomaly detected during stream reassembly."""

    rule_id: str
    rule_name: str
    severity: str  # 'INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    description: str
    evidence: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ReassemblyQuality:
    """Quality metrics characterizing the reconstructed TCP stream."""

    retrans_count: int
    overlap_count: int
    gaps: list[tuple[int, int]]  # (offset_from_isn, length)
    complete: bool
    buffer_truncated: bool
    direction_inferred: bool


@dataclass(frozen=True, slots=True)
class ReassembledSession:
    """Forensic representation of a fully reassembled bidirectional TCP session."""

    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    vlan_id: int | None
    first_seen: float
    last_seen: float
    c2s_bytes: int
    s2c_bytes: int
    c2s_packets: int
    s2c_packets: int
    c2s_payload: bytes
    s2c_payload: bytes
    quality: ReassemblyQuality
    findings: list[ReassemblyFinding]


class HalfStream:
    """Tracks state and payload for one unidirectional half of a TCP stream.

    Uses __slots__ for maximum performance and minimum memory overhead.
    """

    __slots__ = (
        "isn",
        "first_data_seq",
        "next_seq",
        "buffer",
        "ooo_heap",
        "byte_count",
        "packet_count",
        "retrans_count",
        "overlap_count",
        "gaps",
        "fin_seen",
        "fin_seq",
        "rst_seen",
        "last_ts",
        "ooo_bytes",
        "hole_first_ts",
    )

    def __init__(self) -> None:
        self.isn: int | None = None
        self.first_data_seq: int | None = None
        self.next_seq: int = 0
        self.buffer: bytearray = bytearray()
        # ooo_heap stores tuples: (rel_offset, seq, payload, ts)
        # where rel_offset = seq_diff(seq, isn) for wraparound-safe heap ordering
        self.ooo_heap: list[tuple[int, int, bytes, float]] = []
        self.byte_count: int = 0
        self.packet_count: int = 0
        self.retrans_count: int = 0
        self.overlap_count: int = 0
        self.gaps: list[tuple[int, int]] = []
        self.fin_seen: bool = False
        self.fin_seq: int | None = None
        self.rst_seen: bool = False
        self.last_ts: float = 0.0
        self.ooo_bytes: int = 0
        self.hole_first_ts: float | None = None


class TCPSession:
    """Manages bidirectional TCP state for a single canonical flow."""

    def __init__(
        self,
        client_endpoint: tuple[bytes, int],
        server_endpoint: tuple[bytes, int],
        vlan_id: int | None,
        first_ts: float,
        direction_inferred: bool = False,
    ) -> None:
        self.client_endpoint: tuple[bytes, int] = client_endpoint
        self.server_endpoint: tuple[bytes, int] = server_endpoint
        self.vlan_id: int | None = vlan_id
        self.first_ts: float = first_ts
        self.last_ts: float = first_ts
        self.direction_inferred: bool = direction_inferred
        self.buffer_truncated: bool = False
        self.findings: list[ReassemblyFinding] = []

        self.c2s: HalfStream = HalfStream()
        self.s2c: HalfStream = HalfStream()

    @property
    def total_buffered_bytes(self) -> int:
        """Combined buffer size across both directions."""
        return len(self.c2s.buffer) + len(self.s2c.buffer)


# -----------------------------------------------------------------------------
# IP Defragmenter
# -----------------------------------------------------------------------------

# Key for IPv4 / IPv6 fragment reassembly: (src_ip, dst_ip, ip_id, protocol)
IpFragKey = tuple[bytes, bytes, int, int]


@dataclass(slots=True)
class IpFragmentEntry:
    """Holds fragments for a single in-flight fragmented IP datagram."""

    first_ts: float
    last_ts: float
    total_len: int | None  # Set when the last fragment (MF=0) arrives
    fragments: dict[int, bytes]  # offset -> payload
    ip_hdr: bytes


class IpDefragmenter:
    """Bounded, capture-clock-aware IP defragmenter for IPv4 and IPv6."""

    def __init__(self) -> None:
        self._table: OrderedDict[IpFragKey, IpFragmentEntry] = OrderedDict()
        self.max_entries: int = settings.max_fragment_entries
        self.timeout: float = settings.fragment_timeout_seconds

    def prune(self, current_ts: float) -> None:
        """Prune expired fragments based on capture clock."""
        expired_keys: list[IpFragKey] = []
        for key, entry in self._table.items():
            if current_ts - entry.first_ts > self.timeout:
                expired_keys.append(key)
            else:
                break
        for k in expired_keys:
            del self._table[k]

    def process_ipv4(
        self,
        ip_payload: memoryview,
        ts: float,
    ) -> memoryview | None:
        """Process IPv4 packet and return complete reassembled L3 datagram if defragmented."""
        if len(ip_payload) < 20:
            return None

        ihl = (ip_payload[0] & 0x0F) * 4
        if len(ip_payload) < ihl:
            return None

        flags_offset = struct.unpack_from(">H", ip_payload, 6)[0]
        mf = bool(flags_offset & 0x2000)
        frag_offset = (flags_offset & 0x1FFF) * 8

        # Fast path: not fragmented
        if not mf and frag_offset == 0:
            return ip_payload

        # Extract fragment key
        src_ip = bytes(ip_payload[12:16])
        dst_ip = bytes(ip_payload[16:20])
        ip_id = struct.unpack_from(">H", ip_payload, 4)[0]
        proto = ip_payload[9]
        frag_key: IpFragKey = (src_ip, dst_ip, ip_id, proto)

        self.prune(ts)

        if frag_key not in self._table:
            if len(self._table) >= self.max_entries:
                self._table.popitem(last=False)
            self._table[frag_key] = IpFragmentEntry(
                first_ts=ts,
                last_ts=ts,
                total_len=None,
                fragments={},
                ip_hdr=bytes(ip_payload[:ihl]),
            )

        entry = self._table[frag_key]
        entry.last_ts = ts
        frag_data = bytes(ip_payload[ihl:])
        entry.fragments[frag_offset] = frag_data

        if not mf:
            entry.total_len = frag_offset + len(frag_data)

        # Check if complete
        if entry.total_len is not None:
            # Check contiguous coverage
            assembled = bytearray()
            curr_offset = 0
            sorted_offsets = sorted(entry.fragments.keys())
            complete = True

            for off in sorted_offsets:
                if off != curr_offset:
                    complete = False
                    break
                part = entry.fragments[off]
                assembled.extend(part)
                curr_offset += len(part)

            if complete and curr_offset == entry.total_len:
                del self._table[frag_key]
                # Reconstruct full IPv4 packet with updated total length and cleared fragment flags
                full_ip = bytearray(entry.ip_hdr)
                full_len = len(full_ip) + len(assembled)
                struct.pack_into(">H", full_ip, 2, full_len)
                struct.pack_into(">H", full_ip, 6, 0)  # Clear MF and offset flags
                full_ip.extend(assembled)
                return memoryview(bytes(full_ip))

        return None


# -----------------------------------------------------------------------------
# TCP Stream Reassembler
# -----------------------------------------------------------------------------


class StreamReassembler:
    """Correctness-focused, passive TCP stream reassembly engine.

    Features:
    - Wraparound-safe 32-bit sequence arithmetic (RFC 793, RFC 1323).
    - BSD first-received overlap policy with ANOMALY_TCP_OVERLAP IDS evasion detection.
    - Capture-clock-driven SessionReaper with gap and idle timeouts.
    - Hard bounded memory limits (max flows LRU, per-session buffer cap, OOO heap cap).
    - Seamless IPv4/IPv6 IP defragmentation integration.
    """

    def __init__(
        self,
        on_session_finalized: Callable[[ReassembledSession], None] | None = None,
        candidate_ports: set[int] | None = None,
        handshake_only: bool = False,
    ) -> None:
        """Initialize reassembler with optional session finalized callback and fast path options."""
        self._on_session_finalized: Callable[[ReassembledSession], None] | None = (
            on_session_finalized
        )
        self.candidate_ports: set[int] | None = candidate_ports
        self.handshake_only: bool = handshake_only
        self._flows: OrderedDict[FlowKey, TCPSession] = OrderedDict()
        self._collected_sessions: list[ReassembledSession] = []
        self._defragmenter: IpDefragmenter = IpDefragmenter()

        self._packet_counter: int = 0
        self._last_reaper_sec: int = 0
        self._current_ts: float = 0.0

        # Forensic audit counters
        self.evicted_flows: int = 0
        self.total_sessions_finalized: int = 0

        # Well-known server ports for directional inference
        self._well_known_server_ports: Final[set[int]] = {
            25,
            110,
            143,
            465,
            587,
            993,
            995,
            2525,
        }

    def process_packet(self, raw_pkt: RawPacket) -> None:
        """Ingest a normalized RawPacket (L3 payload) into the reassembly engine."""
        self._packet_counter += 1
        self._current_ts = raw_pkt.ts

        payload = raw_pkt.payload
        if len(payload) < 20:
            return

        ip_version = payload[0] >> 4
        ip_payload: memoryview | None = None
        l4_protocol: int = 0
        src_ip: bytes
        dst_ip: bytes

        if ip_version == 4:
            ip_payload = self._defragmenter.process_ipv4(payload, raw_pkt.ts)
            if ip_payload is None:
                return  # Fragment buffered / pending
            ihl = (ip_payload[0] & 0x0F) * 4
            l4_protocol = ip_payload[9]
            src_ip = bytes(ip_payload[12:16])
            dst_ip = bytes(ip_payload[16:20])
            l4_data = ip_payload[ihl:]

        elif ip_version == 6:
            if len(payload) < 40:
                return
            l4_protocol = payload[6]
            src_ip = bytes(payload[8:24])
            dst_ip = bytes(payload[24:40])
            l4_data = payload[40:]
            # If IPv6 fragment header (NextHeader == 44)
            if l4_protocol == 44 and len(l4_data) >= 8:
                # Handle IPv6 fragment
                l4_protocol = l4_data[0]
                frag_offset = struct.unpack_from(">H", l4_data, 2)[0] & 0xFFF8
                mf = bool(l4_data[3] & 0x01)
                if frag_offset != 0 or mf:
                    # Skip incomplete non-first IPv6 fragments for simplicity
                    return
                l4_data = l4_data[8:]

        else:
            return  # Non-IP packet

        # Only process TCP (protocol 6)
        if l4_protocol != 6 or len(l4_data) < 20:
            return

        self._process_tcp_segment(src_ip, dst_ip, l4_data, raw_pkt.ts, raw_pkt.vlan_id)

        # Periodic capture-clock reaper invocation
        current_sec = int(raw_pkt.ts)
        if (
            self._packet_counter % settings.reaper_packet_interval == 0
            or current_sec > self._last_reaper_sec
        ):
            self._last_reaper_sec = current_sec
            self._run_reaper(raw_pkt.ts)

    def _process_tcp_segment(
        self,
        src_ip: bytes,
        dst_ip: bytes,
        tcp_data: memoryview,
        ts: float,
        vlan_id: int | None,
    ) -> None:
        """Parse TCP segment header and route to appropriate HalfStream."""
        src_port, dst_port, seq, _ack, offset_flags = struct.unpack_from(">HHIIH", tcp_data, 0)
        # Fast path early candidate port filtering
        if self.candidate_ports is not None and src_port not in self.candidate_ports and dst_port not in self.candidate_ports:
            return

        data_offset = ((offset_flags >> 12) & 0x0F) * 4
        if len(tcp_data) < data_offset:
            return

        flags = offset_flags & 0x01FF
        fin = bool(flags & 0x01)
        syn = bool(flags & 0x02)
        rst = bool(flags & 0x04)
        _ack_flag = bool(flags & 0x10)

        tcp_payload = bytes(tcp_data[data_offset:])

        # Build canonical 4-tuple key
        ep_a = (src_ip, src_port)
        ep_b = (dst_ip, dst_port)
        flow_key: FlowKey = (min(ep_a, ep_b), max(ep_a, ep_b), vlan_id)

        session = self._flows.get(flow_key)

        if session is None:
            # Enforce flow table capacity (LRU eviction)
            if len(self._flows) >= settings.max_flows:
                _oldest_key, oldest_session = self._flows.popitem(last=False)
                self.evicted_flows += 1
                self._finalize_session(oldest_session)

            # Determine direction: SYN or well-known port heuristic
            direction_inferred = False
            if syn:
                client_ep = ep_a
                server_ep = ep_b
            else:
                # Mid-stream capture without SYN
                direction_inferred = True
                if (
                    dst_port in self._well_known_server_ports
                    and src_port not in self._well_known_server_ports
                ):
                    client_ep = ep_a
                    server_ep = ep_b
                elif (
                    src_port in self._well_known_server_ports
                    and dst_port not in self._well_known_server_ports
                ):
                    client_ep = ep_b
                    server_ep = ep_a
                elif dst_port < src_port:
                    client_ep = ep_a
                    server_ep = ep_b
                else:
                    client_ep = ep_b
                    server_ep = ep_a

            session = TCPSession(
                client_endpoint=client_ep,
                server_endpoint=server_ep,
                vlan_id=vlan_id,
                first_ts=ts,
                direction_inferred=direction_inferred,
            )
            self._flows[flow_key] = session
        else:
            # Move to end of OrderedDict for LRU tracking
            self._flows.move_to_end(flow_key)

        session.last_ts = ts

        # Determine if this segment is C2S or S2C
        is_c2s = ep_a == session.client_endpoint
        half = session.c2s if is_c2s else session.s2c

        # Execute segment ingest algorithm
        self._ingest_segment(session, half, seq, tcp_payload, syn, fin, rst, ts)

        # Immediate teardown check on RST or both FINs
        if half.rst_seen or (session.c2s.fin_seen and session.s2c.fin_seen):
            del self._flows[flow_key]
            self._finalize_session(session)

    def _ingest_segment(
        self,
        session: TCPSession,
        half: HalfStream,
        seq: int,
        payload: bytes,
        syn: bool,
        fin: bool,
        rst: bool,
        ts: float,
    ) -> None:
        """Execute the exact 6-step TCP segment ingest algorithm."""
        half.last_ts = ts
        half.packet_count += 1
        half.byte_count += len(payload)

        # Handle control flags
        if rst:
            half.rst_seen = True
        if fin:
            half.fin_seen = True
            half.fin_seq = (seq + len(payload)) & 0xFFFFFFFF

        # ---------------------------------------------------------------------
        # STEP 1: ISN capture
        # ---------------------------------------------------------------------
        if half.isn is None:
            half.isn = seq
            half.next_seq = (seq + (1 if syn else 0)) & 0xFFFFFFFF
            half.first_data_seq = half.next_seq

        if half.first_data_seq is None:
            half.first_data_seq = (seq + (1 if syn else 0)) & 0xFFFFFFFF

        # Adjust segment start sequence if SYN was set
        seg_seq = (seq + 1) & 0xFFFFFFFF if syn else seq
        payload_len = len(payload)

        if payload_len == 0:
            return

        seg_end = (seg_seq + payload_len) & 0xFFFFFFFF

        # ---------------------------------------------------------------------
        # STEP 2: Pure Retransmission
        # ---------------------------------------------------------------------
        if seq_lte(seg_end, half.next_seq):
            half.retrans_count += 1
            return

        # ---------------------------------------------------------------------
        # STEP 3: Partial Overlap
        # ---------------------------------------------------------------------
        if seq_lt(seg_seq, half.next_seq) and seq_gt(seg_end, half.next_seq):
            half.overlap_count += 1
            lead_trim = seq_diff(half.next_seq, seg_seq)

            # Audit overlap consistency (BSD first-received semantics)
            seg_overlap = payload[:lead_trim]
            # Calculate where seg_seq falls in the reassembled buffer
            if half.first_data_seq is not None:
                buf_offset = seq_diff(seg_seq, half.first_data_seq)
                if buf_offset >= 0 and buf_offset + lead_trim <= len(half.buffer):
                    existing_overlap = bytes(half.buffer[buf_offset : buf_offset + lead_trim])
                    if existing_overlap != seg_overlap:
                        session.findings.append(
                            ReassemblyFinding(
                                rule_id="ANOMALY_TCP_OVERLAP",
                                rule_name="Inconsistent TCP Segment Overlap",
                                severity="HIGH",
                                description=(
                                    "Detected overlapping TCP segment with conflicting bytes "
                                    "(classic IDS/IPS evasion pattern). First-received bytes preserved."
                                ),
                                evidence={
                                    "seq": seg_seq,
                                    "overlap_length": lead_trim,
                                    "existing_bytes": existing_overlap[:64].hex(),
                                    "incoming_bytes": seg_overlap[:64].hex(),
                                },
                            )
                        )

            # Trim leading bytes and advance seg_seq to next_seq
            payload = payload[lead_trim:]
            seg_seq = half.next_seq
            payload_len = len(payload)

        # ---------------------------------------------------------------------
        # STEP 4: In-Order Segment -> Append and Drain OOO Heap
        # ---------------------------------------------------------------------
        if seg_seq == half.next_seq:
            self._append_to_buffer(session, half, payload)
            half.next_seq = (half.next_seq + payload_len) & 0xFFFFFFFF
            half.hole_first_ts = None

            # Drain OOO heap of newly contiguous segments
            self._drain_ooo_heap(session, half, ts)
            return

        # ---------------------------------------------------------------------
        # STEP 5: Out-Of-Order Segment -> Push onto OOO Heap
        # ---------------------------------------------------------------------
        if seq_gt(seg_seq, half.next_seq) and half.isn is not None:
            rel_offset = seq_diff(seg_seq, half.isn)
            heapq.heappush(half.ooo_heap, (rel_offset, seg_seq, payload, ts))
            half.ooo_bytes += len(payload)
            if half.hole_first_ts is None:
                half.hole_first_ts = ts

        # ---------------------------------------------------------------------
        # STEP 6: OOO Cap Enforcement -> Force Gap
        # ---------------------------------------------------------------------
        if half.ooo_bytes > settings.ooo_cap_bytes:
            self._force_gap(session, half, ts)

    def _append_to_buffer(self, session: TCPSession, half: HalfStream, payload: bytes) -> None:
        """Append payload to half stream buffer respecting session buffer cap."""
        if self.handshake_only and len(half.buffer) >= 65536:
            return

        if session.total_buffered_bytes + len(payload) <= settings.max_session_buffer_bytes:
            half.buffer.extend(payload)
        else:
            session.buffer_truncated = True
            remaining_cap = settings.max_session_buffer_bytes - session.total_buffered_bytes
            if remaining_cap > 0:
                half.buffer.extend(payload[:remaining_cap])

    def _drain_ooo_heap(self, session: TCPSession, half: HalfStream, ts: float) -> None:
        """Drain contiguous or overlapping segments from OOO heap."""
        while half.ooo_heap:
            _rel_off, top_seq, top_payload, top_ts = half.ooo_heap[0]
            top_len = len(top_payload)
            top_end = (top_seq + top_len) & 0xFFFFFFFF

            # Case A: Entirely redundant retransmission
            if seq_lte(top_end, half.next_seq):
                heapq.heappop(half.ooo_heap)
                half.ooo_bytes -= top_len
                half.retrans_count += 1
                continue

            # Case B: Partially overlapping
            if seq_lt(top_seq, half.next_seq):
                heapq.heappop(half.ooo_heap)
                half.ooo_bytes -= top_len
                half.overlap_count += 1
                lead_trim = seq_diff(half.next_seq, top_seq)

                # Check overlap consistency
                seg_overlap = top_payload[:lead_trim]
                if half.first_data_seq is not None:
                    buf_offset = seq_diff(top_seq, half.first_data_seq)
                    if buf_offset >= 0 and buf_offset + lead_trim <= len(half.buffer):
                        existing_overlap = bytes(half.buffer[buf_offset : buf_offset + lead_trim])
                        if existing_overlap != seg_overlap:
                            session.findings.append(
                                ReassemblyFinding(
                                    rule_id="ANOMALY_TCP_OVERLAP",
                                    rule_name="Inconsistent TCP Segment Overlap (OOO Drain)",
                                    severity="HIGH",
                                    description=(
                                        "Detected overlapping TCP segment in out-of-order queue "
                                        "with conflicting bytes. First-received bytes preserved."
                                    ),
                                    evidence={
                                        "seq": top_seq,
                                        "overlap_length": lead_trim,
                                        "existing_bytes": existing_overlap[:64].hex(),
                                        "incoming_bytes": seg_overlap[:64].hex(),
                                    },
                                )
                            )

                trimmed_payload = top_payload[lead_trim:]
                self._append_to_buffer(session, half, trimmed_payload)
                half.next_seq = (half.next_seq + len(trimmed_payload)) & 0xFFFFFFFF
                continue

            # Case C: Exactly contiguous
            if top_seq == half.next_seq:
                heapq.heappop(half.ooo_heap)
                half.ooo_bytes -= top_len
                self._append_to_buffer(session, half, top_payload)
                half.next_seq = (half.next_seq + top_len) & 0xFFFFFFFF
                continue

            # Case D: Gap still present
            half.hole_first_ts = top_ts
            break

    def _force_gap(self, session: TCPSession, half: HalfStream, ts: float) -> None:
        """Force a gap at the missing sequence hole to unblock stream processing."""
        if not half.ooo_heap or half.isn is None:
            return

        _rel_off, top_seq, _top_payload, _top_ts = half.ooo_heap[0]
        hole_len = seq_diff(top_seq, half.next_seq)
        gap_offset = seq_diff(half.next_seq, half.isn)

        half.gaps.append((gap_offset, hole_len))
        session.findings.append(
            ReassemblyFinding(
                rule_id="REASSEMBLY_FORCED_GAP",
                rule_name="Forced TCP Reassembly Gap",
                severity="MEDIUM",
                description=(
                    f"Missing TCP sequence hole of {hole_len} bytes at offset {gap_offset} "
                    "was forced due to buffer limits or gap timeout."
                ),
                evidence={
                    "gap_offset": gap_offset,
                    "hole_length": hole_len,
                    "expected_seq": half.next_seq,
                    "resumed_seq": top_seq,
                },
            )
        )

        # Advance next_seq to top_seq and drain heap
        half.next_seq = top_seq
        half.hole_first_ts = None
        self._drain_ooo_heap(session, half, ts)

    def _run_reaper(self, current_ts: float) -> None:
        """Run capture-clock-driven reaper to handle gap timeouts and idle stream prunes."""
        finalized_keys: list[FlowKey] = []

        for flow_key, session in list(self._flows.items()):
            # 1. Check gap timeouts (30 capture seconds)
            for half in (session.c2s, session.s2c):
                if (
                    half.hole_first_ts is not None
                    and current_ts - half.hole_first_ts >= settings.gap_timeout_seconds
                ):
                    self._force_gap(session, half, current_ts)

            # 2. Check idle stream timeout (300 capture seconds)
            if current_ts - session.last_ts >= settings.stream_idle_timeout_seconds:
                finalized_keys.append(flow_key)

        for k in finalized_keys:
            sess = self._flows.pop(k, None)
            if sess is not None:
                self._finalize_session(sess)

    def _finalize_session(self, session: TCPSession) -> None:
        """Compile ReassembledSession and invoke callback."""
        self.total_sessions_finalized += 1

        # Format IP addresses
        client_ip_str = self._format_ip(session.client_endpoint[0])
        server_ip_str = self._format_ip(session.server_endpoint[0])

        # Quality calculation
        all_gaps = session.c2s.gaps + session.s2c.gaps
        complete = (
            len(all_gaps) == 0
            and not session.buffer_truncated
            and (session.c2s.fin_seen or session.s2c.fin_seen)
        )

        quality = ReassemblyQuality(
            retrans_count=session.c2s.retrans_count + session.s2c.retrans_count,
            overlap_count=session.c2s.overlap_count + session.s2c.overlap_count,
            gaps=all_gaps,
            complete=complete,
            buffer_truncated=session.buffer_truncated,
            direction_inferred=session.direction_inferred,
        )

        reassembled = ReassembledSession(
            client_ip=client_ip_str,
            client_port=session.client_endpoint[1],
            server_ip=server_ip_str,
            server_port=session.server_endpoint[1],
            vlan_id=session.vlan_id,
            first_seen=session.first_ts,
            last_seen=session.last_ts,
            c2s_bytes=session.c2s.byte_count,
            s2c_bytes=session.s2c.byte_count,
            c2s_packets=session.c2s.packet_count,
            s2c_packets=session.s2c.packet_count,
            c2s_payload=bytes(session.c2s.buffer),
            s2c_payload=bytes(session.s2c.buffer),
            quality=quality,
            findings=list(session.findings),
        )

        self._collected_sessions.append(reassembled)

        if self._on_session_finalized is not None:
            self._on_session_finalized(reassembled)

    def flush_all(self) -> list[ReassembledSession]:
        """Flush and finalize all remaining active TCP streams at end of capture."""
        # Finalize all remaining flows
        while self._flows:
            _k, sess = self._flows.popitem(last=False)
            self._finalize_session(sess)

        return list(self._collected_sessions)

    def finalize_all(self) -> list[ReassembledSession]:
        """Alias for flush_all()."""
        return self.flush_all()

    @staticmethod
    def _format_ip(packed_ip: bytes) -> str:
        """Convert 4-byte or 16-byte packed IP to string."""
        if len(packed_ip) == 4:
            return socket.inet_ntoa(packed_ip)
        elif len(packed_ip) == 16:
            return str(ipaddress.IPv6Address(packed_ip))
        return "0.0.0.0"


def reassemble_pcap(
    packets: Iterator[RawPacket],
) -> Iterator[ReassembledSession]:
    """Helper generator yielding ReassembledSession objects from an input packet iterator."""
    finalized_queue: list[ReassembledSession] = []

    def session_callback(sess: ReassembledSession) -> None:
        finalized_queue.append(sess)

    engine = StreamReassembler(on_session_finalized=session_callback)

    for pkt in packets:
        engine.process_packet(pkt)
        while finalized_queue:
            yield finalized_queue.pop(0)

    # Flush any remaining sessions at EOF
    engine.flush_all()
    while finalized_queue:
        yield finalized_queue.pop(0)
