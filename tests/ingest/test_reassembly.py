"""Comprehensive test suite for TCP stream reassembly and IP defragmentation.

Includes Hypothesis property-based testing (500 examples), sequence wraparound tests,
overlap IDS evasion detection tests, bounded OOO buffer gap enforcement tests,
mid-stream inference tests, and IP defragmentation tests.
"""

from __future__ import annotations

import random

from hypothesis import given
from hypothesis import settings as hyp_settings
from hypothesis import strategies as st
from scapy.layers.inet import IP, TCP

from pecff.config import settings
from pecff.ingest.reader import RawPacket
from pecff.ingest.reassembly import (
    ReassembledSession,
    StreamReassembler,
    seq_diff,
    seq_gt,
    seq_gte,
    seq_lt,
    seq_lte,
)


def make_raw_tcp_packet(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    seq: int,
    ack: int,
    flags: str,
    payload: bytes,
    ts: float = 1700000000.0,
    vlan_id: int | None = None,
) -> RawPacket:
    """Helper to generate a RawPacket containing an IPv4 TCP packet."""
    pkt = (
        IP(src=src_ip, dst=dst_ip)
        / TCP(sport=src_port, dport=dst_port, seq=seq, ack=ack, flags=flags)
        / payload
    )
    raw_ip = bytes(pkt)
    return RawPacket(
        index=0,
        ts=ts,
        caplen=len(raw_ip),
        wirelen=len(raw_ip),
        vlan_id=vlan_id,
        payload=memoryview(raw_ip),
    )


class TestSequenceArithmetic:
    """Test wraparound-safe sequence arithmetic."""

    def test_seq_lt(self) -> None:
        assert seq_lt(10, 20) is True
        assert seq_lt(20, 10) is False
        assert seq_lt(10, 10) is False

        # Wraparound across 0xFFFFFFFF
        assert seq_lt(0xFFFFFFF0, 0x00000010) is True
        assert seq_lt(0x00000010, 0xFFFFFFF0) is False

    def test_seq_lte(self) -> None:
        assert seq_lte(10, 10) is True
        assert seq_lte(10, 20) is True
        assert seq_lte(20, 10) is False
        assert seq_lte(0xFFFFFFF0, 0x00000010) is True

    def test_seq_gt_and_gte(self) -> None:
        assert seq_gt(20, 10) is True
        assert seq_gt(10, 20) is False
        assert seq_gte(10, 10) is True
        assert seq_gt(0x00000010, 0xFFFFFFF0) is True

    def test_seq_diff(self) -> None:
        assert seq_diff(20, 10) == 10
        assert seq_diff(10, 20) == -10
        assert seq_diff(0x00000010, 0xFFFFFFF0) == 32
        assert seq_diff(0xFFFFFFF0, 0x00000010) == -32


class TestHypothesisReassembly:
    """Property-based testing: random permutations and retransmissions must reconstruct original payload."""

    @given(
        payload=st.binary(min_size=1, max_size=16384),
        random_seed=st.integers(min_value=0, max_value=2**31 - 1),
    )
    @hyp_settings(max_examples=500, deadline=None)
    def test_random_segment_permutation_and_duplicates(
        self, payload: bytes, random_seed: int
    ) -> None:
        rng = random.Random(random_seed)
        total_len = len(payload)

        # Slice payload into random segments (sizes 1 to 500 bytes)
        segments: list[tuple[int, bytes]] = []
        curr = 0
        isn = rng.randint(0, 0xFFFFFFFF)

        while curr < total_len:
            seg_size = rng.randint(1, min(500, total_len - curr))
            seg_data = payload[curr : curr + seg_size]
            seg_seq = (isn + 1 + curr) & 0xFFFFFFFF
            segments.append((seg_seq, seg_data))
            curr += seg_size

        # Insert 10% to 30% random retransmissions / duplicate packets
        dup_count = rng.randint(0, max(1, len(segments) // 3))
        for _ in range(dup_count):
            dup_seg = rng.choice(segments)
            segments.append(dup_seg)

        # Randomly shuffle all segments (simulating out-of-order arrival)
        rng.shuffle(segments)

        # Build packet list: 1 SYN + all segments + 1 FIN
        packets: list[RawPacket] = []
        ts = 1700000000.0

        # SYN packet
        packets.append(
            make_raw_tcp_packet(
                "192.168.1.10",
                "192.168.1.20",
                12345,
                25,
                isn,
                0,
                "S",
                b"",
                ts=ts,
            )
        )

        for seq, data in segments:
            ts += 0.001
            packets.append(
                make_raw_tcp_packet(
                    "192.168.1.10",
                    "192.168.1.20",
                    12345,
                    25,
                    seq,
                    0,
                    "A",
                    data,
                    ts=ts,
                )
            )

        # FIN packet
        fin_seq = (isn + 1 + total_len) & 0xFFFFFFFF
        packets.append(
            make_raw_tcp_packet(
                "192.168.1.10",
                "192.168.1.20",
                12345,
                25,
                fin_seq,
                0,
                "FA",
                b"",
                ts=ts + 0.1,
            )
        )

        # Reassemble
        finalized: list[ReassembledSession] = []
        engine = StreamReassembler(on_session_finalized=finalized.append)
        for p in packets:
            engine.process_packet(p)

        engine.flush_all()

        assert len(finalized) == 1
        sess = finalized[0]
        assert sess.c2s_payload == payload, (
            f"Payload mismatch! Expected {len(payload)}B, got {len(sess.c2s_payload)}B"
        )


class TestReassemblyCornerCases:
    """Test sequence wraparound, overlap attacks, OOO caps, mid-stream inference, and IP defragmentation."""

    def test_sequence_wraparound_reconstruction(self) -> None:
        """Stream starting at 0xFFFFFFF0 wrapping around 0."""
        isn = 0xFFFFFFF0
        p1_data = b"HELLO "
        p2_data = b"WORLD 12345"

        p1_seq = (isn + 1) & 0xFFFFFFFF  # 0xFFFFFFF1
        p2_seq = (p1_seq + len(p1_data)) & 0xFFFFFFFF  # 0xFFFFFFF7

        finalized: list[ReassembledSession] = []
        engine = StreamReassembler(on_session_finalized=finalized.append)

        # Send SYN
        engine.process_packet(
            make_raw_tcp_packet("10.0.0.1", "10.0.0.2", 5000, 25, isn, 0, "S", b"")
        )
        # Send P2 (out of order)
        engine.process_packet(
            make_raw_tcp_packet("10.0.0.1", "10.0.0.2", 5000, 25, p2_seq, 0, "A", p2_data)
        )
        # Send P1 (fills hole and wraps past 0)
        engine.process_packet(
            make_raw_tcp_packet("10.0.0.1", "10.0.0.2", 5000, 25, p1_seq, 0, "A", p1_data)
        )

        engine.flush_all()
        assert len(finalized) == 1
        assert finalized[0].c2s_payload == b"HELLO WORLD 12345"

    def test_overlap_attack_bsd_policy_and_anomaly_finding(self) -> None:
        """Conflicting overlapping bytes trigger ANOMALY_TCP_OVERLAP with BSD first-received policy."""
        isn = 1000
        p1 = b"AAAA"
        p2_conflicting = b"XXBB"  # Overlaps last 2 bytes of p1 ('AA') with 'XX', then 'BB'

        finalized: list[ReassembledSession] = []
        engine = StreamReassembler(on_session_finalized=finalized.append)

        # SYN
        engine.process_packet(
            make_raw_tcp_packet("10.0.0.1", "10.0.0.2", 5000, 25, isn, 0, "S", b"")
        )
        # P1: seq 1001, payload 'AAAA' (seq 1001-1004)
        engine.process_packet(
            make_raw_tcp_packet("10.0.0.1", "10.0.0.2", 5000, 25, 1001, 0, "A", p1)
        )
        # P2: seq 1003, payload 'XXBB' (seq 1003-1006)
        engine.process_packet(
            make_raw_tcp_packet("10.0.0.1", "10.0.0.2", 5000, 25, 1003, 0, "A", p2_conflicting)
        )

        engine.flush_all()
        assert len(finalized) == 1
        sess = finalized[0]

        # BSD first-received: 'AAAA' + 'BB' = 'AAAABB' ('XX' dropped)
        assert sess.c2s_payload == b"AAAABB"

        # Verify ANOMALY_TCP_OVERLAP finding
        overlap_findings = [f for f in sess.findings if f.rule_id == "ANOMALY_TCP_OVERLAP"]
        assert len(overlap_findings) >= 1
        assert "Inconsistent TCP" in overlap_findings[0].rule_name
        assert overlap_findings[0].evidence["existing_bytes"] == "4141"
        assert overlap_findings[0].evidence["incoming_bytes"] == "5858"

    def test_ooo_cap_forced_gap(self) -> None:
        """Exceeding settings.ooo_cap_bytes forces a gap and advances stream."""
        isn = 1000
        hole_len = 100
        # Missing chunk from 1001 to 1100
        # Send 2.5 MB of OOO data starting at seq 1101
        chunk_size = 50000
        total_ooo = int(settings.ooo_cap_bytes * 1.2)  # 2.4 MB

        finalized: list[ReassembledSession] = []
        engine = StreamReassembler(on_session_finalized=finalized.append)

        # SYN
        engine.process_packet(
            make_raw_tcp_packet("10.0.0.1", "10.0.0.2", 5000, 25, isn, 0, "S", b"")
        )

        curr_seq = 1001 + hole_len
        sent_bytes = 0
        while sent_bytes < total_ooo:
            data = b"X" * chunk_size
            engine.process_packet(
                make_raw_tcp_packet("10.0.0.1", "10.0.0.2", 5000, 25, curr_seq, 0, "A", data)
            )
            curr_seq += chunk_size
            sent_bytes += chunk_size

        engine.flush_all()
        assert len(finalized) == 1
        sess = finalized[0]

        # Gaps recorded
        assert len(sess.quality.gaps) >= 1
        assert sess.quality.complete is False

        # REASSEMBLY_FORCED_GAP finding present
        gap_findings = [f for f in sess.findings if f.rule_id == "REASSEMBLY_FORCED_GAP"]
        assert len(gap_findings) >= 1

    def test_mid_stream_capture_direction_inference(self) -> None:
        """Mid-stream packet without SYN infers direction by well-known server port."""
        finalized: list[ReassembledSession] = []
        engine = StreamReassembler(on_session_finalized=finalized.append)

        # Client (port 54321) sends to SMTP server (port 25) without prior SYN
        engine.process_packet(
            make_raw_tcp_packet(
                "192.168.1.50",
                "192.168.1.1",
                54321,
                25,
                50000,
                0,
                "PA",
                b"EHLO client.example.com\r\n",
            )
        )
        # Server replies
        engine.process_packet(
            make_raw_tcp_packet(
                "192.168.1.1",
                "192.168.1.50",
                25,
                54321,
                80000,
                50025,
                "PA",
                b"250-mail.example.com\r\n250 STARTTLS\r\n",
            )
        )

        engine.flush_all()
        assert len(finalized) == 1
        sess = finalized[0]
        assert sess.quality.direction_inferred is True
        assert sess.client_port == 54321
        assert sess.server_port == 25
        assert sess.c2s_payload == b"EHLO client.example.com\r\n"
        assert b"250 STARTTLS" in sess.s2c_payload

    def test_ipv4_defragmentation(self) -> None:
        """Fragmented IPv4 datagram is properly assembled before TCP reassembly."""
        # Create a TCP packet with payload
        tcp_pkt = TCP(sport=10000, dport=25, seq=500, ack=0, flags="PA") / b"DEFRAG_TEST_PAYLOAD"
        tcp_bytes = bytes(tcp_pkt)

        # Split TCP bytes into two IP fragments
        frag1_data = tcp_bytes[:24]  # TCP header + 4 bytes
        frag2_data = tcp_bytes[24:]  # Rest of payload

        # Fragment 1: MF=1, offset=0, proto=6 (TCP)
        ip1 = IP(src="1.1.1.1", dst="2.2.2.2", id=1234, proto=6, flags="MF", frag=0) / frag1_data
        # Fragment 2: MF=0, offset=3 (3 * 8 = 24 bytes), proto=6 (TCP)
        ip2 = IP(src="1.1.1.1", dst="2.2.2.2", id=1234, proto=6, flags=0, frag=3) / frag2_data

        finalized: list[ReassembledSession] = []
        engine = StreamReassembler(on_session_finalized=finalized.append)

        # Process frag 1
        engine.process_packet(
            RawPacket(
                index=0,
                ts=1700000000.0,
                caplen=len(ip1),
                wirelen=len(ip1),
                vlan_id=None,
                payload=memoryview(bytes(ip1)),
            )
        )
        # Process frag 2 (completes datagram)
        engine.process_packet(
            RawPacket(
                index=1,
                ts=1700000000.1,
                caplen=len(ip2),
                wirelen=len(ip2),
                vlan_id=None,
                payload=memoryview(bytes(ip2)),
            )
        )

        engine.flush_all()
        assert len(finalized) == 1
        assert finalized[0].c2s_payload == b"DEFRAG_TEST_PAYLOAD"


class TestReassemblyLifecyclesAndLimits:
    """Test capture-clock reaper, flow table LRU eviction, session buffer caps, and generator helper."""

    def test_reaper_gap_timeout(self) -> None:
        """A sequence hole older than settings.gap_timeout_seconds is forced by capture-clock reaper."""
        finalized: list[ReassembledSession] = []
        engine = StreamReassembler(on_session_finalized=finalized.append)

        # SYN at ts = 100.0
        engine.process_packet(
            make_raw_tcp_packet("10.0.0.1", "10.0.0.2", 1000, 25, 100, 0, "S", b"", ts=100.0)
        )
        # OOO segment (seq 200, missing 101-199) at ts = 101.0
        engine.process_packet(
            make_raw_tcp_packet(
                "10.0.0.1", "10.0.0.2", 1000, 25, 200, 0, "A", b"AFTER_GAP", ts=101.0
            )
        )
        # Fast-forward capture clock to ts = 135.0 (34 seconds later > 30s gap timeout)
        engine.process_packet(
            make_raw_tcp_packet("10.0.0.3", "10.0.0.4", 2000, 25, 500, 0, "S", b"", ts=135.0)
        )

        engine.flush_all()
        sess = [s for s in finalized if s.client_port == 1000][0]
        assert len(sess.quality.gaps) == 1
        assert sess.c2s_payload == b"AFTER_GAP"

    def test_reaper_idle_stream_timeout(self) -> None:
        """Stream idle for >= 300 capture-seconds is finalized automatically."""
        finalized: list[ReassembledSession] = []
        engine = StreamReassembler(on_session_finalized=finalized.append)

        # Stream 1 packet at ts = 1000.0
        engine.process_packet(
            make_raw_tcp_packet("10.0.0.1", "10.0.0.2", 1111, 25, 100, 0, "PA", b"DATA", ts=1000.0)
        )
        assert len(finalized) == 0

        # Fast forward capture clock to ts = 1350.0 (350s later > 300s idle timeout)
        engine.process_packet(
            make_raw_tcp_packet("10.0.0.3", "10.0.0.4", 2222, 25, 100, 0, "PA", b"DATA2", ts=1350.0)
        )

        # Stream 1 should have been finalized by reaper
        assert any(s.client_port == 1111 for s in finalized)

    def test_per_session_buffer_cap(self) -> None:
        """Exceeding max_session_buffer_bytes stops buffering and sets buffer_truncated = True."""
        finalized: list[ReassembledSession] = []
        engine = StreamReassembler(on_session_finalized=finalized.append)

        original_max_buf = settings.max_session_buffer_bytes
        try:
            # Set test buffer cap to 100 KiB
            settings.max_session_buffer_bytes = 100_000

            # SYN
            engine.process_packet(
                make_raw_tcp_packet("10.0.0.1", "10.0.0.2", 5000, 25, 1000, 0, "S", b"")
            )

            # Send 150 KiB in 30 KiB chunks
            chunk_size = 30_000
            total_data = 150_000
            curr_seq = 1001
            sent = 0

            while sent < total_data:
                engine.process_packet(
                    make_raw_tcp_packet(
                        "10.0.0.1", "10.0.0.2", 5000, 25, curr_seq, 0, "A", b"A" * chunk_size
                    )
                )
                curr_seq += chunk_size
                sent += chunk_size

            engine.flush_all()
            assert len(finalized) == 1
            sess = finalized[0]
            assert sess.quality.buffer_truncated is True
            assert len(sess.c2s_payload) == 100_000
            assert sess.c2s_bytes == total_data
        finally:
            settings.max_session_buffer_bytes = original_max_buf

    def test_flow_table_lru_eviction(self) -> None:
        """When flow table capacity is exceeded, oldest flow is evicted with evicted_flows counter."""
        finalized: list[ReassembledSession] = []
        engine = StreamReassembler(on_session_finalized=finalized.append)

        original_max_flows = settings.max_flows
        try:
            # Set small flow table limit for testing
            settings.max_flows = 5

            for i in range(10):
                engine.process_packet(
                    make_raw_tcp_packet("10.0.0.1", "10.0.0.2", 1000 + i, 25, 100, 0, "PA", b"TEST")
                )

            assert engine.evicted_flows == 5
            assert len(finalized) == 5
        finally:
            settings.max_flows = original_max_flows

    def test_reassemble_pcap_generator_helper(self) -> None:
        """reassemble_pcap yields ReassembledSession instances from packet stream."""
        from pecff.ingest.reassembly import reassemble_pcap

        pkts = [make_raw_tcp_packet("10.0.0.1", "10.0.0.2", 8888, 25, 100, 0, "PA", b"STREAM_TEST")]

        sessions = list(reassemble_pcap(iter(pkts)))
        assert len(sessions) == 1
        assert sessions[0].c2s_payload == b"STREAM_TEST"


class TestDifferentialReferenceStreams:
    """Differential testing against 50 synthetic reference scenarios with complex fragmentation & reordering."""

    def test_fifty_reference_streams_parity(self) -> None:
        rng = random.Random(1337)

        for stream_id in range(50):
            # Generate random realistic SMTP/IMAP conversation
            c2s_messages = [
                b"EHLO client.example.org\r\n",
                b"STARTTLS\r\n",
                b"MAIL FROM:<sender@example.org>\r\n",
                b"RCPT TO:<recipient@example.org>\r\n",
                b"DATA\r\n",
                b"Subject: Test Forensic Stream\r\n\r\nForensic Payload Data 1234567890.\r\n.\r\n",
                b"QUIT\r\n",
            ]
            expected_c2s = b"".join(c2s_messages)

            # Chop into arbitrary segments
            segments: list[tuple[int, bytes]] = []
            curr = 0
            isn = rng.randint(0, 0xFFFFFFFF)

            while curr < len(expected_c2s):
                seg_len = rng.randint(3, 40)
                seg_bytes = expected_c2s[curr : curr + seg_len]
                seq_num = (isn + 1 + curr) & 0xFFFFFFFF
                segments.append((seq_num, seg_bytes))
                curr += seg_len

            # Insert duplicates
            for _ in range(rng.randint(2, 5)):
                segments.append(rng.choice(segments))

            rng.shuffle(segments)

            # Reassemble
            finalized: list[ReassembledSession] = []
            engine = StreamReassembler(on_session_finalized=finalized.append)

            # SYN
            engine.process_packet(
                make_raw_tcp_packet(
                    "10.10.10.1", "10.10.10.2", 20000 + stream_id, 25, isn, 0, "S", b""
                )
            )

            for s_seq, s_data in segments:
                engine.process_packet(
                    make_raw_tcp_packet(
                        "10.10.10.1",
                        "10.10.10.2",
                        20000 + stream_id,
                        25,
                        s_seq,
                        0,
                        "A",
                        s_data,
                    )
                )

            # FIN
            fin_seq = (isn + 1 + len(expected_c2s)) & 0xFFFFFFFF
            engine.process_packet(
                make_raw_tcp_packet(
                    "10.10.10.1",
                    "10.10.10.2",
                    20000 + stream_id,
                    25,
                    fin_seq,
                    0,
                    "FA",
                    b"",
                )
            )

            engine.flush_all()
            assert len(finalized) == 1
            assert finalized[0].c2s_payload == expected_c2s, (
                f"Differential parity failed on stream {stream_id}"
            )
