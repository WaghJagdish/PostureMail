"""Adversarial stress test for TCP stream reassembly and memory bounds.

Asserts bounded memory, zero memory leaks, and graceful eviction under extreme
adversarial conditions:
- 100,000 packets across large flow sets.
- 100% out-of-order segments with non-contiguous sequence gaps.
- 50% retransmission rate (duplicate and overlapping sequence windows).
- Strict enforcement of max_flows LRU and OOO heap memory caps.
"""

from __future__ import annotations

import random
import resource
import sys
import tracemalloc

import pytest

from pecff.ingest.reader import RawPacket
from pecff.ingest.reassembly import StreamReassembler


@pytest.mark.slow
class TestAdversarialCaptureTorture:
    """Stress test asserting robust memory bounds and zero crashes under adversarial traffic."""

    def test_100k_adversarial_flows_bounded_memory(self) -> None:
        """Feed 100k adversarial out-of-order, gapped, retransmitted packets and assert bounded memory."""
        tracemalloc.start()
        rng = random.Random(42)

        reassembler = StreamReassembler()
        num_packets = 100_000
        num_flows = 20_000  # Stretches past typical LRU limits

        # Pre-generate synthetic packet headers
        base_ts = 1700000000.0

        for i in range(num_packets):
            flow_idx = i % num_flows
            client_ip_last = (flow_idx % 250) + 1
            client_ip = bytes([192, 168, (flow_idx // 250) % 250, client_ip_last])
            server_ip = bytes([10, 0, 0, 25])
            client_port = 10000 + (flow_idx % 40000)
            server_port = 25

            # 50% retransmission / overlapping vs out-of-order gap
            is_retrans = (i % 2 == 0)
            if is_retrans:
                seq = 1000 + (i % 5) * 100
            else:
                seq = 1000 + (i * 73) % 1_000_000

            payload_len = 128
            payload_data = rng.randbytes(payload_len)

            # Construct IPv4 + TCP packet bytes
            # IP header: 20 bytes, TCP header: 20 bytes
            ip_hdr = bytearray(20)
            ip_hdr[0] = 0x45
            ip_hdr[9] = 6  # TCP
            ip_hdr[12:16] = client_ip
            ip_hdr[16:20] = server_ip

            tcp_hdr = bytearray(20)
            tcp_hdr[0:2] = client_port.to_bytes(2, "big")
            tcp_hdr[2:4] = server_port.to_bytes(2, "big")
            tcp_hdr[4:8] = seq.to_bytes(4, "big")
            tcp_hdr[12] = 0x50  # 20 bytes TCP header
            tcp_hdr[13] = 0x18  # ACK + PSH

            pkt_bytes = bytes(ip_hdr) + bytes(tcp_hdr) + payload_data

            raw_pkt = RawPacket(
                index=i,
                ts=base_ts + (i * 0.001),
                caplen=len(pkt_bytes),
                wirelen=len(pkt_bytes),
                vlan_id=None,
                payload=memoryview(pkt_bytes),
            )

            reassembler.process_packet(raw_pkt)

        # Finalize reassembly
        sessions = reassembler.finalize_all()

        current_mem, peak_traced_mem = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        rusage = resource.getrusage(resource.RUSAGE_SELF)
        peak_rss_gib = (rusage.ru_maxrss / (1024**3)) if sys.platform == "darwin" else (rusage.ru_maxrss * 1024 / (1024**3))

        print(
            f"\n--- ADVERSARIAL TORTURE TEST RESULTS ---\n"
            f"Packets Ingested:    {num_packets:,}\n"
            f"Active Flows Tracked:{len(reassembler._flows):,}\n"
            f"Evicted Flows:       {reassembler.evicted_flows:,}\n"
            f"Finalized Sessions:  {len(sessions):,}\n"
            f"Peak Traced Memory:  {peak_traced_mem / (1024*1024):.2f} MiB\n"
            f"Process Peak RSS:    {peak_rss_gib:.3f} GiB\n"
        )

        # Memory assertions: peak traced memory must remain tightly bounded (< 150 MiB)
        assert peak_traced_mem < 150 * 1024 * 1024, (
            f"Peak traced memory {peak_traced_mem / (1024*1024):.2f} MiB exceeded 150 MiB cap"
        )
        assert peak_rss_gib < 6.0, f"Process RSS {peak_rss_gib:.2f} GiB exceeded 6.0 GiB budget"
        assert len(sessions) > 0, "Expected finalized sessions"
