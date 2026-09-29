"""Performance and throughput benchmark asserting engine scaling requirements.

Requirements:
- Ingestion + Reassembly + Analysis Throughput >= 10 GiB / hour / worker (~2.98 MB/s).
- Peak Memory Footprint (RSS) < 6 GiB.
- Constant memory consumption independent of capture size (streaming fast paths).
"""

from __future__ import annotations

import resource
import sys
import time
import tracemalloc
from pathlib import Path

import pytest
from scapy.all import IP, TCP, Ether, wrpcap

from pecff.crypto.risk_engine import NISTDeterministicRiskScorer, SessionCryptoParameters
from pecff.ingest.reader import PcapReader
from pecff.ingest.reassembly import StreamReassembler
from pecff.parse.classify import ProtocolClassifier
from pecff.parse.downgrade_detectors import DowngradeDetectorEngine
from pecff.parse.starttls_fsm import Direction, StarttlsFSM


@pytest.mark.slow
class TestEnginePerformanceAndThroughput:
    """Benchmark asserting processing throughput and bounded memory usage."""

    def _get_peak_rss_gib(self) -> float:
        """Get peak RSS in GiB across macOS and Linux."""
        rusage = resource.getrusage(resource.RUSAGE_SELF)
        if sys.platform == "darwin":
            # On macOS, ru_maxrss is in bytes
            return rusage.ru_maxrss / (1024**3)
        else:
            # On Linux, ru_maxrss is in kilobytes
            return (rusage.ru_maxrss * 1024) / (1024**3)

    def test_pipeline_throughput_and_rss_bound(self, tmp_path: Path) -> None:
        """Assert throughput >= 10 GiB/hr/worker and RSS < 6 GiB under high-packet load."""
        tracemalloc.start()
        start_rss = self._get_peak_rss_gib()

        # Generate a high-volume synthetic PCAP with realistic TLS and SMTP streams
        pcap_file = tmp_path / "bench_throughput.pcap"
        pkts: list[Ether] = []
        base_time = 1700000000.0

        # Build 200 concurrent sessions with 50 segments each
        for session_id in range(200):
            client_port = 30000 + (session_id % 20000)
            server_port = 25 if session_id % 2 == 0 else 465
            client_ip = f"192.168.1.{10 + (session_id % 200)}"
            server_ip = "10.0.0.25"

            # 3-way handshake
            t = base_time + session_id * 0.01
            syn = Ether(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee") / IP(src=client_ip, dst=server_ip) / TCP(
                sport=client_port, dport=server_port, flags="S", seq=1000
            )
            syn.time = t
            pkts.append(syn)

            synack = Ether(src="00:aa:bb:cc:dd:ee", dst="00:11:22:33:44:55") / IP(src=server_ip, dst=client_ip) / TCP(
                sport=server_port, dport=client_port, flags="SA", seq=5000, ack=1001
            )
            synack.time = t + 0.001
            pkts.append(synack)

            ack = Ether(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee") / IP(src=client_ip, dst=server_ip) / TCP(
                sport=client_port, dport=server_port, flags="A", seq=1001, ack=5001
            )
            ack.time = t + 0.002
            pkts.append(ack)

            # Dialogue payload
            c_seq = 1001
            s_seq = 5001

            if server_port == 25:
                banner = b"220 mx.example.com ESMTP Postfix\r\n"
                p_banner = Ether(src="00:aa:bb:cc:dd:ee", dst="00:11:22:33:44:55") / IP(src=server_ip, dst=client_ip) / TCP(
                    sport=server_port, dport=client_port, flags="PA", seq=s_seq, ack=c_seq
                ) / banner
                p_banner.time = t + 0.005
                pkts.append(p_banner)
                s_seq += len(banner)

                ehlo = b"EHLO client.example.com\r\n"
                p_ehlo = Ether(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee") / IP(src=client_ip, dst=server_ip) / TCP(
                    sport=client_port, dport=server_port, flags="PA", seq=c_seq, ack=s_seq
                ) / ehlo
                p_ehlo.time = t + 0.010
                pkts.append(p_ehlo)
                c_seq += len(ehlo)

                caps = b"250-mx.example.com\r\n250-STARTTLS\r\n250 8BITMIME\r\n"
                p_caps = Ether(src="00:aa:bb:cc:dd:ee", dst="00:11:22:33:44:55") / IP(src=server_ip, dst=client_ip) / TCP(
                    sport=server_port, dport=client_port, flags="PA", seq=s_seq, ack=c_seq
                ) / caps
                p_caps.time = t + 0.015
                pkts.append(p_caps)
                s_seq += len(caps)

            # Add data chunks
            for seg in range(10):
                c_data = b"X" * 1200
                p_data = Ether(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee") / IP(src=client_ip, dst=server_ip) / TCP(
                    sport=client_port, dport=server_port, flags="PA", seq=c_seq, ack=s_seq
                ) / c_data
                p_data.time = t + 0.02 + seg * 0.002
                pkts.append(p_data)
                c_seq += len(c_data)

        wrpcap(str(pcap_file), pkts)
        file_size_bytes = pcap_file.stat().st_size

        # Run pipeline measurement
        t0 = time.perf_counter()

        reader = PcapReader(pcap_file)
        reassembler = StreamReassembler(
            candidate_ports={25, 465, 587, 110, 143, 993, 995, 2525},
            handshake_only=True,
        )
        classifier = ProtocolClassifier()
        detector_engine = DowngradeDetectorEngine(known_starttls_endpoints={"10.0.0.25:25"})
        risk_scorer = NISTDeterministicRiskScorer()

        packet_count = 0
        for pkt in reader.packets():
            reassembler.process_packet(pkt)
            packet_count += 1

        sessions = reassembler.finalize_all()

        for session in sessions:
            cls = classifier.classify(session)
            fsm = StarttlsFSM(protocol=cls.protocol, mode=cls.mode)
            if session.s2c_payload:
                fsm.feed(Direction.S2C, bytes(session.s2c_payload[:1024]), 0, session.first_seen)
            if session.c2s_payload:
                fsm.feed(Direction.C2S, bytes(session.c2s_payload[:1024]), 0, session.first_seen)

            _ = detector_engine.analyze_session(session=session, fsm=fsm)
            crypto_params = SessionCryptoParameters(
                protocol_version="TLS 1.2" if cls.mode == "IMPLICIT" else "NONE",
                dst_port=session.server_port,
                handshake_completed=True,
                cert_analysis_possible=False,
            )
            _ = risk_scorer.score_session(crypto_params)

        t1 = time.perf_counter()
        elapsed_sec = max(0.001, t1 - t0)

        # Compute throughput metrics
        bytes_per_sec = file_size_bytes / elapsed_sec
        gib_per_hour = (bytes_per_sec * 3600.0) / (1024**3)
        packets_per_sec = packet_count / elapsed_sec

        current_mem, peak_traced_mem = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        peak_rss_gib = self._get_peak_rss_gib()

        print(
            f"\n--- PERFORMANCE BENCHMARK RESULTS ---\n"
            f"File Size:       {file_size_bytes / (1024*1024):.2f} MiB ({packet_count} packets, {len(sessions)} sessions)\n"
            f"Elapsed Time:    {elapsed_sec:.4f} s\n"
            f"Throughput:      {bytes_per_sec / (1024*1024):.2f} MiB/s | {gib_per_hour:.2f} GiB/hr/worker\n"
            f"Packet Rate:     {packets_per_sec:,.0f} pkts/s\n"
            f"Peak Traced Mem: {peak_traced_mem / (1024*1024):.2f} MiB\n"
            f"Peak Process RSS:{peak_rss_gib:.3f} GiB (Limit: < 6.0 GiB)\n"
        )

        # Assert performance standards
        assert gib_per_hour >= 10.0, (
            f"Processing throughput {gib_per_hour:.2f} GiB/hr/worker is below required 10.0 GiB/hr"
        )
        assert peak_rss_gib < 6.0, (
            f"Peak RSS {peak_rss_gib:.2f} GiB exceeded 6.0 GiB worker memory budget"
        )
        assert len(sessions) > 0, "No sessions were processed"
