"""Comprehensive test suite for downgrade detectors D1-D9.

Includes:
- Positive triggers and negative near-misses for every detector (D1-D9).
- 200 benign sessions validating zero false positives.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from pecff.ingest.reader import PcapReader
from pecff.ingest.reassembly import ReassembledSession, ReassemblyQuality, StreamReassembler
from pecff.parse.classify import ProtocolClassifier
from pecff.parse.downgrade_detectors import (
    TLS12_DOWNGRADE_SENTINEL,
    DowngradeDetectorEngine,
)
from pecff.parse.starttls_fsm import Direction, StarttlsFSM, StarttlsState


def make_test_session(
    c2s_payload: bytes = b"",
    s2c_payload: bytes = b"",
    server_port: int = 25,
    server_ip: str = "192.168.1.10",
    first_seen: float = 1000.0,
    last_seen: float = 1005.0,
) -> ReassembledSession:
    """Helper to construct ReassembledSession for detector tests."""
    return ReassembledSession(
        client_ip="192.168.1.100",
        client_port=54321,
        server_ip=server_ip,
        server_port=server_port,
        vlan_id=None,
        first_seen=first_seen,
        last_seen=last_seen,
        c2s_bytes=len(c2s_payload),
        s2c_bytes=len(s2c_payload),
        c2s_packets=10,
        s2c_packets=10,
        c2s_payload=c2s_payload,
        s2c_payload=s2c_payload,
        quality=ReassemblyQuality(
            retrans_count=0,
            overlap_count=0,
            gaps=[],
            complete=True,
            buffer_truncated=False,
            direction_inferred=False,
        ),
        findings=[],
    )


class TestDowngradeDetectorsD1toD9:
    """Trigger tests and near-misses for D1-D9."""

    # -------------------------------------------------------------------------
    # D1: CAPABILITY_STRIP
    # -------------------------------------------------------------------------
    def test_d1_capability_strip_positive(self) -> None:
        """Trigger: Server known to support STARTTLS omits it from capabilities."""
        engine = DowngradeDetectorEngine(known_starttls_endpoints={"192.168.1.10:25"})
        sess = make_test_session(server_ip="192.168.1.10", server_port=25)

        fsm = StarttlsFSM(protocol="SMTP")
        fsm.server_banner = "220 mail.example.com"
        fsm.advertised_capabilities = ["PIPELINING", "8BITMIME"]  # STARTTLS stripped!

        finding = engine.detect_d1_capability_strip(sess, fsm)
        assert finding is not None
        assert finding.rule_id == "D1_CAPABILITY_STRIP"
        assert finding.severity == "CRITICAL"

    def test_d1_capability_strip_near_miss(self) -> None:
        """Near-miss: STARTTLS is present in capabilities -> No finding."""
        engine = DowngradeDetectorEngine(known_starttls_endpoints={"192.168.1.10:25"})
        sess = make_test_session(server_ip="192.168.1.10", server_port=25)

        fsm = StarttlsFSM(protocol="SMTP")
        fsm.server_banner = "220 mail.example.com"
        fsm.advertised_capabilities = ["PIPELINING", "STARTTLS"]

        finding = engine.detect_d1_capability_strip(sess, fsm)
        assert finding is None

    # -------------------------------------------------------------------------
    # D2: SILENT_FAILURE
    # -------------------------------------------------------------------------
    def test_d2_silent_failure_positive(self) -> None:
        """Trigger: S2_CMD sent, but no accept/reject returned before session close."""
        engine = DowngradeDetectorEngine()
        sess = make_test_session(first_seen=100.0, last_seen=115.0)  # 15s > 10s timeout

        fsm = StarttlsFSM(protocol="SMTP")
        fsm.feed(Direction.S2C, b"220 mail.example.com\r\n", 0, 100.0)
        fsm.feed(Direction.C2S, b"STARTTLS\r\n", 22, 100.1)  # Enters S2_CMD

        finding = engine.detect_d2_silent_failure(sess, fsm)
        assert finding is not None
        assert finding.rule_id == "D2_SILENT_FAILURE"

    def test_d2_silent_failure_near_miss(self) -> None:
        """Near-miss: Server responds with 220 within 0.2s -> No finding."""
        engine = DowngradeDetectorEngine()
        sess = make_test_session(first_seen=100.0, last_seen=105.0)

        fsm = StarttlsFSM(protocol="SMTP")
        fsm.feed(Direction.S2C, b"220 mail.example.com\r\n", 0, 100.0)
        fsm.feed(Direction.C2S, b"STARTTLS\r\n", 22, 100.1)
        fsm.feed(Direction.S2C, b"220 Ready for TLS\r\n", 32, 100.3)  # Resolved

        finding = engine.detect_d2_silent_failure(sess, fsm)
        assert finding is None

    # -------------------------------------------------------------------------
    # D3: EXPLICIT_REFUSAL
    # -------------------------------------------------------------------------
    def test_d3_explicit_refusal_positive(self) -> None:
        """Trigger: Server returns 500 or 454 to STARTTLS command."""
        engine = DowngradeDetectorEngine()
        fsm = StarttlsFSM(protocol="SMTP")
        fsm.feed(Direction.S2C, b"220 mail.example.com\r\n", 0, 100.0)
        fsm.feed(Direction.C2S, b"STARTTLS\r\n", 22, 100.1)
        fsm.feed(Direction.S2C, b"500 5.3.3 Unrecognized command\r\n", 32, 100.2)

        finding = engine.detect_d3_explicit_refusal(fsm)
        assert finding is not None
        assert finding.rule_id == "D3_EXPLICIT_REFUSAL"
        assert finding.severity == "HIGH"

    def test_d3_explicit_refusal_near_miss(self) -> None:
        """Near-miss: Server accepts with 220 -> No refusal finding."""
        engine = DowngradeDetectorEngine()
        fsm = StarttlsFSM(protocol="SMTP")
        fsm.feed(Direction.S2C, b"220 mail.example.com\r\n", 0, 100.0)
        fsm.feed(Direction.C2S, b"STARTTLS\r\n", 22, 100.1)
        fsm.feed(Direction.S2C, b"220 2.0.0 Ready\r\n", 32, 100.2)

        finding = engine.detect_d3_explicit_refusal(fsm)
        assert finding is None

    # -------------------------------------------------------------------------
    # D4: POST220_PLAINTEXT
    # -------------------------------------------------------------------------
    def test_d4_post220_plaintext_positive(self) -> None:
        """Trigger: 220 accepted, but client sends plaintext EHLO instead of TLS ClientHello."""
        engine = DowngradeDetectorEngine()
        sess = make_test_session(c2s_payload=b"STARTTLS\r\nEHLO client.com\r\n")

        fsm = StarttlsFSM(protocol="SMTP")
        fsm.feed(Direction.S2C, b"220 mail.example.com\r\n", 0, 100.0)
        fsm.feed(Direction.C2S, b"STARTTLS\r\n", 22, 100.1)
        fsm.feed(Direction.S2C, b"220 Ready for TLS\r\n", 32, 100.2)
        fsm.feed(Direction.C2S, b"EHLO client.com\r\n", 50, 100.3)  # Plaintext after 220!

        finding = engine.detect_d4_post220_plaintext(sess, fsm)
        assert finding is not None
        assert finding.rule_id == "D4_POST220_PLAINTEXT"
        assert finding.severity == "CRITICAL"

    def test_d4_post220_plaintext_near_miss(self) -> None:
        """Near-miss: Client sends TLS ClientHello (0x16 0x03 0x03) after 220 -> No finding."""
        engine = DowngradeDetectorEngine()
        sess = make_test_session(c2s_payload=b"STARTTLS\r\n\x16\x03\x03\x00\x50...")

        fsm = StarttlsFSM(protocol="SMTP")
        fsm.feed(Direction.S2C, b"220 mail.example.com\r\n", 0, 100.0)
        fsm.feed(Direction.C2S, b"STARTTLS\r\n", 22, 100.1)
        fsm.feed(Direction.S2C, b"220 Ready for TLS\r\n", 32, 100.2)
        fsm.feed(Direction.C2S, b"\x16\x03\x03\x00\x50\x01\x00\x00", 50, 100.3)

        finding = engine.detect_d4_post220_plaintext(sess, fsm)
        assert finding is None

    # -------------------------------------------------------------------------
    # D5: CLEARTEXT_CREDENTIALS
    # -------------------------------------------------------------------------
    def test_d5_cleartext_credentials_positive(self) -> None:
        """Trigger: Cleartext AUTH PLAIN / USER / PASS in unencrypted session."""
        engine = DowngradeDetectorEngine()
        sess = make_test_session(c2s_payload=b"EHLO client\r\nAUTH PLAIN dXNlcgBwYXNz\r\n")

        fsm = StarttlsFSM(protocol="SMTP")
        fsm.state = StarttlsState.S_PLAINTEXT

        finding = engine.detect_d5_cleartext_credentials(sess, fsm)
        assert finding is not None
        assert finding.rule_id == "D5_CLEARTEXT_CREDENTIALS"
        assert finding.severity == "CRITICAL"
        assert "HASHED_PII" in finding.evidence_bytes.decode("latin-1")

    def test_d5_cleartext_credentials_near_miss(self) -> None:
        """Near-miss: Session is fully encrypted (S4_ENCRYPTED) -> No finding."""
        engine = DowngradeDetectorEngine()
        sess = make_test_session(c2s_payload=b"\x17\x03\x03\x00\x40ENCRYPTED_PAYLOAD")

        fsm = StarttlsFSM(protocol="SMTP")
        fsm.state = StarttlsState.S4_ENCRYPTED

        finding = engine.detect_d5_cleartext_credentials(sess, fsm)
        assert finding is None

    # -------------------------------------------------------------------------
    # D6: VERSION_DOWNGRADE
    # -------------------------------------------------------------------------
    def test_d6_version_downgrade_sentinel(self) -> None:
        """Trigger: ServerRandom contains RFC 8446 downgrade sentinel DOWNGRD\\x01."""
        engine = DowngradeDetectorEngine()
        server_random = (b"\xaa" * 24) + TLS12_DOWNGRADE_SENTINEL

        finding = engine.detect_d6_version_downgrade(
            client_supported_versions=[0x0304, 0x0303],
            server_selected_version=0x0303,
            server_random=server_random,
        )
        assert finding is not None
        assert finding.rule_id == "D6_VERSION_DOWNGRADE"
        assert "TLS Downgrade Sentinel" in finding.title

    def test_d6_version_downgrade_forced_drop(self) -> None:
        """Trigger: Client supports TLS 1.3 (0x0304) but server forces <= TLS 1.1 (0x0302)."""
        engine = DowngradeDetectorEngine()
        server_random = b"\xaa" * 32  # Random without sentinel

        finding = engine.detect_d6_version_downgrade(
            client_supported_versions=[0x0304, 0x0303, 0x0302],
            server_selected_version=0x0302,
            server_random=server_random,
        )
        assert finding is not None
        assert finding.rule_id == "D6_VERSION_DOWNGRADE"
        assert "Forced Insecure TLS" in finding.title

    def test_d6_version_downgrade_near_miss(self) -> None:
        """Near-miss: Client and Server both negotiate TLS 1.3 cleanly -> No finding."""
        engine = DowngradeDetectorEngine()
        server_random = b"\x55" * 32

        finding = engine.detect_d6_version_downgrade(
            client_supported_versions=[0x0304],
            server_selected_version=0x0304,
            server_random=server_random,
        )
        assert finding is None

    # -------------------------------------------------------------------------
    # D7: HANDSHAKE_TRUNCATION
    # -------------------------------------------------------------------------
    def test_d7_handshake_truncation_positive(self) -> None:
        """Trigger: S3_TLS_HS entered, ClientHello sent, but connection reset before ServerHello."""
        engine = DowngradeDetectorEngine()
        sess = make_test_session(c2s_payload=b"\x16\x03\x03\x00\x50...", s2c_payload=b"")

        fsm = StarttlsFSM(protocol="SMTP")
        fsm.state = StarttlsState.S3_TLS_HS

        finding = engine.detect_d7_handshake_truncation(fsm, sess, server_hello_seen=False)
        assert finding is not None
        assert finding.rule_id == "D7_HANDSHAKE_TRUNCATION"

    def test_d7_handshake_truncation_near_miss(self) -> None:
        """Near-miss: ServerHello was seen -> No truncation finding."""
        engine = DowngradeDetectorEngine()
        sess = make_test_session(
            c2s_payload=b"\x16\x03\x03\x00\x50...", s2c_payload=b"\x16\x03\x03\x00\x50..."
        )

        fsm = StarttlsFSM(protocol="SMTP")
        fsm.state = StarttlsState.S3_TLS_HS

        finding = engine.detect_d7_handshake_truncation(fsm, sess, server_hello_seen=True)
        assert finding is None

    # -------------------------------------------------------------------------
    # D8: BANNER_MUTATION
    # -------------------------------------------------------------------------
    def test_d8_banner_mutation_positive(self) -> None:
        """Trigger: Server banner differs from baseline by Levenshtein distance > 8."""
        engine = DowngradeDetectorEngine(
            cached_banners={"192.168.1.10:25": "220 mx1.corporate-mail.example.com ESMTP Postfix"}
        )
        sess = make_test_session(server_ip="192.168.1.10", server_port=25)

        fsm = StarttlsFSM(protocol="SMTP")
        fsm.server_banner = "220 totally-different-mitm-banner.attacker.net"

        finding = engine.detect_d8_banner_mutation(sess, fsm)
        assert finding is not None
        assert finding.rule_id == "D8_BANNER_MUTATION"

    def test_d8_banner_mutation_near_miss(self) -> None:
        """Near-miss: Banner only differs by minor timestamp/PID (< 8 chars) -> No finding."""
        engine = DowngradeDetectorEngine(
            cached_banners={
                "192.168.1.10:25": "220 mx1.corporate-mail.example.com ESMTP Postfix (Ubuntu 1)"
            }
        )
        sess = make_test_session(server_ip="192.168.1.10", server_port=25)

        fsm = StarttlsFSM(protocol="SMTP")
        fsm.server_banner = (
            "220 mx1.corporate-mail.example.com ESMTP Postfix (Ubuntu 2)"  # distance = 1
        )

        finding = engine.detect_d8_banner_mutation(sess, fsm)
        assert finding is None

    # -------------------------------------------------------------------------
    # D9: POLICY_VIOLATION
    # -------------------------------------------------------------------------
    def test_d9_policy_violation_positive(self) -> None:
        """Trigger: Domain in MTA-STS enforce mode completed session in plaintext."""
        engine = DowngradeDetectorEngine(mta_sts_policies={"secure.example.com": "enforce"})
        sess = make_test_session()

        fsm = StarttlsFSM(protocol="SMTP")
        fsm.ehlo_domain = "secure.example.com"
        fsm.state = StarttlsState.S_PLAINTEXT

        finding = engine.detect_d9_policy_violation(sess, fsm)
        assert finding is not None
        assert finding.rule_id == "D9_POLICY_VIOLATION"
        assert finding.severity == "CRITICAL"

    def test_d9_policy_violation_near_miss(self) -> None:
        """Near-miss: Domain in enforce mode successfully upgraded to TLS (S4_ENCRYPTED)."""
        engine = DowngradeDetectorEngine(mta_sts_policies={"secure.example.com": "enforce"})
        sess = make_test_session()

        fsm = StarttlsFSM(protocol="SMTP")
        fsm.ehlo_domain = "secure.example.com"
        fsm.state = StarttlsState.S4_ENCRYPTED

        finding = engine.detect_d9_policy_violation(sess, fsm)
        assert finding is None


class TestBenignCorpusZeroFalsePositives:
    """Validate 200 benign clean sessions produce zero false positive downgrade findings."""

    def test_two_hundred_benign_sessions_zero_fp(self) -> None:
        engine = DowngradeDetectorEngine(
            known_starttls_endpoints={"10.0.0.1:25", "10.0.0.2:587", "10.0.0.3:143"},
            cached_banners={
                "10.0.0.1:25": "220 mail.example.com ESMTP Postfix",
                "10.0.0.2:587": "220 smtp.example.com ESMTP Submission",
                "10.0.0.3:143": "* OK IMAP4rev1 Server Ready",
            },
            mta_sts_policies={"mail.example.com": "enforce"},
        )

        for i in range(200):
            sess = make_test_session(
                server_ip="10.0.0.1",
                server_port=25,
                c2s_payload=b"EHLO mail.example.com\r\nSTARTTLS\r\n\x16\x03\x03\x00\x50\x17\x03\x03...",
                s2c_payload=b"220 mail.example.com ESMTP Postfix\r\n250-STARTTLS\r\n220 2.0.0 Ready\r\n\x16\x03\x03...",
            )

            fsm = StarttlsFSM(protocol="SMTP")
            fsm.server_banner = "220 mail.example.com ESMTP Postfix"
            fsm.ehlo_domain = "mail.example.com"
            fsm.advertised_capabilities = ["PIPELINING", "STARTTLS", "8BITMIME"]
            fsm.state = StarttlsState.S4_ENCRYPTED

            findings = engine.run_all(
                session=sess,
                fsm=fsm,
                client_supported_versions=[0x0304, 0x0303],
                server_selected_version=0x0304,
                server_random=b"\x42" * 32,
                server_hello_seen=True,
            )

            assert len(findings) == 0, f"False positive detected on benign session {i}: {findings}"


class TestScapySyntheticCaptures:
    """Hand-crafted Scapy PCAP validations for synthetic attacks and near misses."""

    def _create_pcap_session(
        self,
        c2s_dialogue: list[tuple[float, bytes]],
        s2c_dialogue: list[tuple[float, bytes]],
        server_port: int = 25,
        server_ip: str = "192.168.1.25",
        client_ip: str = "192.168.1.100",
        client_port: int = 50000,
    ) -> tuple[ReassembledSession, StarttlsFSM]:
        pkts = []
        seq_c = 1000
        seq_s = 5000

        # Handshake: SYN -> SYN/ACK -> ACK
        t0 = 1000.0
        p_syn = (
            Ether()
            / IP(src=client_ip, dst=server_ip)
            / TCP(sport=client_port, dport=server_port, flags="S", seq=seq_c)
        )
        p_syn.time = t0
        pkts.append(p_syn)
        seq_c += 1

        p_sa = (
            Ether()
            / IP(src=server_ip, dst=client_ip)
            / TCP(sport=server_port, dport=client_port, flags="SA", seq=seq_s, ack=seq_c)
        )
        p_sa.time = t0 + 0.001
        pkts.append(p_sa)
        seq_s += 1

        p_ack = (
            Ether()
            / IP(src=client_ip, dst=server_ip)
            / TCP(sport=client_port, dport=server_port, flags="A", seq=seq_c, ack=seq_s)
        )
        p_ack.time = t0 + 0.002
        pkts.append(p_ack)

        # Merge timeline
        all_events = [(t, "C2S", data) for t, data in c2s_dialogue] + [
            (t, "S2C", data) for t, data in s2c_dialogue
        ]
        all_events.sort(key=lambda x: x[0])

        for t, direction, data in all_events:
            if direction == "C2S":
                p = (
                    Ether()
                    / IP(src=client_ip, dst=server_ip)
                    / TCP(sport=client_port, dport=server_port, flags="PA", seq=seq_c, ack=seq_s)
                    / data
                )
                seq_c += len(data)
            else:
                p = (
                    Ether()
                    / IP(src=server_ip, dst=client_ip)
                    / TCP(sport=server_port, dport=client_port, flags="PA", seq=seq_s, ack=seq_c)
                    / data
                )
                seq_s += len(data)
            p.time = t
            pkts.append(p)

        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
            pcap_path = Path(tf.name)
        wrpcap(str(pcap_path), pkts)

        reader = PcapReader(pcap_path)
        reassembler = StreamReassembler()
        classifier = ProtocolClassifier()

        for raw_pkt in reader.packets():
            reassembler.process_packet(raw_pkt)

        reader.close()
        sessions = reassembler.flush_all()
        assert len(sessions) == 1
        sess = sessions[0]

        classification = classifier.classify_stream(
            server_port=sess.server_port,
            s2c_initial_bytes=sess.s2c_payload[:8],
            c2s_initial_bytes=sess.c2s_payload[:8],
        )

        fsm = StarttlsFSM(protocol=classification.protocol, mode=classification.mode)
        # Feed dialogue
        for t, direction, data in all_events:
            dir_enum = Direction.C2S if direction == "C2S" else Direction.S2C
            fsm.feed(direction=dir_enum, chunk=data, stream_offset=0, ts=t)

        pcap_path.unlink(missing_ok=True)
        return sess, fsm

    def test_scapy_capability_strip_attack(self) -> None:
        """Synthetic PCAP: Active MITM strips STARTTLS from 250 response."""
        c2s = [
            (1000.01, b"EHLO mail.target.com\r\n"),
            (1000.03, b"MAIL FROM:<alice@example.com>\r\n"),
        ]
        s2c = [
            (1000.005, b"220 mail.target.com ESMTP Postfix\r\n"),
            (
                1000.02,
                b"250-mail.target.com\r\n250-PIPELINING\r\n250 8BITMIME\r\n",
            ),  # STARTTLS stripped!
            (1000.04, b"250 2.1.0 Ok\r\n"),
        ]
        sess, fsm = self._create_pcap_session(c2s, s2c, server_port=25, server_ip="192.168.1.25")
        engine = DowngradeDetectorEngine(known_starttls_endpoints={"192.168.1.25:25"})
        findings = engine.run_all(session=sess, fsm=fsm)
        assert any(f.rule_id == "D1_CAPABILITY_STRIP" for f in findings)

    def test_scapy_post220_plaintext_attack(self) -> None:
        """Synthetic PCAP: Client received 220 Ready for TLS but sends plaintext command instead."""
        c2s = [
            (1000.01, b"EHLO client.test\r\n"),
            (1000.03, b"STARTTLS\r\n"),
            (
                1000.05,
                b"AUTH PLAIN AHVzZXIAcGFzc3dvcmQ=\r\n",
            ),  # Plaintext command instead of TLS record!
        ]
        s2c = [
            (1000.005, b"220 mail.example.com ESMTP\r\n"),
            (1000.02, b"250-mail.example.com\r\n250 STARTTLS\r\n"),
            (1000.04, b"220 2.0.0 Ready to start TLS\r\n"),
        ]
        sess, fsm = self._create_pcap_session(c2s, s2c, server_port=25)
        engine = DowngradeDetectorEngine()
        findings = engine.run_all(session=sess, fsm=fsm)
        assert any(f.rule_id == "D4_POST220_PLAINTEXT" for f in findings)
        assert any(f.rule_id == "D5_CLEARTEXT_CREDENTIALS" for f in findings)

    def test_scapy_benign_clean_starttls(self) -> None:
        """Synthetic PCAP: Clean STARTTLS upgrade with subsequent TLS traffic -> 0 findings."""
        c2s = [
            (1000.01, b"EHLO client.test\r\n"),
            (1000.03, b"STARTTLS\r\n"),
            (1000.05, b"\x16\x03\x03\x00\x40" + b"\x00" * 64),  # TLS ClientHello
        ]
        s2c = [
            (1000.005, b"220 mail.example.com ESMTP\r\n"),
            (1000.02, b"250-mail.example.com\r\n250 STARTTLS\r\n"),
            (1000.04, b"220 2.0.0 Ready to start TLS\r\n"),
            (1000.06, b"\x16\x03\x03\x00\x40" + b"\x00" * 64),  # TLS ServerHello
        ]
        sess, fsm = self._create_pcap_session(c2s, s2c, server_port=25, server_ip="192.168.1.25")
        engine = DowngradeDetectorEngine(known_starttls_endpoints={"192.168.1.25:25"})
        findings = engine.run_all(session=sess, fsm=fsm, server_hello_seen=True)
        assert len(findings) == 0
