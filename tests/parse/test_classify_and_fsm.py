"""Tests for protocol classification and STARTTLS state machine."""

import tempfile
from pathlib import Path

import yaml

from pecff.parse.classify import ProtocolClassifier
from pecff.parse.starttls_fsm import Direction, StarttlsFSM, StarttlsState


class TestProtocolClassification:
    """Test two-stage protocol classification and content override."""

    def test_standard_port_hints(self) -> None:
        classifier = ProtocolClassifier()
        # SMTP
        res25 = classifier.classify_stream(25, b"")
        assert res25.protocol == "SMTP"
        assert res25.mode == "EXPLICIT"
        assert res25.detected_by == "port"
        assert res25.port_is_standard_mail is True

        # SMTPS
        res465 = classifier.classify_stream(465, b"")
        assert res465.protocol == "SMTP"
        assert res465.mode == "IMPLICIT"

        # POP3 / POP3S
        res110 = classifier.classify_stream(110, b"")
        assert res110.protocol == "POP3"
        assert res110.mode == "EXPLICIT"

        res995 = classifier.classify_stream(995, b"")
        assert res995.protocol == "POP3"
        assert res995.mode == "IMPLICIT"

        # IMAP / IMAPS
        res143 = classifier.classify_stream(143, b"")
        assert res143.protocol == "IMAP"
        assert res143.mode == "EXPLICIT"

        res993 = classifier.classify_stream(993, b"")
        assert res993.protocol == "IMAP"
        assert res993.mode == "IMPLICIT"

    def test_content_always_wins_conflicts(self) -> None:
        """Content confirmation overrides conflicting port hints."""
        classifier = ProtocolClassifier()

        # SMTP banner on IMAP port 143
        res = classifier.classify_stream(143, b"220 mail.example.com ESMTP Postfix\r\n")
        assert res.protocol == "SMTP"
        assert res.mode == "EXPLICIT"
        assert res.detected_by == "content"

        # POP3 greeting on SMTP port 25
        res = classifier.classify_stream(25, b"+OK Dovecot ready.\r\n")
        assert res.protocol == "POP3"
        assert res.detected_by == "content"

        # IMAP greeting on port 8080 (non-standard port)
        res = classifier.classify_stream(8080, b"* OK IMAP4rev1 Server Ready\r\n")
        assert res.protocol == "IMAP"
        assert res.detected_by == "content"
        assert res.port_is_standard_mail is False

    def test_alpn_mail_override(self) -> None:
        """ALPN takes highest precedence on non-standard ports (RFC 7639)."""
        classifier = ProtocolClassifier()

        res = classifier.classify_stream(8443, b"\x16\x03\x03\x00\x50", alpn="imap")
        assert res.protocol == "IMAP"
        assert res.mode == "IMPLICIT"
        assert res.detected_by == "alpn"

    def test_quic_transport_detection(self) -> None:
        """QUIC on standard mail ports emits UNSUPPORTED_TRANSPORT_QUIC finding."""
        classifier = ProtocolClassifier()
        quic_pkt = b"\xc0\x00\x00\x01\x08"  # Initial QUIC packet with long header bit set (0x80)

        finding = classifier.check_quic_transport(25, quic_pkt)
        assert finding is not None
        assert finding.rule_id == "UNSUPPORTED_TRANSPORT_QUIC"

        # Non-QUIC UDP payload
        finding_none = classifier.check_quic_transport(25, b"\x00\x01\x02")
        assert finding_none is None

    def test_custom_ports_yaml_override(self) -> None:
        """Operator custom_ports.yaml overrides default port mapping."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as tf:
            yaml.dump(
                {
                    "2525": {"protocol": "SMTP", "mode": "EXPLICIT"},
                    "9999": {"protocol": "IMAP", "mode": "IMPLICIT"},
                },
                tf,
            )
            custom_path = Path(tf.name)

        classifier = ProtocolClassifier(custom_ports_file=custom_path)
        res = classifier.classify_stream(9999, b"")
        assert res.protocol == "IMAP"
        assert res.mode == "IMPLICIT"
        assert res.detected_by == "override"


class TestStarttlsFSM:
    """Test finite state machine progression and forensic evidence recording."""

    def test_smtp_clean_starttls_lifecycle(self) -> None:
        fsm = StarttlsFSM(protocol="SMTP", mode="EXPLICIT")
        assert fsm.get_state() == StarttlsState.S0_TCP_EST

        # S2C Server banner -> S1_GREETING
        fsm.feed(Direction.S2C, b"220 mail.example.com ESMTP Postfix\r\n", 0, 1000.0)
        assert fsm.get_state() == StarttlsState.S1_GREETING
        assert fsm.server_banner == "220 mail.example.com ESMTP Postfix"

        # C2S EHLO -> S1B_CAPS_ADV
        fsm.feed(Direction.C2S, b"EHLO client.example.com\r\n", 36, 1000.05)
        assert fsm.ehlo_domain == "client.example.com"

        # S2C 250 Capabilities
        fsm.feed(
            Direction.S2C,
            b"250-mail.example.com\r\n250-PIPELINING\r\n250-STARTTLS\r\n250 8BITMIME\r\n",
            62,
            1000.1,
        )
        assert fsm.get_state() == StarttlsState.S1B_CAPS_ADV
        assert "STARTTLS" in fsm.advertised_capabilities
        assert "PIPELINING" in fsm.advertised_capabilities

        # C2S STARTTLS -> S2_CMD
        fsm.feed(Direction.C2S, b"STARTTLS\r\n", 130, 1000.2)
        assert fsm.get_state() == StarttlsState.S2_CMD

        # S2C 220 2.0.0 Ready to start TLS -> S2_ACCEPTED
        fsm.feed(Direction.S2C, b"220 2.0.0 Ready to start TLS\r\n", 140, 1000.25)
        assert fsm.get_state() == StarttlsState.S2_ACCEPTED

        # C2S TLS ClientHello -> S3_TLS_HS
        tls_hello = b"\x16\x03\x03\x00\x50\x01\x00\x00\x4c" + (b"\x00" * 70)
        fsm.feed(Direction.C2S, tls_hello, 170, 1000.3)
        assert fsm.get_state() == StarttlsState.S3_TLS_HS
        assert fsm.upgrade_latency_ms is not None
        assert abs(fsm.upgrade_latency_ms - 100.0) < 1.0  # 1000.3 - 1000.2 = 100ms

        # Check that all transitions recorded nonzero evidence slices
        assert len(fsm.transitions) >= 5
        for t in fsm.transitions:
            assert len(t.evidence_slice) > 0
            assert len(t.evidence_bytes) > 0
            assert "|" in t.evidence_slice  # Hex | ASCII representation

    def test_imap_starttls_and_tag_matching(self) -> None:
        fsm = StarttlsFSM(protocol="IMAP", mode="EXPLICIT")

        # Greeting
        fsm.feed(Direction.S2C, b"* OK IMAP4rev1 Service Ready\r\n", 0, 100.0)
        assert fsm.get_state() == StarttlsState.S1_GREETING

        # Upgrade command with tag "A001"
        fsm.feed(Direction.C2S, b"A001 STARTTLS\r\n", 30, 100.1)
        assert fsm.get_state() == StarttlsState.S2_CMD

        # Accept response with matching tag "A001"
        fsm.feed(Direction.S2C, b"A001 OK Begin TLS negotiation now\r\n", 45, 100.2)
        assert fsm.get_state() == StarttlsState.S2_ACCEPTED
        assert len(fsm.findings) == 0

    def test_imap_tag_mismatch_anomaly(self) -> None:
        fsm = StarttlsFSM(protocol="IMAP", mode="EXPLICIT")
        fsm.feed(Direction.S2C, b"* OK IMAP4rev1 Ready\r\n", 0, 100.0)
        fsm.feed(Direction.C2S, b"TAG_XYZ STARTTLS\r\n", 22, 100.1)
        # Server responds with mismatched tag "TAG_WRONG"
        fsm.feed(Direction.S2C, b"TAG_WRONG OK Begin TLS\r\n", 40, 100.2)

        assert any(f.rule_id == "IMAP_TAG_MISMATCH" for f in fsm.findings)
