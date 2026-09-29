"""Unit tests and fuzz smoke suite for hostile-input safe TLS decoder."""

from __future__ import annotations

import random
import struct

from pecff.parse.tls_decoder import (
    ContentType,
    ExtensionType,
    HandshakeType,
    TLSHandshakeDecoder,
)


def build_tls_record(content_type: int, version: int, fragment: bytes) -> bytes:
    """Helper to assemble a single TLSPlaintext record."""
    return struct.pack(">BHH", content_type, version, len(fragment)) + fragment


def build_handshake_message(hs_type: int, body: bytes) -> bytes:
    """Helper to assemble a Handshake message header + body."""
    hs_len = len(body)
    return bytes([hs_type, (hs_len >> 16) & 0xFF, (hs_len >> 8) & 0xFF, hs_len & 0xFF]) + body


def build_chrome_client_hello() -> bytes:
    """Assemble a realistic Chrome TLS 1.3 ClientHello with RFC 8701 GREASE."""
    rand = b"\x01" * 32
    session_id = b"\xaa" * 32

    # Cipher suites with GREASE (0x2A2A)
    ciphers = [0x2A2A, 0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F]
    cs_bytes = struct.pack(">H", len(ciphers) * 2) + b"".join(struct.pack(">H", c) for c in ciphers)

    comp_bytes = b"\x01\x00"  # null compression

    # Extensions
    exts: list[tuple[int, bytes]] = []

    # 1. GREASE extension 0x1A1A
    exts.append((0x1A1A, b"\x00"))

    # 2. Server Name (SNI) = "mail.example.com"
    sni_data = b"mail.example.com"
    sni_ext = struct.pack(">HBH", len(sni_data) + 3, 0, len(sni_data)) + sni_data
    exts.append((ExtensionType.SERVER_NAME, sni_ext))

    # 3. Supported Versions (TLS 1.3 + TLS 1.2 + GREASE 0x3A3A)
    sv_data = struct.pack(">B", 6) + struct.pack(">HHH", 0x3A3A, 0x0304, 0x0303)
    exts.append((ExtensionType.SUPPORTED_VERSIONS, sv_data))

    # 4. Supported Groups (X25519 + secp256r1 + GREASE 0x4A4A)
    sg_data = struct.pack(">H", 6) + struct.pack(">HHH", 0x4A4A, 0x001D, 0x0017)
    exts.append((ExtensionType.SUPPORTED_GROUPS, sg_data))

    # 5. EC Point Formats
    ec_data = struct.pack(">B", 1) + b"\x00"
    exts.append((ExtensionType.EC_POINT_FORMATS, ec_data))

    # 6. ALPN (imap, smtp)
    alpn_raw = b"\x04imap\x04smtp"
    alpn_data = struct.pack(">H", len(alpn_raw)) + alpn_raw
    exts.append((ExtensionType.ALPN, alpn_data))

    ext_body = bytearray()
    for etype, edata in exts:
        ext_body.extend(struct.pack(">HH", etype, len(edata)))
        ext_body.extend(edata)

    ext_bytes = struct.pack(">H", len(ext_body)) + bytes(ext_body)

    body = (
        struct.pack(">H", 0x0303)
        + rand
        + struct.pack(">B", len(session_id))
        + session_id
        + cs_bytes
        + comp_bytes
        + ext_bytes
    )
    return build_handshake_message(HandshakeType.CLIENT_HELLO, body)


class TestTLSHandshakeDecoder:
    """Validate TLS 1.0-1.3 record decoding, GREASE stripping, and fragmented reassembly."""

    def test_chrome_client_hello_grease_stripping(self) -> None:
        ch_msg = build_chrome_client_hello()
        rec = build_tls_record(ContentType.HANDSHAKE, 0x0301, ch_msg)

        decoder = TLSHandshakeDecoder()
        decoder.process_c2s_record_bytes(rec)

        ch = decoder.summary.client_hello
        assert ch is not None
        assert ch.legacy_version == 0x0303
        assert ch.server_name == "mail.example.com"
        assert "imap" in ch.alpn_protocols
        assert "smtp" in ch.alpn_protocols

        # GREASE identification and presence
        assert ch.grease_present is True
        assert 0x2A2A in ch.grease_values
        assert 0x1A1A in ch.grease_values
        assert 0x3A3A in ch.grease_values
        assert 0x4A4A in ch.grease_values

        # GREASE stripped from JA3
        assert "10794" not in ch.ja3_string  # 0x2A2A = 10794
        assert "6682" not in ch.ja3_string  # 0x1A1A = 6682
        assert len(ch.ja3_hash) == 32
        assert len(ch.ja4_string) > 0

    def test_tls13_server_hello_encrypted_cert_reality_check(self) -> None:
        """TLS 1.3 selected_version sets cert_analysis_possible = False and empty certs."""
        rand = b"\x02" * 32
        sid_echo = b"\xaa" * 32
        sel_cipher = 0x1301  # TLS_AES_128_GCM_SHA256
        sel_comp = 0x00

        # supported_versions extension = 0x0304 (TLS 1.3)
        ext_sv = struct.pack(">HHH", ExtensionType.SUPPORTED_VERSIONS, 2, 0x0304)
        ext_total = struct.pack(">H", len(ext_sv)) + ext_sv

        sh_body = (
            struct.pack(">H", 0x0303)
            + rand
            + struct.pack(">B", len(sid_echo))
            + sid_echo
            + struct.pack(">HB", sel_cipher, sel_comp)
            + ext_total
        )
        sh_msg = build_handshake_message(HandshakeType.SERVER_HELLO, sh_body)
        rec = build_tls_record(ContentType.HANDSHAKE, 0x0303, sh_msg)

        decoder = TLSHandshakeDecoder()
        decoder.process_s2c_record_bytes(rec)

        sh = decoder.summary.server_hello
        assert sh is not None
        assert sh.selected_version == 0x0304
        assert decoder.summary.cert_analysis_possible is False
        assert decoder.summary.certificates_der == []

    def test_tls_record_fragmentation_reassembly(self) -> None:
        """Handshake message split across 3 consecutive TLS records is assembled cleanly."""
        ch_msg = build_chrome_client_hello()
        assert len(ch_msg) > 60

        # Split into 3 parts
        part1 = ch_msg[:20]
        part2 = ch_msg[20:50]
        part3 = ch_msg[50:]

        rec1 = build_tls_record(ContentType.HANDSHAKE, 0x0301, part1)
        rec2 = build_tls_record(ContentType.HANDSHAKE, 0x0301, part2)
        rec3 = build_tls_record(ContentType.HANDSHAKE, 0x0301, part3)

        decoder = TLSHandshakeDecoder()
        decoder.process_c2s_record_bytes(rec1)
        decoder.process_c2s_record_bytes(rec2)
        decoder.process_c2s_record_bytes(rec3)

        assert decoder.summary.client_hello is not None
        assert decoder.summary.client_hello.server_name == "mail.example.com"

    def test_tls_alert_record_parsing(self) -> None:
        """Alert record (handshake failure 40) is decoded and logged."""
        alert_payload = b"\x02\x28"  # Fatal (2), handshake_failure (40)
        rec = build_tls_record(ContentType.ALERT, 0x0303, alert_payload)

        decoder = TLSHandshakeDecoder()
        decoder.process_s2c_record_bytes(rec)

        assert len(decoder.summary.alerts) == 1
        alert = decoder.summary.alerts[0]
        assert alert.level == 2
        assert alert.description == 40
        assert alert.description_name == "handshake_failure"

    def test_fuzz_smoke_ten_thousand_mutations_zero_crash(self) -> None:
        """Fuzz smoke: 10,000 random mutations of valid ClientHello must never crash."""
        valid_ch = build_chrome_client_hello()
        rng = random.Random(1337)

        for _ in range(10000):
            mutated = bytearray(valid_ch)
            mutation_type = rng.randint(0, 4)

            if mutation_type == 0:
                # Random byte substitution
                pos = rng.randint(0, len(mutated) - 1)
                mutated[pos] = rng.randint(0, 255)
            elif mutation_type == 1:
                # Truncation
                trunc_len = rng.randint(0, len(mutated))
                mutated = mutated[:trunc_len]
            elif mutation_type == 2:
                # Insertion of random bytes
                pos = rng.randint(0, len(mutated))
                insert_len = rng.randint(1, 30)
                mutated[pos:pos] = bytes(rng.randint(0, 255) for _ in range(insert_len))
            elif mutation_type == 3:
                # Bit flip
                pos = rng.randint(0, len(mutated) - 1)
                mutated[pos] ^= 1 << rng.randint(0, 7)
            else:
                # Length corruption (e.g. huge extension/cipher length)
                if len(mutated) > 40:
                    mutated[36] = 0xFF
                    mutated[37] = 0xFF

            rec = build_tls_record(ContentType.HANDSHAKE, 0x0301, bytes(mutated))
            decoder = TLSHandshakeDecoder()
            # Must never raise an uncaught exception
            decoder.process_c2s_record_bytes(rec)
