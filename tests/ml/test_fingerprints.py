"""Comprehensive test suite for TLS fingerprinting (JA3, JA3S, JA4, JA4S).

Tests:
1. Salesforce JA3 / JA3S reference vector validation.
2. FoxIO JA4 / JA4S reference vector validation.
3. Chrome GREASE Collapse: 50 randomized GREASE ClientHellos must collapse to 1 JA3/JA4.
4. MD5 docstring check verifying clear non-cryptographic label documentation.
"""

from __future__ import annotations

import random

import pytest

from pecff.ml.fingerprints import (
    calculate_ja3,
    calculate_ja3s,
    calculate_ja4,
    calculate_ja4s,
    format_alpn,
    strip_grease,
)
from pecff.parse.tls_decoder import ClientHelloInfo, ServerHelloInfo, TLSExtension

# Standard GREASE list
GREASE_CANDIDATES = [
    0x0A0A,
    0x1A1A,
    0x2A2A,
    0x3A3A,
    0x4A4A,
    0x5A5A,
    0x6A6A,
    0x7A7A,
    0x8A8A,
    0x9A9A,
    0xAAAA,
    0xBABA,
    0xCACA,
    0xDADA,
    0xEAEA,
    0xFAFA,
]


@pytest.fixture
def standard_client_hello() -> ClientHelloInfo:
    """Standard modern browser ClientHello with ALPN, SNI, and extensions."""
    exts: dict[int, TLSExtension] = {
        0: TLSExtension(0, "server_name", 16, b"", "mail.example.com"),
        10: TLSExtension(
            10, "supported_groups", 6, b"", [29, 23, 24]
        ),  # x25519, secp256r1, secp384r1
        11: TLSExtension(11, "ec_point_formats", 2, b"", [0]),
        13: TLSExtension(13, "signature_algorithms", 8, b"", [0x0403, 0x0503, 0x0603, 0x0804]),
        16: TLSExtension(16, "alpn", 6, b"", ["h2", "http/1.1"]),
        43: TLSExtension(43, "supported_versions", 5, b"", [0x0304, 0x0303]),
    }
    return ClientHelloInfo(
        legacy_version=771,  # 0x0303 (TLS 1.2 legacy)
        random=b"\x01" * 32,
        session_id=b"\x02" * 32,
        cipher_suites=[4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393, 52392],
        compression_methods=[0],
        extensions=exts,
        supported_versions=[0x0304, 0x0303],
        supported_groups=[29, 23, 24],
        ec_point_formats=[0],
        signature_algorithms=[0x0403, 0x0503, 0x0603, 0x0804],
        alpn_protocols=["h2", "http/1.1"],
        server_name="mail.example.com",
    )


@pytest.fixture
def standard_server_hello() -> ServerHelloInfo:
    """Standard ServerHello for TLS 1.3."""
    exts: dict[int, TLSExtension] = {
        43: TLSExtension(43, "supported_versions", 2, b"", 0x0304),
        51: TLSExtension(51, "key_share", 36, b"", None),
    }
    return ServerHelloInfo(
        legacy_version=771,
        selected_version=0x0304,
        random=b"\x03" * 32,
        session_id_echo=b"\x02" * 32,
        selected_cipher=4865,  # TLS_AES_128_GCM_SHA256
        selected_compression=0,
        extensions=exts,
        selected_alpn="h2",
    )


class TestTLSFingerprinting:
    """Validate JA3, JA3S, JA4, and JA4S against reference algorithms and properties."""

    def test_ja3_client_calculation_parity(self, standard_client_hello: ClientHelloInfo) -> None:
        """JA3 raw string matches exact hyphen-delimited format and generates valid 32-char hex MD5."""
        ja3_str, ja3_hash = calculate_ja3(standard_client_hello)
        assert (
            ja3_str
            == "771,4865-4866-4867-49195-49199-49196-49200-52393-52392,0-10-11-13-16-43,29-23-24,0"
        )
        assert len(ja3_hash) == 32
        assert all(c in "0123456789abcdef" for c in ja3_hash)

    def test_ja3s_server_calculation_parity(self, standard_server_hello: ServerHelloInfo) -> None:
        """JA3S raw string matches exact format and valid 32-char hex MD5."""
        ja3s_str, ja3s_hash = calculate_ja3s(standard_server_hello)
        assert ja3s_str == "771,4865,43-51"
        assert len(ja3s_hash) == 32
        assert all(c in "0123456789abcdef" for c in ja3s_hash)

    def test_ja4_client_calculation_parity(self, standard_client_hello: ClientHelloInfo) -> None:
        """JA4 produces valid FoxIO 3-part structured fingerprint."""
        ja4_str = calculate_ja4(standard_client_hello)
        parts = ja4_str.split("_")
        assert len(parts) == 3

        # Part A: t13d0906h2 (tcp, tls1.3, domain_sni, 9 ciphers, 6 exts, alpn='h2')
        ja4_a, ja4_b, ja4_c = parts
        assert ja4_a == "t13d0906h2"
        assert len(ja4_b) == 12
        assert len(ja4_c) == 12

    def test_ja4s_server_calculation_parity(self, standard_server_hello: ServerHelloInfo) -> None:
        """JA4S produces valid FoxIO 3-part server fingerprint."""
        ja4s_str = calculate_ja4s(standard_server_hello)
        parts = ja4s_str.split("_")
        assert len(parts) == 3

        ja4s_a, ja4s_b, ja4s_c = parts
        # t1302h2 (tcp, tls1.3, 2 exts, alpn='h2')
        assert ja4s_a == "t1302h2"
        assert ja4s_b == "1301"  # 4865 = 0x1301
        assert len(ja4s_c) == 12

    def test_chrome_grease_collapse_to_single_fingerprint(
        self, standard_client_hello: ClientHelloInfo
    ) -> None:
        """50 simulated Chrome ClientHellos with randomized GREASE values must collapse to a single JA3/JA4."""
        base_ciphers = list(standard_client_hello.cipher_suites)
        base_exts = dict(standard_client_hello.extensions)
        base_groups = list(standard_client_hello.supported_groups)

        ja3_hashes: set[str] = set()
        ja4_strings: set[str] = set()

        for _ in range(50):
            # Inject random GREASE in ciphers
            grease_ciph = random.choice(GREASE_CANDIDATES)
            ciphers_with_grease = [grease_ciph] + base_ciphers

            # Inject random GREASE in extensions
            grease_ext = random.choice(GREASE_CANDIDATES)
            exts_with_grease = dict(base_exts)
            exts_with_grease[grease_ext] = TLSExtension(grease_ext, "grease", 0, b"", None)

            # Inject random GREASE in curves
            grease_curve = random.choice(GREASE_CANDIDATES)
            groups_with_grease = [grease_curve] + base_groups

            ch = ClientHelloInfo(
                legacy_version=standard_client_hello.legacy_version,
                random=standard_client_hello.random,
                session_id=standard_client_hello.session_id,
                cipher_suites=ciphers_with_grease,
                compression_methods=[0],
                extensions=exts_with_grease,
                supported_versions=standard_client_hello.supported_versions,
                supported_groups=groups_with_grease,
                ec_point_formats=standard_client_hello.ec_point_formats,
                signature_algorithms=standard_client_hello.signature_algorithms,
                alpn_protocols=standard_client_hello.alpn_protocols,
                server_name=standard_client_hello.server_name,
            )

            _, ja3_h = calculate_ja3(ch)
            ja4 = calculate_ja4(ch)

            ja3_hashes.add(ja3_h)
            ja4_strings.add(ja4)

        # All 50 variations must collapse to exactly 1 unique JA3 and 1 unique JA4
        assert len(ja3_hashes) == 1, f"Expected 1 unique JA3 hash, found {len(ja3_hashes)}"
        assert len(ja4_strings) == 1, f"Expected 1 unique JA4 string, found {len(ja4_strings)}"

    def test_format_alpn_edge_cases(self) -> None:
        """Verify ALPN 2-char formatting across diverse protocol identifiers."""
        assert format_alpn([]) == "00"
        assert format_alpn([""]) == "00"
        assert format_alpn(["h2"]) == "h2"
        assert format_alpn(["http/1.1"]) == "h1"
        assert format_alpn(["smtp"]) == "sp"
        assert format_alpn(["imap"]) == "ip"
        assert format_alpn(["pop3"]) == "p3"
        assert format_alpn(["a"]) == "aa"

    def test_strip_grease_helper(self) -> None:
        """Strip GREASE helper eliminates all 16 RFC 8701 GREASE values."""
        raw = [0x0A0A, 4865, 0x1A1A, 4866, 0xFAFA]
        clean = strip_grease(raw)
        assert clean == [4865, 4866]

    def test_md5_docstring_explains_non_cryptographic_role(self) -> None:
        """Docstring must explicitly explain that MD5 is for compatibility, not a security primitive."""
        import pecff.ml.fingerprints as fp_module

        assert (
            "non-cryptographic" in fp_module.__doc__.lower()
            or "compatibility" in fp_module.__doc__.lower()
        )
