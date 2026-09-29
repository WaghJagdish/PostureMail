"""Unit tests for X.509 certificate parsing and NIST SP 800-57 security strength calculation."""

from __future__ import annotations

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID

from pecff.crypto.strength import (
    ecc_security_bits,
    hash_security_bits,
    rsa_security_bits,
    snap_to_nist_tier,
)
from pecff.crypto.x509_parser import X509Parser


def generate_self_signed_cert_der(key_type: str = "rsa", key_size: int = 2048) -> bytes:
    """Generate self-signed X.509 certificate for testing."""
    now = datetime.datetime.now(datetime.UTC)
    private_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey

    if key_type == "rsa":
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    elif key_type == "ec":
        private_key = ec.generate_private_key(ec.SECP256R1())
    elif key_type == "ed25519":
        private_key = ed25519.Ed25519PrivateKey.generate()
    else:
        raise ValueError(f"Unknown key_type: {key_type}")

    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "mail.example.com"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Org"),
        ]
    )

    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("mail.example.com"),
                    x509.DNSName("smtp.example.com"),
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
    )

    if isinstance(private_key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
        cert = builder.sign(private_key, hashes.SHA256())
    else:
        cert = builder.sign(private_key, None)

    return cert.public_bytes(serialization.Encoding.DER)


class TestSecurityBitsStrength:
    """Validate NIST SP 800-57 Part 1 Table 2 snapping and GNFS approximation."""

    def test_rsa_security_tiers(self) -> None:
        assert rsa_security_bits(512) == 56
        assert rsa_security_bits(1024) == 80
        assert rsa_security_bits(2048) == 112
        assert rsa_security_bits(3072) == 128
        assert rsa_security_bits(4096) == 128
        assert rsa_security_bits(7680) == 192
        assert rsa_security_bits(15360) == 256

    def test_ecc_security_tiers(self) -> None:
        assert ecc_security_bits(256) == 128
        assert ecc_security_bits(384) == 192
        assert ecc_security_bits(521) == 256
        assert ecc_security_bits(160) == 80
        assert ecc_security_bits(128) == 64

    def test_hash_security_tiers(self) -> None:
        assert hash_security_bits("MD5") == 0
        assert hash_security_bits("SHA1") == 80
        assert hash_security_bits("SHA-256") == 128
        assert hash_security_bits("SHA-384") == 192
        assert hash_security_bits("SHA-512") == 256

    def test_snap_to_nist_tier(self) -> None:
        assert snap_to_nist_tier(115.4) == 112
        assert snap_to_nist_tier(130.0) == 128
        assert snap_to_nist_tier(200.0) == 192
        assert snap_to_nist_tier(75.0) == 75


class TestX509Parser:
    """Validate strict and lenient X.509 parsing paths."""

    def test_rsa_self_signed_cert_parsing(self) -> None:
        der = generate_self_signed_cert_der("rsa", 2048)
        parsed = X509Parser.parse_der(der)

        assert parsed.public_key_algorithm == "RSA"
        assert parsed.public_key_bits == 2048
        assert parsed.security_bits == 112
        assert parsed.is_self_signed is True
        assert "mail.example.com" in parsed.san_dns
        assert "smtp.example.com" in parsed.san_dns
        assert parsed.parse_mode == "strict"
        assert parsed.lifetime_days >= 364
        assert len(parsed.fingerprint_sha256) == 64
        assert len(parsed.spki_sha256) == 64

    def test_ec_self_signed_cert_parsing(self) -> None:
        der = generate_self_signed_cert_der("ec")
        parsed = X509Parser.parse_der(der)

        assert parsed.public_key_algorithm == "EC"
        assert parsed.public_key_bits == 256
        assert parsed.security_bits == 128
        assert parsed.is_self_signed is True
        assert parsed.parse_mode == "strict"

    def test_ed25519_cert_parsing(self) -> None:
        der = generate_self_signed_cert_der("ed25519")
        parsed = X509Parser.parse_der(der)

        assert parsed.public_key_algorithm == "Ed25519"
        assert parsed.public_key_bits == 256
        assert parsed.security_bits == 128
        assert parsed.is_self_signed is True

    def test_malformed_der_fallback_corpus(self) -> None:
        """Verify that 20 corrupt/mutated certificate blobs never throw unhandled exceptions."""
        valid_der = generate_self_signed_cert_der("rsa", 2048)

        for i in range(20):
            # Introduce byte corruptions, truncation, bit flips
            mutated = bytearray(valid_der)
            if i % 3 == 0:
                mutated = mutated[: len(mutated) // 2]  # Truncation
            elif i % 3 == 1:
                mutated[10:20] = b"\xff" * 10  # Corrupt ASN.1 headers
            else:
                mutated = mutated + b"EXTRA_GARBAGE_BYTES"

            parsed = X509Parser.parse_der(bytes(mutated))
            assert parsed is not None
            assert parsed.fingerprint_sha256 is not None
            assert parsed.parse_mode in ("strict", "lenient", "corrupt")
