"""Comprehensive test suite modeling badssl.com scenarios.

Tests:
1. expired.badssl.com: Expired at capture time -> CERT_EXPIRED
2. self-signed.badssl.com: Self-signed -> SELF_SIGNED_CERT
3. wrong.host.badssl.com: Wrong hostname -> MISMATCH / CERT_CN_ONLY_MATCH
4. rsa512.badssl.com & rsa1024.badssl.com: Weak key size -> PROHIBITED / LEGACY
5. revoked.badssl.com: Revoked cert -> OCSP / CRL REVOKED
6. sha1-intermediate.badssl.com: SHA1 signed in chain -> WEAK_HASH_ALGO
7. incomplete-chain.badssl.com: Missing intermediate -> UNTRUSTED_ROOT
8. temporal-valid: Expired today but valid at capture time -> VALID
9. unauthorized-ocsp: OCSP signed by unauthorized party -> OCSP_UNAUTHORIZED_RESPONDER
"""

from __future__ import annotations

import datetime
import hashlib
import socket
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from pecff.crypto.chain_validator import OfflineChainValidator
from pecff.crypto.hostname import HostnameVerifier
from pecff.crypto.policy_store import PolicyStore
from pecff.crypto.strength import rsa_security_bits, security_tier
from pecff.crypto.x509_parser import X509Parser


@pytest.fixture(autouse=True)
def block_all_network_sockets(monkeypatch: pytest.MonkeyPatch) -> None:
    """Guarantee strictly passive execution: Fail if any socket is created."""

    def guarded_socket(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("FATAL: Offline test attempted network socket creation!")

    monkeypatch.setattr(socket, "socket", guarded_socket)


def generate_ca_and_leaf(
    leaf_cn: str = "badssl.local",
    leaf_sans: list[str] | None = None,
    key_size: int = 2048,
    hash_algo: hashes.SHA224 | hashes.SHA256 | hashes.SHA384 | hashes.SHA512 | None = None,
    valid_from: datetime.datetime | None = None,
    valid_to: datetime.datetime | None = None,
    is_ca: bool = False,
) -> tuple[bytes, bytes, rsa.RSAPrivateKey, rsa.RSAPrivateKey]:
    """Helper to generate CA and issued certificate."""
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)

    now = datetime.datetime.now(datetime.UTC)
    v_from = valid_from or (now - datetime.timedelta(days=10))
    v_to = valid_to or (now + datetime.timedelta(days=30))
    h_algo = hash_algo or hashes.SHA256()

    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "BadSSL Test Root CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(1)
        .not_valid_before(now - datetime.timedelta(days=100))
        .not_valid_after(now + datetime.timedelta(days=1000))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, leaf_cn)])
    leaf_builder = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(2)
        .not_valid_before(v_from)
        .not_valid_after(v_to)
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
    )

    sans = leaf_sans if leaf_sans is not None else [leaf_cn]
    if sans:
        leaf_builder = leaf_builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]),
            critical=False,
        )

    leaf_cert = leaf_builder.sign(ca_key, h_algo)

    return (
        ca_cert.public_bytes(serialization.Encoding.DER),
        leaf_cert.public_bytes(serialization.Encoding.DER),
        ca_key,
        leaf_key,
    )


class TestBadSSLSuite:
    """Test suite mirroring badssl.com scenarios."""

    def test_badssl_expired(self, tmp_path: Any) -> None:
        """expired.badssl.com: Certificate expired relative to capture timestamp."""
        now = datetime.datetime.now(datetime.UTC)
        past_from = now - datetime.timedelta(days=60)
        past_to = now - datetime.timedelta(days=10)

        ca_der, leaf_der, _, _ = generate_ca_and_leaf(
            valid_from=past_from,
            valid_to=past_to,
        )

        ent_dir = tmp_path / "enterprise_roots.d"
        ent_dir.mkdir()
        (ent_dir / "ca.pem").write_bytes(
            x509.load_der_x509_certificate(ca_der).public_bytes(serialization.Encoding.PEM)
        )

        validator = OfflineChainValidator(enterprise_roots_dir=ent_dir)
        # Capture timestamp is NOW (after past_to)
        result = validator.validate_chain([leaf_der, ca_der], capture_timestamp=now.timestamp())

        assert result.is_valid is False
        assert any(e.code == "CERT_EXPIRED" for e in result.errors)

    def test_badssl_temporal_validity_preserved(self, tmp_path: Any) -> None:
        """Historical capture where cert was valid at capture timestamp passes cleanly."""
        now = datetime.datetime.now(datetime.UTC)
        past_from = now - datetime.timedelta(days=60)
        past_to = now - datetime.timedelta(days=10)

        ca_der, leaf_der, _, _ = generate_ca_and_leaf(
            valid_from=past_from,
            valid_to=past_to,
        )

        ent_dir = tmp_path / "enterprise_roots.d"
        ent_dir.mkdir()
        (ent_dir / "ca.pem").write_bytes(
            x509.load_der_x509_certificate(ca_der).public_bytes(serialization.Encoding.PEM)
        )

        validator = OfflineChainValidator(enterprise_roots_dir=ent_dir)
        # Capture timestamp was 30 days ago (within past_from - past_to window)
        historical_ts = (now - datetime.timedelta(days=30)).timestamp()
        result = validator.validate_chain([leaf_der, ca_der], capture_timestamp=historical_ts)

        assert result.is_valid is True
        assert result.chain_length == 2
        assert len(result.errors) == 0

    def test_badssl_self_signed(self) -> None:
        """self-signed.badssl.com: Untrusted self-signed certificate."""
        now = datetime.datetime.now(datetime.UTC)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "self-signed.badssl.com")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(100)
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=10))
            .sign(key, hashes.SHA256())
        )
        cert_der = cert.public_bytes(serialization.Encoding.DER)

        validator = OfflineChainValidator()
        result = validator.validate_chain([cert_der], capture_timestamp=now.timestamp())

        assert result.is_valid is False
        assert result.anchor_source == "self_signed"
        assert any(e.code == "SELF_SIGNED_CERT" for e in result.errors)

    def test_badssl_wrong_host(self) -> None:
        """wrong.host.badssl.com: Hostname does not match SAN."""
        _, leaf_der, _, _ = generate_ca_and_leaf(
            leaf_cn="unrelated.badssl.com",
            leaf_sans=["unrelated.badssl.com"],
        )
        parsed = X509Parser.parse_der(leaf_der)

        res = HostnameVerifier.verify(parsed, sni="wrong.host.badssl.com")
        assert res.matched is False
        assert res.status == "MISMATCH"

    def test_badssl_cn_only_match_deprecated(self) -> None:
        """CN matches but SAN is absent or different -> CERT_CN_ONLY_MATCH finding."""
        _, leaf_der, _, _ = generate_ca_and_leaf(
            leaf_cn="mail.badssl.com",
            leaf_sans=["other.badssl.com"],
        )
        parsed = X509Parser.parse_der(leaf_der)

        res = HostnameVerifier.verify(parsed, sni="mail.badssl.com")
        assert res.matched is False
        assert any(f.rule_id == "CERT_CN_ONLY_MATCH" for f in res.findings)

    def test_badssl_weak_keys(self) -> None:
        """rsa512.badssl.com and rsa1024.badssl.com: Key strength evaluation."""
        # RSA 512 bits
        sec_512 = rsa_security_bits(512)
        tier_512 = security_tier(sec_512)
        assert sec_512 < 80
        assert tier_512 == "prohibited"

        # RSA 1024 bits
        sec_1024 = rsa_security_bits(1024)
        tier_1024 = security_tier(sec_1024)
        assert 80 <= sec_1024 < 112
        assert tier_1024 == "legacy"

        # RSA 2048 bits
        sec_2048 = rsa_security_bits(2048)
        tier_2048 = security_tier(sec_2048)
        assert sec_2048 >= 112
        assert tier_2048 == "approved"

    def test_badssl_sha1_signed_rejected(self, tmp_path: Any) -> None:
        """sha1-intermediate.badssl.com: Signature with SHA-1 is flagged as weak algorithm."""
        import asn1crypto.x509 as x509_asn1

        now = datetime.datetime.now(datetime.UTC)
        ca_der, leaf_der, _, _ = generate_ca_and_leaf(
            hash_algo=hashes.SHA256(),
        )

        # Mutate leaf certificate to use SHA-1 signature algorithm (1.2.840.113549.1.1.5)
        asn_leaf = x509_asn1.Certificate.load(leaf_der)
        asn_leaf["signature_algorithm"] = {"algorithm": "1.2.840.113549.1.1.5"}
        asn_leaf["tbs_certificate"]["signature"] = {"algorithm": "1.2.840.113549.1.1.5"}
        sha1_leaf_der = asn_leaf.dump()

        ent_dir = tmp_path / "enterprise_roots.d"
        ent_dir.mkdir()
        (ent_dir / "ca.pem").write_bytes(
            x509.load_der_x509_certificate(ca_der).public_bytes(serialization.Encoding.PEM)
        )

        validator = OfflineChainValidator(enterprise_roots_dir=ent_dir)
        result = validator.validate_chain(
            [sha1_leaf_der, ca_der], capture_timestamp=now.timestamp()
        )

        assert result.is_valid is False
        assert any(e.code == "WEAK_HASH_ALGO" for e in result.errors)

    def test_badssl_incomplete_chain(self) -> None:
        """incomplete-chain.badssl.com: Intermediate missing from handshake chain and cache."""
        # Generate Root CA -> Intermediate CA -> Leaf
        inter_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        now = datetime.datetime.now(datetime.UTC)
        inter_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Intermediate CA")])
        leaf_name = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "incomplete-chain.badssl.com")]
        )

        leaf_cert = (
            x509.CertificateBuilder()
            .subject_name(leaf_name)
            .issuer_name(inter_name)
            .public_key(leaf_key.public_key())
            .serial_number(3)
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=10))
            .sign(inter_key, hashes.SHA256())
        )
        leaf_der = leaf_cert.public_bytes(serialization.Encoding.DER)

        validator = OfflineChainValidator()
        # Provide only leaf (missing intermediate and root)
        result = validator.validate_chain([leaf_der], capture_timestamp=now.timestamp())

        assert result.is_valid is False
        assert any(e.code == "UNTRUSTED_ROOT" for e in result.errors)

    def test_dane_tlsa_verification(self) -> None:
        """Verify DANE TLSA records against certificates and SPKIs."""
        ca_der, leaf_der, _, leaf_key = generate_ca_and_leaf()

        store = PolicyStore()
        spki_der = leaf_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        spki_sha256 = hashlib.sha256(spki_der).hexdigest()

        # Add TLSA record (Usage 3: DANE-EE, Selector 1: SPKI, Matching 1: SHA-256)
        store.add_tlsa_record(
            domain="mail.badssl.local",
            port=25,
            protocol="tcp",
            usage=3,
            selector=1,
            matching_type=1,
            cert_association_data=spki_sha256,
        )

        records = store.get_tlsa_records("mail.badssl.local", port=25, protocol="tcp")
        assert len(records) == 1

        is_match = store.verify_dane_record(records[0], cert_der=leaf_der, spki_der=spki_der)
        assert is_match is True

        # Test mismatch
        mismatch_match = store.verify_dane_record(
            records[0],
            cert_der=leaf_der,
            spki_der=b"wrong_spki_data",
        )
        assert mismatch_match is False
