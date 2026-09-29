"""Unit tests for offline X.509 certificate chain validation, temporal correctness, and revocation."""

from __future__ import annotations

import datetime
import hashlib
import socket
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import NameOID

from pecff.crypto.chain_validator import OfflineChainValidator


@pytest.fixture(autouse=True)
def block_all_network_sockets(monkeypatch: pytest.MonkeyPatch) -> None:
    """Hard safety guarantee: Intercept and fail any attempt to open a network socket."""

    def guarded_socket(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError(
            "CRITICAL VIOLATION: Offline validator attempted network socket creation!"
        )

    monkeypatch.setattr(socket, "socket", guarded_socket)


def build_test_ca_and_leaf(
    leaf_valid_days: int = 30,
    backdate_days: int = 100,
) -> tuple[bytes, bytes, rsa.RSAPrivateKey, rsa.RSAPrivateKey]:
    """Helper to build a custom Root CA and issued leaf certificate."""
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    base_time = datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=backdate_days)

    ca_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "Test Enterprise Root CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Enterprise Test"),
        ]
    )

    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(1)
        .not_valid_before(base_time)
        .not_valid_after(base_time + datetime.timedelta(days=1000))
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

    leaf_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "mail.enterprise.local"),
        ]
    )

    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(2)
        .not_valid_before(base_time)
        .not_valid_after(base_time + datetime.timedelta(days=leaf_valid_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("mail.enterprise.local")]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    return (
        ca_cert.public_bytes(serialization.Encoding.DER),
        leaf_cert.public_bytes(serialization.Encoding.DER),
        ca_key,
        leaf_key,
    )


class TestOfflineChainValidator:
    """Test chain building, temporal correctness, and revocation mechanisms."""

    def test_temporal_correctness_historical_capture(self, tmp_path: Any) -> None:
        """A certificate that expired today but was valid at capture time must validate cleanly."""
        # Certificate was valid 100 days ago for 30 days (expired 70 days ago)
        ca_der, leaf_der, _, _ = build_test_ca_and_leaf(leaf_valid_days=30, backdate_days=100)

        # Write enterprise CA to temporary enterprise roots dir
        ent_dir = tmp_path / "enterprise_roots.d"
        ent_dir.mkdir(parents=True)
        (ent_dir / "test_ca.pem").write_bytes(
            x509.load_der_x509_certificate(ca_der).public_bytes(serialization.Encoding.PEM)
        )

        validator = OfflineChainValidator(enterprise_roots_dir=ent_dir)

        # Capture timestamp from 90 days ago (within validity window)
        historical_ts = (
            datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=90)
        ).timestamp()

        result = validator.validate_chain(
            chain_der=[leaf_der, ca_der],
            capture_timestamp=historical_ts,
        )

        assert result.is_valid is True
        assert result.chain_length == 2
        assert len(result.errors) == 0

        # Capture timestamp from today (expired)
        today_ts = datetime.datetime.now(datetime.UTC).timestamp()
        result_today = validator.validate_chain(
            chain_der=[leaf_der, ca_der],
            capture_timestamp=today_ts,
        )

        assert result_today.is_valid is False
        assert any(e.code == "CERT_EXPIRED" for e in result_today.errors)

    def test_self_signed_cert_flagged(self) -> None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.datetime.now(datetime.UTC)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "untrusted.selfsigned")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(1234)
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

    def test_unauthorized_ocsp_responder_finding(self) -> None:
        """OCSP response signed by an unauthorized third party produces OCSP_UNAUTHORIZED_RESPONDER."""
        ca_der, leaf_der, ca_key, _ = build_test_ca_and_leaf()
        unauthorized_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        now = datetime.datetime.now(datetime.UTC)
        leaf_cert = x509.load_der_x509_certificate(leaf_der)
        ca_cert = x509.load_der_x509_certificate(ca_der)

        # Build unauthorized responder cert (self-signed / not signed by CA)
        unauth_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Rogue OCSP Responder")])
        unauth_cert = (
            x509.CertificateBuilder()
            .subject_name(unauth_name)
            .issuer_name(unauth_name)
            .public_key(unauthorized_key.public_key())
            .serial_number(999)
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=10))
            .sign(unauthorized_key, hashes.SHA256())
        )

        builder = ocsp.OCSPResponseBuilder()
        builder = builder.add_response(
            cert=leaf_cert,
            issuer=ca_cert,
            algorithm=hashes.SHA256(),
            cert_status=ocsp.OCSPCertStatus.GOOD,
            this_update=now - datetime.timedelta(hours=1),
            next_update=now + datetime.timedelta(hours=24),
            revocation_time=None,
            revocation_reason=None,
        ).responder_id(ocsp.OCSPResponderEncoding.NAME, unauth_cert)

        ocsp_resp = builder.sign(unauthorized_key, hashes.SHA256())
        ocsp_der = ocsp_resp.public_bytes(serialization.Encoding.DER)

        validator = OfflineChainValidator()
        result = validator.validate_chain(
            chain_der=[leaf_der, ca_der],
            capture_timestamp=now.timestamp(),
            stapled_ocsp_der=ocsp_der,
        )

        assert result.ocsp_status == "UNAUTHORIZED"
        assert any(f.rule_id == "OCSP_UNAUTHORIZED_RESPONDER" for f in result.findings)

    def test_offline_crl_revocation_detection(self) -> None:
        """Offline CRL containing certificate serial number flags CRL_REVOKED."""
        ca_der, leaf_der, ca_key, _ = build_test_ca_and_leaf()
        now = datetime.datetime.now(datetime.UTC)
        ca_cert = x509.load_der_x509_certificate(ca_der)

        # Build CRL revoking serial number 2
        revoked_builder = (
            x509.RevokedCertificateBuilder()
            .serial_number(2)
            .revocation_date(now - datetime.timedelta(days=1))
            .build()
        )

        crl = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(ca_cert.subject)
            .last_update(now - datetime.timedelta(days=2))
            .next_update(now + datetime.timedelta(days=5))
            .add_revoked_certificate(revoked_builder)
            .sign(ca_key, hashes.SHA256())
        )
        crl_der = crl.public_bytes(serialization.Encoding.DER)

        # Add CRL DP to leaf cert
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        dp_url = "http://crl.enterprise.local/ca.crl"
        dp_hash = hashlib.sha256(dp_url.encode("utf-8")).hexdigest()

        leaf_with_crl = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mail.crl.local")]))
            .issuer_name(ca_cert.subject)
            .public_key(leaf_key.public_key())
            .serial_number(2)
            .not_valid_before(now - datetime.timedelta(days=5))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(
                x509.CRLDistributionPoints(
                    [
                        x509.DistributionPoint(
                            full_name=[x509.UniformResourceIdentifier(dp_url)],
                            relative_name=None,
                            reasons=None,
                            crl_issuer=None,
                        )
                    ]
                ),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )
        leaf_with_crl_der = leaf_with_crl.public_bytes(serialization.Encoding.DER)

        validator = OfflineChainValidator()
        result = validator.validate_chain(
            chain_der=[leaf_with_crl_der, ca_der],
            capture_timestamp=now.timestamp(),
            offline_crls={dp_hash: crl_der},
        )

        assert result.crl_status == "REVOKED"
        assert result.is_valid is False
        assert any(e.code == "CRL_REVOKED" for e in result.errors)
