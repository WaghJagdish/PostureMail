"""Unit tests for RFC 6125 hostname matching and wildcard matrix."""

from __future__ import annotations

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from pecff.crypto.hostname import (
    HostnameVerifier,
    match_wildcard_pattern,
)
from pecff.crypto.x509_parser import X509Parser


def create_cert_with_san_and_cn(
    san_dns: list[str],
    common_name: str = "example.com",
    san_ip: list[str] | None = None,
) -> bytes:
    """Helper to generate a test certificate with specific SAN entries and CN."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.UTC)

    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )

    san_items: list[x509.GeneralName] = [x509.DNSName(dns) for dns in san_dns]
    if san_ip:
        import ipaddress

        for ip_str in san_ip:
            san_items.append(x509.IPAddress(ipaddress.ip_address(ip_str)))

    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName(san_items),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    return cert.public_bytes(serialization.Encoding.DER)


class TestWildcardMatrixRFC6125:
    """Test comprehensive RFC 6125 wildcard matching matrix."""

    @pytest.mark.parametrize(
        ("pattern", "hostname", "expected"),
        [
            # 1. Standard valid single-level leftmost wildcard
            ("*.example.com", "foo.example.com", True),
            ("*.example.com", "bar.example.com", True),
            ("*.example.com", "mail.example.com", True),
            # 2. Bare apex rejection (RFC 6125 §6.4.3)
            ("*.example.com", "example.com", False),
            # 3. Multi-level subdomain rejection
            ("*.example.com", "sub.foo.example.com", False),
            ("*.example.com", "a.b.c.example.com", False),
            # 4. Partial wildcard rejection
            ("f*.example.com", "foo.example.com", False),
            ("*foo.example.com", "barfoo.example.com", False),
            ("foo*.example.com", "foobar.example.com", False),
            # 5. Non-leftmost wildcard rejection
            ("example.*.com", "example.foo.com", False),
            ("foo.*.example.com", "foo.bar.example.com", False),
            # 6. Public suffix / single label rejection
            ("*.com", "example.com", False),
            ("*.org", "wikipedia.org", False),
            ("*", "localhost", False),
            # 7. Case insensitivity and IDN
            ("*.EXAMPLE.COM", "foo.example.com", True),
            ("*.example.com", "FOO.EXAMPLE.COM", True),
            ("*.bücher.example.com", "xn--foo-11a.xn--bcher-kva.example.com", True),
        ],
    )
    def test_wildcard_cases(self, pattern: str, hostname: str, expected: bool) -> None:
        result = match_wildcard_pattern(pattern, hostname)
        assert result == expected


class TestHostnameVerifier:
    """Validate reference identifier prioritization and CN fallback findings."""

    def test_sni_match_priority(self) -> None:
        cert_der = create_cert_with_san_and_cn(
            san_dns=["mail.example.com", "smtp.example.com"],
            common_name="legacy.example.com",
        )
        cert = X509Parser.parse_der(cert_der)

        res = HostnameVerifier.verify(
            cert=cert,
            sni="mail.example.com",
            ehlo_domain="wrong.example.com",
        )
        assert res.matched is True
        assert res.status == "MATCH"
        assert res.method == "sni"
        assert res.matched_san == "mail.example.com"
        assert len(res.findings) == 0

    def test_ehlo_fallback_when_sni_absent(self) -> None:
        cert_der = create_cert_with_san_and_cn(san_dns=["smtp.target.org"])
        cert = X509Parser.parse_der(cert_der)

        res = HostnameVerifier.verify(
            cert=cert,
            sni=None,
            ehlo_domain="smtp.target.org",
        )
        assert res.matched is True
        assert res.method == "ehlo"
        assert res.status == "MATCH"

    def test_cn_only_match_emits_finding(self) -> None:
        """When CN matches but SAN does not, emit CERT_CN_ONLY_MATCH finding."""
        cert_der = create_cert_with_san_and_cn(
            san_dns=["other.example.com"],
            common_name="mail.example.com",
        )
        cert = X509Parser.parse_der(cert_der)

        res = HostnameVerifier.verify(cert=cert, sni="mail.example.com")
        assert res.matched is False
        assert res.status == "MISMATCH"
        assert any(f.rule_id == "CERT_CN_ONLY_MATCH" for f in res.findings)

    def test_indeterminate_when_no_identifier_provided(self) -> None:
        cert_der = create_cert_with_san_and_cn(san_dns=["mail.example.com"])
        cert = X509Parser.parse_der(cert_der)

        res = HostnameVerifier.verify(cert=cert, sni=None, ehlo_domain=None)
        assert res.matched is False
        assert res.status == "INDETERMINATE"
        assert res.method == "none"
