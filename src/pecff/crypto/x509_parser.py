"""Hostile-input safe X.509 certificate parser with RFC 4514 compliance.

Provides strict parsing via `cryptography.x509` and robust lenient fallback
via `asn1crypto` for malformed or non-compliant certificates encountered
in network captures. Extract comprehensive cryptographic and X.509 extension
metadata with exact byte provenance.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import asn1crypto.x509
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, padding, rsa

from pecff.crypto.strength import ecc_security_bits, rsa_security_bits


@dataclass(slots=True)
class ParsedCertificate:
    """Forensic representation of an X.509 certificate."""

    fingerprint_sha256: str
    spki_sha256: str
    serial_number: str
    version: int
    subject_dn: str
    issuer_dn: str
    not_before: datetime
    not_after: datetime
    lifetime_days: int
    signature_algorithm_oid: str
    signature_hash: str | None
    public_key_algorithm: str
    public_key_bits: int
    ec_curve: str | None
    security_bits: int
    is_self_signed: bool
    san_dns: list[str] = field(default_factory=list)
    san_ip: list[str] = field(default_factory=list)
    basic_constraints: dict[str, Any] = field(default_factory=dict)
    key_usage: list[str] = field(default_factory=list)
    extended_key_usage: list[str] = field(default_factory=list)
    aia_ocsp: list[str] = field(default_factory=list)
    crl_dp: list[str] = field(default_factory=list)
    sct_count: int = 0
    parse_mode: str = "strict"  # "strict" or "lenient"
    parse_warnings: list[str] = field(default_factory=list)
    raw_der: bytes = b""


class X509Parser:
    """Hostile-input safe X.509 certificate parser with fallback decoding."""

    @classmethod
    def parse_der(cls, der_bytes: bytes) -> ParsedCertificate:
        """Parse DER-encoded X.509 certificate with automatic lenient fallback."""
        if not der_bytes:
            raise ValueError("Empty DER certificate bytes")

        fp_sha256 = hashlib.sha256(der_bytes).hexdigest()

        # ---------------------------------------------------------------------
        # Primary Strict Path (cryptography.x509)
        # ---------------------------------------------------------------------
        try:
            cert = x509.load_der_x509_certificate(der_bytes)
            return cls._extract_cryptography_cert(cert, der_bytes, fp_sha256)
        except Exception as strict_err:
            # -----------------------------------------------------------------
            # Fallback Lenient Path (asn1crypto)
            # -----------------------------------------------------------------
            warnings = [f"Strict parser failed: {strict_err}; using lenient fallback"]
            try:
                asn1_cert = asn1crypto.x509.Certificate.load(der_bytes)
                return cls._extract_asn1crypto_cert(asn1_cert, der_bytes, fp_sha256, warnings)
            except Exception as lenient_err:
                # If even asn1crypto fails, construct minimal stub with error record
                return cls._construct_corrupt_stub(
                    der_bytes, fp_sha256, [str(strict_err), str(lenient_err)]
                )

    @classmethod
    def _extract_cryptography_cert(
        cls,
        cert: x509.Certificate,
        der_bytes: bytes,
        fp_sha256: str,
    ) -> ParsedCertificate:
        """Extract fields using standard cryptography.x509 API."""
        warnings: list[str] = []

        # Serial & Version
        serial_hex = format(cert.serial_number, "X")
        version_num = cert.version.value + 1  # Version enum: v1=0, v3=2 -> RFC version 1, 3

        # DNs in RFC 4514 format
        subject_dn = cert.subject.rfc4514_string()
        issuer_dn = cert.issuer.rfc4514_string()

        # Validity
        try:
            not_before = cert.not_valid_before_utc
            not_after = cert.not_valid_after_utc
        except AttributeError:  # Older cryptography compatibility
            not_before = cert.not_valid_before.replace(tzinfo=UTC)
            not_after = cert.not_valid_after.replace(tzinfo=UTC)

        lifetime_days = max(0, (not_after - not_before).days)

        # Signature details
        sig_oid = cert.signature_algorithm_oid.dotted_string
        sig_hash: str | None = None
        if cert.signature_hash_algorithm:
            sig_hash = cert.signature_hash_algorithm.name.upper()

        # Public Key details
        pub_key = cert.public_key()
        spki_der = pub_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        spki_sha256 = hashlib.sha256(spki_der).hexdigest()

        pub_algo = "UNKNOWN"
        pub_bits = 0
        ec_curve: str | None = None
        sec_bits = 0

        if isinstance(pub_key, rsa.RSAPublicKey):
            pub_algo = "RSA"
            pub_bits = pub_key.key_size
            sec_bits = rsa_security_bits(pub_bits)
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            pub_algo = "EC"
            pub_bits = pub_key.key_size
            ec_curve = pub_key.curve.name
            sec_bits = ecc_security_bits(pub_bits)
        elif isinstance(pub_key, dsa.DSAPublicKey):
            pub_algo = "DSA"
            pub_bits = pub_key.key_size
            sec_bits = rsa_security_bits(pub_bits)
        elif isinstance(pub_key, ed25519.Ed25519PublicKey):
            pub_algo = "Ed25519"
            pub_bits = 256
            sec_bits = 128
        elif isinstance(pub_key, ed448.Ed448PublicKey):
            pub_algo = "Ed448"
            pub_bits = 448
            sec_bits = 224

        # Extensions
        san_dns: list[str] = []
        san_ip: list[str] = []
        basic_constraints: dict[str, Any] = {"ca": False, "path_length": None}
        key_usage: list[str] = []
        ext_key_usage: list[str] = []
        aia_ocsp: list[str] = []
        crl_dp: list[str] = []
        sct_count = 0

        for ext in cert.extensions:
            oid_str = ext.oid.dotted_string
            val = ext.value

            if isinstance(val, x509.SubjectAlternativeName):
                for name in val:
                    if isinstance(name, x509.DNSName):
                        san_dns.append(name.value)
                    elif isinstance(name, x509.IPAddress):
                        san_ip.append(str(name.value))
            elif isinstance(val, x509.BasicConstraints):
                basic_constraints = {"ca": val.ca, "path_length": val.path_length}
            elif isinstance(val, x509.KeyUsage):
                ku_flags = [
                    "digital_signature",
                    "content_commitment",
                    "key_encipherment",
                    "data_encipherment",
                    "key_agreement",
                    "key_cert_sign",
                    "crl_sign",
                ]
                for flag in ku_flags:
                    try:
                        if getattr(val, flag):
                            key_usage.append(flag)
                    except ValueError:
                        pass
            elif isinstance(val, x509.ExtendedKeyUsage):
                for usage_oid in val:
                    ext_key_usage.append(usage_oid.dotted_string)
            elif isinstance(val, x509.AuthorityInformationAccess):
                for desc in val:
                    if desc.access_method.dotted_string == "1.3.6.1.5.5.7.48.1" and isinstance(
                        desc.access_location, x509.UniformResourceIdentifier
                    ):
                        aia_ocsp.append(desc.access_location.value)
            elif isinstance(val, x509.CRLDistributionPoints):
                for dp in val:
                    if dp.full_name:
                        for name in dp.full_name:
                            if isinstance(name, x509.UniformResourceIdentifier):
                                crl_dp.append(name.value)
            elif oid_str == "1.3.6.1.4.1.11129.2.4.2":  # Embedded SCT list (RFC 6962)
                # Count SCTs if raw extension bytes present
                raw_ext = ext.value
                if hasattr(raw_ext, "value"):
                    # First 2 bytes = length of SCT list
                    sct_bytes = getattr(raw_ext, "value", b"")
                    if len(sct_bytes) >= 2:
                        sct_count = max(1, len(sct_bytes) // 100)
                else:
                    sct_count = 1

        # Check self-signed (both subject == issuer AND signature verifies)
        is_self_signed = False
        if cert.subject == cert.issuer:
            is_self_signed = cls._verify_self_signature(cert)

        return ParsedCertificate(
            fingerprint_sha256=fp_sha256,
            spki_sha256=spki_sha256,
            serial_number=serial_hex,
            version=version_num,
            subject_dn=subject_dn,
            issuer_dn=issuer_dn,
            not_before=not_before,
            not_after=not_after,
            lifetime_days=lifetime_days,
            signature_algorithm_oid=sig_oid,
            signature_hash=sig_hash,
            public_key_algorithm=pub_algo,
            public_key_bits=pub_bits,
            ec_curve=ec_curve,
            security_bits=sec_bits,
            is_self_signed=is_self_signed,
            san_dns=san_dns,
            san_ip=san_ip,
            basic_constraints=basic_constraints,
            key_usage=key_usage,
            extended_key_usage=ext_key_usage,
            aia_ocsp=aia_ocsp,
            crl_dp=crl_dp,
            sct_count=sct_count,
            parse_mode="strict",
            parse_warnings=warnings,
            raw_der=der_bytes,
        )

    @classmethod
    def _verify_self_signature(cls, cert: x509.Certificate) -> bool:
        """Verify that certificate was self-signed using its own public key."""
        try:
            pub_key = cert.public_key()
            if isinstance(pub_key, rsa.RSAPublicKey):
                hash_algo = cert.signature_hash_algorithm
                if hash_algo is None:
                    return False
                pub_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    hash_algo,
                )
                return True
            elif isinstance(pub_key, ec.EllipticCurvePublicKey):
                hash_algo = cert.signature_hash_algorithm
                if hash_algo is None:
                    return False
                pub_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    ec.ECDSA(hash_algo),
                )
                return True
            elif isinstance(pub_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
                pub_key.verify(cert.signature, cert.tbs_certificate_bytes)
                return True
            elif isinstance(pub_key, dsa.DSAPublicKey):
                hash_algo = cert.signature_hash_algorithm
                if hash_algo is None:
                    return False
                pub_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    hash_algo,
                )
                return True
        except (InvalidSignature, Exception):
            return False
        return False

    @classmethod
    def _extract_asn1crypto_cert(
        cls,
        cert: asn1crypto.x509.Certificate,
        der_bytes: bytes,
        fp_sha256: str,
        warnings: list[str],
    ) -> ParsedCertificate:
        """Lenient parsing fallback via asn1crypto for non-standard certificates."""
        tbs = cert["tbs_certificate"]

        # Serial & Version
        serial_hex = format(tbs["serial_number"].native, "X")
        version_num = tbs["version"].native if "version" in tbs else 1

        # Subject & Issuer RFC 4514
        subject_dn = tbs["subject"].human_friendly
        issuer_dn = tbs["issuer"].human_friendly

        # Validity
        validity = tbs["validity"]
        not_before = validity["not_before"].native
        not_after = validity["not_after"].native
        if not_before.tzinfo is None:
            not_before = not_before.replace(tzinfo=UTC)
        if not_after.tzinfo is None:
            not_after = not_after.replace(tzinfo=UTC)

        lifetime_days = max(0, (not_after - not_before).days)

        # Signature details
        sig_algo = tbs["signature"]
        sig_oid = sig_algo["algorithm"].dotted
        sig_algo_name = sig_algo["algorithm"].native or ""
        sig_hash: str | None = None
        if "sha256" in sig_algo_name:
            sig_hash = "SHA256"
        elif "sha384" in sig_algo_name:
            sig_hash = "SHA384"
        elif "sha512" in sig_algo_name:
            sig_hash = "SHA512"
        elif "sha1" in sig_algo_name:
            sig_hash = "SHA1"
        elif "md5" in sig_algo_name:
            sig_hash = "MD5"

        # Public Key
        spki = tbs["subject_public_key_info"]
        spki_der = spki.dump()
        spki_sha256 = hashlib.sha256(spki_der).hexdigest()
        pub_algo_name = spki.algorithm.upper()
        pub_bits = spki.bit_size or 0
        ec_curve = spki.curve or None

        if "RSA" in pub_algo_name:
            pub_algo = "RSA"
            sec_bits = rsa_security_bits(pub_bits)
        elif "EC" in pub_algo_name or "ELLIPTIC" in pub_algo_name:
            pub_algo = "EC"
            sec_bits = ecc_security_bits(pub_bits)
        else:
            pub_algo = pub_algo_name
            sec_bits = max(0, pub_bits // 2)

        # Extensions
        san_dns: list[str] = []
        san_ip: list[str] = []
        basic_constraints: dict[str, Any] = {"ca": False, "path_length": None}
        key_usage: list[str] = []
        ext_key_usage: list[str] = []
        aia_ocsp: list[str] = []
        crl_dp: list[str] = []
        sct_count = 0

        for ext in tbs["extensions"]:
            name = ext["extn_id"].native
            val = ext["extn_value"].parsed

            if name == "subject_alt_name" and val:
                for item in val:
                    if item.name == "dns_name":
                        san_dns.append(item.native)
                    elif item.name == "ip_address":
                        san_ip.append(item.native)
            elif name == "basic_constraints" and val:
                basic_constraints = {
                    "ca": bool(val["ca"].native),
                    "path_length": val["path_len_constraint"].native
                    if "path_len_constraint" in val
                    else None,
                }
            elif name == "key_usage" and val:
                key_usage = list(val.native)
            elif name == "extended_key_usage" and val:
                ext_key_usage = [item.dotted for item in val]
            elif name == "authority_information_access" and val:
                for desc in val:
                    if desc["access_method"].native == "ocsp":
                        aia_ocsp.append(desc["access_location"].native)
            elif name == "crl_distribution_points" and val:
                for dp in val:
                    fn = dp["distribution_point"]
                    if fn:
                        for entry in fn.chosen:
                            if isinstance(entry.native, str):
                                crl_dp.append(entry.native)
            elif ext["extn_id"].dotted == "1.3.6.1.4.1.11129.2.4.2":
                sct_count = 1

        is_self_signed = subject_dn == issuer_dn

        return ParsedCertificate(
            fingerprint_sha256=fp_sha256,
            spki_sha256=spki_sha256,
            serial_number=serial_hex,
            version=version_num,
            subject_dn=subject_dn,
            issuer_dn=issuer_dn,
            not_before=not_before,
            not_after=not_after,
            lifetime_days=lifetime_days,
            signature_algorithm_oid=sig_oid,
            signature_hash=sig_hash,
            public_key_algorithm=pub_algo,
            public_key_bits=pub_bits,
            ec_curve=ec_curve,
            security_bits=sec_bits,
            is_self_signed=is_self_signed,
            san_dns=san_dns,
            san_ip=san_ip,
            basic_constraints=basic_constraints,
            key_usage=key_usage,
            extended_key_usage=ext_key_usage,
            aia_ocsp=aia_ocsp,
            crl_dp=crl_dp,
            sct_count=sct_count,
            parse_mode="lenient",
            parse_warnings=warnings,
            raw_der=der_bytes,
        )

    @classmethod
    def _construct_corrupt_stub(
        cls,
        der_bytes: bytes,
        fp_sha256: str,
        errors: list[str],
    ) -> ParsedCertificate:
        """Construct safe fallback object for completely unparseable certificate blobs."""
        now = datetime.fromtimestamp(0.0, UTC)
        return ParsedCertificate(
            fingerprint_sha256=fp_sha256,
            spki_sha256=hashlib.sha256(der_bytes).hexdigest(),
            serial_number="UNKNOWN",
            version=0,
            subject_dn="CN=CORRUPT_CERTIFICATE",
            issuer_dn="CN=CORRUPT_CERTIFICATE",
            not_before=now,
            not_after=now,
            lifetime_days=0,
            signature_algorithm_oid="0.0.0",
            signature_hash=None,
            public_key_algorithm="UNKNOWN",
            public_key_bits=0,
            ec_curve=None,
            security_bits=0,
            is_self_signed=False,
            parse_mode="corrupt",
            parse_warnings=[f"Certificate parsing failed completely: {err}" for err in errors],
            raw_der=der_bytes,
        )
