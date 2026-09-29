"""NIST SP 800-57 aligned pure deterministic cryptographic risk scoring engine.

Hard Constraints Enforced:
1. STRICTLY DETERMINISTIC & AUDITABLE: Pure functions, zero clock reads, zero I/O,
   zero randomness. Decimal arithmetic with exact ROUND_HALF_EVEN rounding.
2. VETO DOMINANCE: Categorical floors (e.g., NULL/EXPORT cipher, revoked cert,
   MD5 sig) set a minimum score floor that cannot be diluted by other components.
3. EFFECTIVE STRENGTH GATE: Minimum 112-bit security threshold across sym, kex,
   auth, and hash collision resistance (NIST SP 800-57 Part 1 Rev. 5, Table 2).
4. TLS 1.3 WEIGHT REDISTRIBUTION: Proportionally redistributes certificate weight
   (0.20) across remaining components when TLS 1.3 encrypts handshake certificates.
5. COMPLETE PROVENANCE: Every non-zero score is accompanied by granular evidence
   items referencing specific standards (NIST SP 800-52r2, RFCs, CA/B Forum).
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import ROUND_HALF_EVEN, Decimal
from typing import Final

from pecff.crypto.chain_validator import ChainValidationResult
from pecff.crypto.cipher_db import CipherDatabase, CipherSuiteInfo
from pecff.crypto.hostname import HostnameVerificationResult
from pecff.crypto.strength import ecc_security_bits, hash_security_bits, rsa_security_bits
from pecff.crypto.x509_parser import ParsedCertificate

# -----------------------------------------------------------------------------
# Base Component Weights (Must sum to 1.0000)
# -----------------------------------------------------------------------------
BASE_WEIGHTS: Final[dict[str, Decimal]] = {
    "protocol_version": Decimal("0.25"),
    "cipher_hash": Decimal("0.25"),
    "key_exchange": Decimal("0.20"),
    "certificate": Decimal("0.20"),
    "session_hygiene": Decimal("0.10"),
}

# TLS 1.3 Redistributed Weights (When C4 certificate is encrypted)
# 0.20 redistributed proportionally over (0.25 + 0.25 + 0.20 + 0.10 = 0.80)
# C1: 0.25 / 0.80 = 0.3125, C2: 0.25 / 0.80 = 0.3125, C3: 0.20 / 0.80 = 0.25, C5: 0.10 / 0.80 = 0.125
TLS13_REDISTRIBUTED_WEIGHTS: Final[dict[str, Decimal]] = {
    "protocol_version": Decimal("0.3125"),
    "cipher_hash": Decimal("0.3125"),
    "key_exchange": Decimal("0.2500"),
    "session_hygiene": Decimal("0.1250"),
}


@dataclass(frozen=True, slots=True)
class PenaltyRule:
    """Module-level frozen metadata for a risk penalty or veto."""

    rule_id: str
    penalty: int
    is_veto: bool
    standards_ref: str
    description: str


# -----------------------------------------------------------------------------
# Frozen Penalty Tables per Blueprint Specification
# -----------------------------------------------------------------------------
C1_RULES: Final[dict[str, PenaltyRule]] = {
    "no_tls_with_auth": PenaltyRule(
        rule_id="PROTO-NO-TLS-AUTH",
        penalty=100,
        is_veto=True,
        standards_ref="RFC 8314 §3",
        description="Cleartext email session observed with authentication credentials",
    ),
    "no_tls_plaintext": PenaltyRule(
        rule_id="PROTO-NO-TLS-PLAIN",
        penalty=100,
        is_veto=False,
        standards_ref="RFC 8314 §3",
        description="Cleartext unencrypted email session",
    ),
    "ssl2": PenaltyRule(
        rule_id="PROTO-SSL2",
        penalty=100,
        is_veto=True,
        standards_ref="RFC 6176",
        description="Prohibited SSLv2 protocol version negotiated",
    ),
    "ssl3": PenaltyRule(
        rule_id="PROTO-SSL3",
        penalty=100,
        is_veto=True,
        standards_ref="RFC 7568",
        description="Prohibited SSLv3 protocol version negotiated (POODLE vulnerable)",
    ),
    "tls10": PenaltyRule(
        rule_id="PROTO-TLS10",
        penalty=80,
        is_veto=False,
        standards_ref="RFC 8996",
        description="Deprecated TLS 1.0 protocol version negotiated",
    ),
    "tls11": PenaltyRule(
        rule_id="PROTO-TLS11",
        penalty=60,
        is_veto=False,
        standards_ref="RFC 8996",
        description="Deprecated TLS 1.1 protocol version negotiated",
    ),
    "tls12_legacy": PenaltyRule(
        rule_id="PROTO-TLS12-LEGACY",
        penalty=10,
        is_veto=False,
        standards_ref="NIST SP 800-52r2 §3.3.1",
        description="TLS 1.2 negotiated without AEAD or without Perfect Forward Secrecy",
    ),
    "unknown_version": PenaltyRule(
        rule_id="PROTO-UNKNOWN",
        penalty=70,
        is_veto=False,
        standards_ref="NIST SP 800-52r2",
        description="Unknown or unrecognized TLS protocol version",
    ),
}

C2_RULES: Final[dict[str, PenaltyRule]] = {
    "null_cipher": PenaltyRule(
        rule_id="CIPHER-NULL",
        penalty=100,
        is_veto=True,
        standards_ref="RFC 5246 App. A.5",
        description="Plaintext NULL encryption cipher suite negotiated",
    ),
    "export_cipher": PenaltyRule(
        rule_id="CIPHER-EXPORT",
        penalty=100,
        is_veto=True,
        standards_ref="RFC 2246 / FREAK",
        description="Weakened export-grade cipher suite negotiated",
    ),
    "anon_cipher": PenaltyRule(
        rule_id="CIPHER-ANON",
        penalty=100,
        is_veto=True,
        standards_ref="RFC 5246 §F.1.1",
        description="Anonymous unauthenticated key exchange cipher suite negotiated",
    ),
    "rc4": PenaltyRule(
        rule_id="CIPHER-RC4",
        penalty=95,
        is_veto=False,
        standards_ref="RFC 7465",
        description="Insecure RC4 stream cipher negotiated",
    ),
    "des": PenaltyRule(
        rule_id="CIPHER-DES",
        penalty=95,
        is_veto=False,
        standards_ref="NIST SP 800-131Ar2",
        description="Broken single DES cipher negotiated (56-bit key)",
    ),
    "3des": PenaltyRule(
        rule_id="CIPHER-3DES",
        penalty=70,
        is_veto=False,
        standards_ref="NIST SP 800-131Ar2 / Sweet32",
        description="Deprecated Triple-DES (3DES) 64-bit block cipher negotiated",
    ),
    "cbc_legacy": PenaltyRule(
        rule_id="CIPHER-CBC-LEGACY",
        penalty=25,
        is_veto=False,
        standards_ref="NIST SP 800-52r2 §3.3.1",
        description="Legacy block cipher negotiated (IDEA/SEED/Camellia-CBC)",
    ),
    "md5": PenaltyRule(
        rule_id="HASH-MD5",
        penalty=90,
        is_veto=False,
        standards_ref="RFC 6151",
        description="Broken MD5 hash function used for MAC or PRF",
    ),
    "sha1_mac": PenaltyRule(
        rule_id="HASH-SHA1-MAC",
        penalty=60,
        is_veto=False,
        standards_ref="NIST SP 800-52r2 §3.3.1",
        description="Legacy SHA-1 used for HMAC in non-AEAD cipher suite",
    ),
    "sha1_cert_sig": PenaltyRule(
        rule_id="HASH-SHA1-CERT",
        penalty=85,
        is_veto=False,
        standards_ref="NIST SP 800-52r2 §3.2",
        description="Certificate signed using weak SHA-1 algorithm",
    ),
    "cbc_no_etm": PenaltyRule(
        rule_id="CIPHER-CBC-NO-ETM",
        penalty=30,
        is_veto=False,
        standards_ref="RFC 7366 / Lucky13",
        description="CBC mode cipher used without Encrypt-then-MAC extension",
    ),
}

C3_RULES: Final[dict[str, PenaltyRule]] = {
    "static_rsa": PenaltyRule(
        rule_id="KEX-STATIC-RSA",
        penalty=75,
        is_veto=False,
        standards_ref="NIST SP 800-52r2 §3.3.1",
        description="Static RSA key transport without Perfect Forward Secrecy",
    ),
    "static_dh": PenaltyRule(
        rule_id="KEX-STATIC-DH",
        penalty=75,
        is_veto=False,
        standards_ref="NIST SP 800-52r2 §3.3.1",
        description="Static Diffie-Hellman key exchange without ephemeral keys",
    ),
    "dhe_logjam": PenaltyRule(
        rule_id="KEX-DHE-LOGJAM",
        penalty=100,
        is_veto=True,
        standards_ref="RFC 7919 / Logjam",
        description="Insecure Ephemeral Diffie-Hellman modulus p < 1024 bits",
    ),
    "dhe_weak": PenaltyRule(
        rule_id="KEX-DHE-WEAK",
        penalty=55,
        is_veto=False,
        standards_ref="NIST SP 800-57 Table 2",
        description="Weak Ephemeral Diffie-Hellman modulus 1024 <= p < 2048 bits",
    ),
    "dhe_2048": PenaltyRule(
        rule_id="KEX-DHE-2048",
        penalty=5,
        is_veto=False,
        standards_ref="NIST SP 800-52r2 §3.3.1",
        description="DHE with 2048-bit modulus (moderate computational cost)",
    ),
    "ecdhe_weak_curve": PenaltyRule(
        rule_id="KEX-ECDHE-WEAK-CURVE",
        penalty=70,
        is_veto=False,
        standards_ref="NIST SP 800-57 Table 2",
        description="Weak Elliptic Curve negotiated (secp192r1/secp224r1 < 256 bits)",
    ),
    "ecdhe_unknown_curve": PenaltyRule(
        rule_id="KEX-ECDHE-UNKNOWN-CURVE",
        penalty=35,
        is_veto=False,
        standards_ref="NIST SP 800-52r2 §3.3.1",
        description="Non-standard or unrecognized named curve for ECDHE",
    ),
}

C4_RULES: Final[dict[str, PenaltyRule]] = {
    "cert_expired": PenaltyRule(
        rule_id="CERT-EXPIRED",
        penalty=70,
        is_veto=False,
        standards_ref="RFC 5280 §4.1.2.5",
        description="Certificate was expired at network capture timestamp",
    ),
    "cert_not_yet_valid": PenaltyRule(
        rule_id="CERT-NOT-YET-VALID",
        penalty=70,
        is_veto=False,
        standards_ref="RFC 5280 §4.1.2.5",
        description="Certificate was not yet valid at network capture timestamp",
    ),
    "self_signed_untrusted": PenaltyRule(
        rule_id="CERT-SELF-SIGNED",
        penalty=65,
        is_veto=False,
        standards_ref="RFC 5280",
        description="Untrusted self-signed leaf certificate",
    ),
    "chain_untrusted": PenaltyRule(
        rule_id="CERT-UNTRUSTED-CHAIN",
        penalty=75,
        is_veto=False,
        standards_ref="RFC 5280 §6.1",
        description="Certificate chain failed path building against trusted anchors",
    ),
    "hostname_mismatch": PenaltyRule(
        rule_id="CERT-HOSTNAME-MISMATCH",
        penalty=80,
        is_veto=False,
        standards_ref="RFC 6125 §6.4.3",
        description="Certificate Subject Alternative Name does not match reference hostname",
    ),
    "rsa_weak_512": PenaltyRule(
        rule_id="CERT-RSA-512",
        penalty=100,
        is_veto=True,
        standards_ref="NIST SP 800-57 Table 2",
        description="Critically weak RSA public key size (< 1024 bits)",
    ),
    "rsa_weak_1024": PenaltyRule(
        rule_id="CERT-RSA-1024",
        penalty=85,
        is_veto=False,
        standards_ref="NIST SP 800-57 Table 2",
        description="Weak RSA public key size (1024 <= bits < 2048)",
    ),
    "ecdsa_weak": PenaltyRule(
        rule_id="CERT-ECDSA-WEAK",
        penalty=90,
        is_veto=False,
        standards_ref="NIST SP 800-57 Table 2",
        description="Weak ECDSA public key curve (< 224 bits)",
    ),
    "md5_sig": PenaltyRule(
        rule_id="CERT-SIG-MD5",
        penalty=100,
        is_veto=True,
        standards_ref="RFC 6151",
        description="Certificate signed using cryptographically broken MD5 hash",
    ),
    "sha1_sig": PenaltyRule(
        rule_id="CERT-SIG-SHA1",
        penalty=85,
        is_veto=False,
        standards_ref="NIST SP 800-52r2 §3.2",
        description="Certificate signed using deprecated SHA-1 signature algorithm",
    ),
    "revoked": PenaltyRule(
        rule_id="CERT-REVOKED",
        penalty=100,
        is_veto=True,
        standards_ref="RFC 5280 §6.3",
        description="Certificate is explicitly revoked according to offline OCSP/CRL",
    ),
    "revocation_unknown": PenaltyRule(
        rule_id="CERT-REVOCATION-UNKNOWN",
        penalty=10,
        is_veto=False,
        standards_ref="RFC 6960 / RFC 5280",
        description="Revocation status could not be verified offline (soft penalty)",
    ),
    "lifetime_398": PenaltyRule(
        rule_id="CERT-LIFETIME-398",
        penalty=20,
        is_veto=False,
        standards_ref="CA/Browser Forum BR 1.8.0",
        description="Certificate validity period exceeds 398 days",
    ),
    "lifetime_825": PenaltyRule(
        rule_id="CERT-LIFETIME-825",
        penalty=35,
        is_veto=False,
        standards_ref="CA/Browser Forum BR 1.6.0",
        description="Certificate validity period exceeds 825 days",
    ),
    "ca_no_basic_constraints": PenaltyRule(
        rule_id="CERT-CA-NO-BC",
        penalty=50,
        is_veto=False,
        standards_ref="RFC 5280 §4.2.1.9",
        description="CA certificate in chain missing basicConstraints extension",
    ),
    "no_san": PenaltyRule(
        rule_id="CERT-NO-SAN",
        penalty=25,
        is_veto=False,
        standards_ref="RFC 6125 §6.4.4",
        description="Certificate missing Subject Alternative Name (SAN) extension",
    ),
    "no_sct": PenaltyRule(
        rule_id="CERT-NO-SCT",
        penalty=8,
        is_veto=False,
        standards_ref="RFC 6962 §3.3",
        description="No Certificate Transparency SCT timestamps found in certificate",
    ),
    "compromised_key": PenaltyRule(
        rule_id="CERT-COMPROMISED-KEY",
        penalty=100,
        is_veto=True,
        standards_ref="NIST SP 800-57 Part 1",
        description="Certificate public key matches known compromised or debian weak key list",
    ),
}

C5_RULES: Final[dict[str, PenaltyRule]] = {
    "reneg_insecure": PenaltyRule(
        rule_id="HYGIENE-INSECURE-RENEG",
        penalty=60,
        is_veto=False,
        standards_ref="RFC 5746",
        description="Renegotiation supported without RFC 5746 secure renegotiation indication",
    ),
    "no_ems": PenaltyRule(
        rule_id="HYGIENE-NO-EMS",
        penalty=25,
        is_veto=False,
        standards_ref="RFC 7627",
        description="TLS 1.2 connection negotiated without Extended Master Secret extension",
    ),
    "compression": PenaltyRule(
        rule_id="HYGIENE-COMPRESSION-CRIME",
        penalty=80,
        is_veto=False,
        standards_ref="RFC 7525 §3.3 / CRIME",
        description="TLS record compression enabled (vulnerable to CRIME attack)",
    ),
    "long_ticket": PenaltyRule(
        rule_id="HYGIENE-LONG-TICKET",
        penalty=20,
        is_veto=False,
        standards_ref="RFC 8446 §4.6.1",
        description="Session ticket lifetime exceeds 7 days (604,800 seconds)",
    ),
    "zero_rtt_submission": PenaltyRule(
        rule_id="HYGIENE-0RTT-SUBMISSION",
        penalty=30,
        is_veto=False,
        standards_ref="RFC 8446 §E.5",
        description="TLS 1.3 0-RTT early data enabled on credential submission port",
    ),
    "incomplete_handshake": PenaltyRule(
        rule_id="HYGIENE-INCOMPLETE-HANDSHAKE",
        penalty=15,
        is_veto=False,
        standards_ref="PECFF Operational Metric",
        description="TLS handshake initiated but never completed by endpoints",
    ),
}

RULE_MIN_STRENGTH: Final[PenaltyRule] = PenaltyRule(
    rule_id="NIST-MIN-STRENGTH",
    penalty=90,
    is_veto=True,
    standards_ref="NIST SP 800-57 Part 1 Rev. 5, Table 2 (112-bit minimum through 2030)",
    description="Effective cryptographic security strength < 112 bits",
)


@dataclass(frozen=True, slots=True)
class ProvenanceItem:
    """Individual auditable penalty evidence item."""

    component: str  # "protocol_version", "cipher_hash", "key_exchange", "certificate", "session_hygiene", "strength_gate"
    rule_id: str
    penalty: int
    evidence: str
    nist_reference: str


@dataclass(frozen=True, slots=True)
class VetoFinding:
    """Categorical floor veto item."""

    rule_id: str
    floor_score: int
    evidence: str
    nist_reference: str


@dataclass(frozen=True, slots=True)
class RiskResult:
    """Comprehensive forensic outcome of NIST SP 800-57 risk scoring."""

    score: int  # 0 to 100
    band: str  # "SECURE", "ACCEPTABLE", "WEAK", "HIGH", "CRITICAL"
    context_multiplier: float  # 1.0, 1.15, 1.25
    component_scores: dict[str, int]  # Raw penalty per component (0-100)
    component_weights: dict[str, float]  # Applied weights (sum = 1.0)
    vetoes: list[VetoFinding]
    effective_security_bits: int
    weight_redistributed: bool
    provenance: list[ProvenanceItem]


@dataclass(slots=True)
class SessionCryptoParameters:
    """Forensic cryptographic parameters extracted from a reconstructed mail session."""

    # Protocol & Context
    protocol_version: str = (
        "TLS 1.3"  # "TLS 1.3", "TLS 1.2", "TLS 1.1", "TLS 1.0", "SSL 3.0", "SSL 2.0", "NONE"
    )
    dst_port: int = 25
    has_auth: bool = False
    cleartext_credentials_observed: bool = False
    handshake_completed: bool = True
    cert_analysis_possible: bool = True

    # Cipher & Hash
    cipher_id: str | None = None  # e.g. "0x1301", "0xC02F", "0x0001"
    cipher_info: CipherSuiteInfo | None = None
    encrypt_then_mac: bool = False
    extended_master_secret: bool = False
    secure_renegotiation: bool = True
    compression_method: int = 0
    ticket_lifetime_seconds: int | None = None
    zero_rtt_used: bool = False

    # Key Exchange
    kex_algorithm: str = "ECDHE"  # "ECDHE", "DHE", "RSA", "DH", "NONE"
    named_group: str | None = "x25519"  # e.g., "x25519", "secp256r1", "ffdhe2048", "secp192r1"
    dh_key_bits: int | None = None
    ec_curve: str | None = "x25519"
    ec_bits: int | None = 256

    # Certificate & Trust Validation
    leaf_certificate: ParsedCertificate | None = None
    chain_validation_result: ChainValidationResult | None = None
    hostname_verification_result: HostnameVerificationResult | None = None
    known_compromised_spki: bool = False


class NISTDeterministicRiskScorer:
    """Pure, deterministic NIST SP 800-57 risk engine."""

    def __init__(self, cipher_db: CipherDatabase | None = None) -> None:
        self.cipher_db = cipher_db or CipherDatabase()

    def score_session(self, params: SessionCryptoParameters) -> RiskResult:
        """Calculate pure deterministic risk score (0-100) with complete provenance."""
        provenance: list[ProvenanceItem] = []
        vetoes: list[VetoFinding] = []

        # ---------------------------------------------------------------------
        # 1. Resolve Context Multiplier OMEGA
        # ---------------------------------------------------------------------
        # OMEGA: 1.0 default; 1.15 if submission port {465, 587}; 1.25 if cleartext creds
        # Maximum taken rather than compounding
        omega = Decimal("1.0")
        if params.cleartext_credentials_observed:
            omega = Decimal("1.25")
        elif params.dst_port in {465, 587}:
            omega = Decimal("1.15")

        # ---------------------------------------------------------------------
        # 2. Resolve Cipher Metadata
        # ---------------------------------------------------------------------
        cipher_info = params.cipher_info
        if cipher_info is None and params.cipher_id:
            cipher_info = self.cipher_db.get(params.cipher_id)

        # ---------------------------------------------------------------------
        # 3. Component C1: protocol_version
        # ---------------------------------------------------------------------
        p1_raw = 0
        proto_norm = params.protocol_version.upper().strip()

        if proto_norm in {"NONE", "PLAINTEXT", ""}:
            if params.has_auth or params.cleartext_credentials_observed:
                r = C1_RULES["no_tls_with_auth"]
                p1_raw = r.penalty
                vetoes.append(
                    VetoFinding(
                        r.rule_id,
                        r.penalty,
                        "Cleartext credentials on unencrypted session",
                        r.standards_ref,
                    )
                )
                provenance.append(
                    ProvenanceItem(
                        "protocol_version",
                        r.rule_id,
                        r.penalty,
                        "No TLS with authentication",
                        r.standards_ref,
                    )
                )
            else:
                r = C1_RULES["no_tls_plaintext"]
                p1_raw = r.penalty
                provenance.append(
                    ProvenanceItem(
                        "protocol_version",
                        r.rule_id,
                        r.penalty,
                        "Plaintext session without TLS",
                        r.standards_ref,
                    )
                )
        elif "SSL 2" in proto_norm or "SSLV2" in proto_norm:
            r = C1_RULES["ssl2"]
            p1_raw = r.penalty
            vetoes.append(VetoFinding(r.rule_id, r.penalty, "SSL 2.0 negotiated", r.standards_ref))
            provenance.append(
                ProvenanceItem(
                    "protocol_version", r.rule_id, r.penalty, "SSL 2.0 negotiated", r.standards_ref
                )
            )
        elif "SSL 3" in proto_norm or "SSLV3" in proto_norm:
            r = C1_RULES["ssl3"]
            p1_raw = r.penalty
            vetoes.append(VetoFinding(r.rule_id, r.penalty, "SSL 3.0 negotiated", r.standards_ref))
            provenance.append(
                ProvenanceItem(
                    "protocol_version", r.rule_id, r.penalty, "SSL 3.0 negotiated", r.standards_ref
                )
            )
        elif "TLS 1.0" in proto_norm or "TLSV1.0" in proto_norm:
            r = C1_RULES["tls10"]
            p1_raw = r.penalty
            provenance.append(
                ProvenanceItem(
                    "protocol_version", r.rule_id, r.penalty, "TLS 1.0 negotiated", r.standards_ref
                )
            )
        elif "TLS 1.1" in proto_norm or "TLSV1.1" in proto_norm:
            r = C1_RULES["tls11"]
            p1_raw = r.penalty
            provenance.append(
                ProvenanceItem(
                    "protocol_version", r.rule_id, r.penalty, "TLS 1.1 negotiated", r.standards_ref
                )
            )
        elif "TLS 1.2" in proto_norm or "TLSV1.2" in proto_norm:
            # Check if non-AEAD or non-PFS
            if cipher_info and (not cipher_info.aead or not cipher_info.pfs):
                r = C1_RULES["tls12_legacy"]
                p1_raw = r.penalty
                provenance.append(
                    ProvenanceItem(
                        "protocol_version",
                        r.rule_id,
                        r.penalty,
                        f"TLS 1.2 with non-AEAD/non-PFS ({cipher_info.name})",
                        r.standards_ref,
                    )
                )
            else:
                p1_raw = 0
        elif "TLS 1.3" in proto_norm or "TLSV1.3" in proto_norm:
            p1_raw = 0
        else:
            r = C1_RULES["unknown_version"]
            p1_raw = r.penalty
            provenance.append(
                ProvenanceItem(
                    "protocol_version",
                    r.rule_id,
                    r.penalty,
                    f"Unknown protocol version: {params.protocol_version}",
                    r.standards_ref,
                )
            )

        # ---------------------------------------------------------------------
        # 4. Component C2: cipher_hash (Sum capped at 100)
        # ---------------------------------------------------------------------
        p2_sum = 0
        if cipher_info:
            c_name = cipher_info.name.upper()
            c_enc = cipher_info.enc.upper()
            c_mac = cipher_info.mac.upper()

            # NULL
            if cipher_info.null_enc or "NULL" in c_enc or "NULL" in c_name:
                r = C2_RULES["null_cipher"]
                p2_sum += r.penalty
                vetoes.append(
                    VetoFinding(
                        r.rule_id, r.penalty, f"NULL cipher ({cipher_info.name})", r.standards_ref
                    )
                )
                provenance.append(
                    ProvenanceItem(
                        "cipher_hash",
                        r.rule_id,
                        r.penalty,
                        f"NULL cipher ({cipher_info.name})",
                        r.standards_ref,
                    )
                )

            # EXPORT
            if cipher_info.export or "EXPORT" in c_name or "EXP" in c_name:
                r = C2_RULES["export_cipher"]
                p2_sum += r.penalty
                vetoes.append(
                    VetoFinding(
                        r.rule_id, r.penalty, f"Export cipher ({cipher_info.name})", r.standards_ref
                    )
                )
                provenance.append(
                    ProvenanceItem(
                        "cipher_hash",
                        r.rule_id,
                        r.penalty,
                        f"Export cipher ({cipher_info.name})",
                        r.standards_ref,
                    )
                )

            # ANON
            if cipher_info.anon or "ANON" in c_name or "ANON" in cipher_info.kex.upper():
                r = C2_RULES["anon_cipher"]
                p2_sum += r.penalty
                vetoes.append(
                    VetoFinding(
                        r.rule_id,
                        r.penalty,
                        f"Anonymous cipher ({cipher_info.name})",
                        r.standards_ref,
                    )
                )
                provenance.append(
                    ProvenanceItem(
                        "cipher_hash",
                        r.rule_id,
                        r.penalty,
                        f"Anonymous cipher ({cipher_info.name})",
                        r.standards_ref,
                    )
                )

            # RC4
            if "RC4" in c_enc or "RC4" in c_name:
                r = C2_RULES["rc4"]
                p2_sum += r.penalty
                provenance.append(
                    ProvenanceItem(
                        "cipher_hash",
                        r.rule_id,
                        r.penalty,
                        f"RC4 cipher ({cipher_info.name})",
                        r.standards_ref,
                    )
                )

            # DES (single)
            if (
                "DES" in c_enc
                and "3DES" not in c_enc
                and "EDE" not in c_enc
                and "TRIPLE" not in c_enc
            ):
                r = C2_RULES["des"]
                p2_sum += r.penalty
                provenance.append(
                    ProvenanceItem(
                        "cipher_hash",
                        r.rule_id,
                        r.penalty,
                        f"Single DES cipher ({cipher_info.name})",
                        r.standards_ref,
                    )
                )

            # 3DES
            if "3DES" in c_enc or "EDE" in c_enc or "3DES" in c_name:
                r = C2_RULES["3des"]
                p2_sum += r.penalty
                provenance.append(
                    ProvenanceItem(
                        "cipher_hash",
                        r.rule_id,
                        r.penalty,
                        f"3DES cipher ({cipher_info.name})",
                        r.standards_ref,
                    )
                )

            # Legacy CBC (IDEA / SEED / Camellia)
            if any(k in c_name for k in ("IDEA", "SEED", "CAMELLIA")):
                r = C2_RULES["cbc_legacy"]
                p2_sum += r.penalty
                provenance.append(
                    ProvenanceItem(
                        "cipher_hash",
                        r.rule_id,
                        r.penalty,
                        f"Legacy CBC cipher ({cipher_info.name})",
                        r.standards_ref,
                    )
                )

            # MD5
            if "MD5" in c_mac or "MD5" in cipher_info.hash.upper():
                r = C2_RULES["md5"]
                p2_sum += r.penalty
                provenance.append(
                    ProvenanceItem(
                        "cipher_hash",
                        r.rule_id,
                        r.penalty,
                        f"MD5 hash ({cipher_info.name})",
                        r.standards_ref,
                    )
                )

            # SHA1 MAC
            if not cipher_info.aead and (
                "SHA1" in c_mac or "SHA" in c_mac or "SHA1" in cipher_info.hash.upper()
            ):
                r = C2_RULES["sha1_mac"]
                p2_sum += r.penalty
                provenance.append(
                    ProvenanceItem(
                        "cipher_hash",
                        r.rule_id,
                        r.penalty,
                        f"SHA-1 MAC ({cipher_info.name})",
                        r.standards_ref,
                    )
                )

            # CBC without EtM
            if "CBC" in c_enc and not cipher_info.aead and not params.encrypt_then_mac:
                r = C2_RULES["cbc_no_etm"]
                p2_sum += r.penalty
                provenance.append(
                    ProvenanceItem(
                        "cipher_hash",
                        r.rule_id,
                        r.penalty,
                        "CBC cipher without Encrypt-then-MAC",
                        r.standards_ref,
                    )
                )

        p2_raw = min(100, p2_sum)

        # ---------------------------------------------------------------------
        # 5. Component C3: key_exchange
        # ---------------------------------------------------------------------
        p3_raw = 0
        kex = params.kex_algorithm.upper().strip()
        named_grp = (params.named_group or "").lower().strip()

        if kex == "RSA":
            r = C3_RULES["static_rsa"]
            p3_raw = r.penalty
            provenance.append(
                ProvenanceItem(
                    "key_exchange",
                    r.rule_id,
                    r.penalty,
                    "Static RSA key transport",
                    r.standards_ref,
                )
            )
        elif kex == "DH" or kex == "STATIC_DH":
            r = C3_RULES["static_dh"]
            p3_raw = r.penalty
            provenance.append(
                ProvenanceItem(
                    "key_exchange", r.rule_id, r.penalty, "Static DH key exchange", r.standards_ref
                )
            )
        elif kex == "DHE":
            dh_bits = params.dh_key_bits or 1024
            if dh_bits < 1024:
                r = C3_RULES["dhe_logjam"]
                p3_raw = r.penalty
                vetoes.append(
                    VetoFinding(
                        r.rule_id, r.penalty, f"DHE p={dh_bits} bits (< 1024)", r.standards_ref
                    )
                )
                provenance.append(
                    ProvenanceItem(
                        "key_exchange",
                        r.rule_id,
                        r.penalty,
                        f"DHE p={dh_bits} bits (< 1024)",
                        r.standards_ref,
                    )
                )
            elif dh_bits < 2048:
                r = C3_RULES["dhe_weak"]
                p3_raw = r.penalty
                provenance.append(
                    ProvenanceItem(
                        "key_exchange",
                        r.rule_id,
                        r.penalty,
                        f"DHE p={dh_bits} bits (1024-2047)",
                        r.standards_ref,
                    )
                )
            else:
                r = C3_RULES["dhe_2048"]
                p3_raw = r.penalty
                provenance.append(
                    ProvenanceItem(
                        "key_exchange",
                        r.rule_id,
                        r.penalty,
                        f"DHE p={dh_bits} bits",
                        r.standards_ref,
                    )
                )
        elif kex == "ECDHE":
            if named_grp in {"secp192r1", "secp224r1"} or (
                params.ec_bits is not None and params.ec_bits < 256
            ):
                r = C3_RULES["ecdhe_weak_curve"]
                p3_raw = r.penalty
                provenance.append(
                    ProvenanceItem(
                        "key_exchange",
                        r.rule_id,
                        r.penalty,
                        f"Weak ECDHE curve ({named_grp or params.ec_bits} bits)",
                        r.standards_ref,
                    )
                )
            elif named_grp in {
                "x25519",
                "x448",
                "secp256r1",
                "secp384r1",
                "secp521r1",
                "prime256v1",
                "p-256",
                "p-384",
                "p-521",
            } or (params.ec_bits is not None and params.ec_bits >= 256):
                p3_raw = 0
            elif named_grp in {"unknown", "unrecognized", ""} and not params.ec_bits:
                r = C3_RULES["ecdhe_unknown_curve"]
                p3_raw = r.penalty
                provenance.append(
                    ProvenanceItem(
                        "key_exchange",
                        r.rule_id,
                        r.penalty,
                        "Unknown/unrecognized ECDHE named curve",
                        r.standards_ref,
                    )
                )

        # ---------------------------------------------------------------------
        # 6. Component C4: certificate (Sum capped at 100)
        # ---------------------------------------------------------------------
        p4_sum = 0
        cert = params.leaf_certificate
        chain_res = params.chain_validation_result
        host_res = params.hostname_verification_result

        if params.cert_analysis_possible and cert:
            # Compromised SPKI
            if params.known_compromised_spki:
                r = C4_RULES["compromised_key"]
                p4_sum += r.penalty
                vetoes.append(
                    VetoFinding(r.rule_id, r.penalty, "Known compromised SPKI", r.standards_ref)
                )
                provenance.append(
                    ProvenanceItem(
                        "certificate",
                        r.rule_id,
                        r.penalty,
                        "Known compromised SPKI",
                        r.standards_ref,
                    )
                )

            # Expiration / Not Yet Valid
            if chain_res and any(e.code == "CERT_EXPIRED" for e in chain_res.errors):
                r = C4_RULES["cert_expired"]
                p4_sum += r.penalty
                provenance.append(
                    ProvenanceItem(
                        "certificate",
                        r.rule_id,
                        r.penalty,
                        "Certificate expired at capture time",
                        r.standards_ref,
                    )
                )
            elif chain_res and any(e.code == "CERT_NOT_YET_VALID" for e in chain_res.errors):
                r = C4_RULES["cert_not_yet_valid"]
                p4_sum += r.penalty
                provenance.append(
                    ProvenanceItem(
                        "certificate",
                        r.rule_id,
                        r.penalty,
                        "Certificate not yet valid at capture time",
                        r.standards_ref,
                    )
                )

            # Self-signed
            if cert.is_self_signed or (chain_res and chain_res.anchor_source == "self_signed"):
                r = C4_RULES["self_signed_untrusted"]
                p4_sum += r.penalty
                provenance.append(
                    ProvenanceItem(
                        "certificate",
                        r.rule_id,
                        r.penalty,
                        "Untrusted self-signed certificate",
                        r.standards_ref,
                    )
                )
            elif (
                chain_res
                and not chain_res.is_valid
                and any(e.code == "UNTRUSTED_ROOT" for e in chain_res.errors)
            ):
                r = C4_RULES["chain_untrusted"]
                p4_sum += r.penalty
                provenance.append(
                    ProvenanceItem(
                        "certificate",
                        r.rule_id,
                        r.penalty,
                        "Untrusted certificate chain",
                        r.standards_ref,
                    )
                )

            # Hostname mismatch
            if host_res and host_res.status == "MISMATCH":
                r = C4_RULES["hostname_mismatch"]
                p4_sum += r.penalty
                provenance.append(
                    ProvenanceItem(
                        "certificate",
                        r.rule_id,
                        r.penalty,
                        f"Hostname mismatch ({host_res.reference_identifier})",
                        r.standards_ref,
                    )
                )

            # Key size
            if cert.public_key_algorithm == "RSA":
                if cert.public_key_bits < 1024:
                    r = C4_RULES["rsa_weak_512"]
                    p4_sum += r.penalty
                    vetoes.append(
                        VetoFinding(
                            r.rule_id,
                            r.penalty,
                            f"RSA key size {cert.public_key_bits} bits (< 1024)",
                            r.standards_ref,
                        )
                    )
                    provenance.append(
                        ProvenanceItem(
                            "certificate",
                            r.rule_id,
                            r.penalty,
                            f"RSA key size {cert.public_key_bits} bits (< 1024)",
                            r.standards_ref,
                        )
                    )
                elif cert.public_key_bits < 2048:
                    r = C4_RULES["rsa_weak_1024"]
                    p4_sum += r.penalty
                    provenance.append(
                        ProvenanceItem(
                            "certificate",
                            r.rule_id,
                            r.penalty,
                            f"RSA key size {cert.public_key_bits} bits (1024-2047)",
                            r.standards_ref,
                        )
                    )
            elif cert.public_key_algorithm == "ECDSA" and cert.public_key_bits < 224:
                r = C4_RULES["ecdsa_weak"]
                p4_sum += r.penalty
                provenance.append(
                    ProvenanceItem(
                        "certificate",
                        r.rule_id,
                        r.penalty,
                        f"ECDSA key size {cert.public_key_bits} bits (< 224)",
                        r.standards_ref,
                    )
                )

            # Signature hash
            sig_h = (cert.signature_hash or "").upper()
            if "MD5" in sig_h:
                r = C4_RULES["md5_sig"]
                p4_sum += r.penalty
                vetoes.append(
                    VetoFinding(
                        r.rule_id, r.penalty, "Certificate signed with MD5", r.standards_ref
                    )
                )
                provenance.append(
                    ProvenanceItem(
                        "certificate",
                        r.rule_id,
                        r.penalty,
                        "Certificate signed with MD5",
                        r.standards_ref,
                    )
                )
            elif "SHA1" in sig_h or (
                chain_res and any(e.code == "WEAK_HASH_ALGO" for e in chain_res.errors)
            ):
                r = C4_RULES["sha1_sig"]
                p4_sum += r.penalty
                provenance.append(
                    ProvenanceItem(
                        "certificate",
                        r.rule_id,
                        r.penalty,
                        "Certificate signed with SHA-1",
                        r.standards_ref,
                    )
                )

            # Revocation
            if chain_res and (
                chain_res.ocsp_status == "REVOKED"
                or chain_res.crl_status == "REVOKED"
                or any(
                    e.code in {"CERT_REVOKED", "OCSP_REVOKED", "CRL_REVOKED"}
                    for e in chain_res.errors
                )
            ):
                r = C4_RULES["revoked"]
                p4_sum += r.penalty
                vetoes.append(
                    VetoFinding(r.rule_id, r.penalty, "Certificate is revoked", r.standards_ref)
                )
                provenance.append(
                    ProvenanceItem(
                        "certificate", r.rule_id, r.penalty, "Certificate revoked", r.standards_ref
                    )
                )
            elif (
                chain_res
                and chain_res.ocsp_status == "UNKNOWN"
                and chain_res.crl_status == "UNKNOWN"
                and chain_res.is_valid
            ):
                r = C4_RULES["revocation_unknown"]
                p4_sum += r.penalty
                provenance.append(
                    ProvenanceItem(
                        "certificate",
                        r.rule_id,
                        r.penalty,
                        "Revocation status unknown (offline cache miss)",
                        r.standards_ref,
                    )
                )

            # Lifetime
            if cert.lifetime_days > 825:
                r = C4_RULES["lifetime_825"]
                p4_sum += r.penalty
                provenance.append(
                    ProvenanceItem(
                        "certificate",
                        r.rule_id,
                        r.penalty,
                        f"Certificate lifetime {cert.lifetime_days}d (> 825d)",
                        r.standards_ref,
                    )
                )
            elif cert.lifetime_days > 398:
                r = C4_RULES["lifetime_398"]
                p4_sum += r.penalty
                provenance.append(
                    ProvenanceItem(
                        "certificate",
                        r.rule_id,
                        r.penalty,
                        f"Certificate lifetime {cert.lifetime_days}d (> 398d)",
                        r.standards_ref,
                    )
                )

            # CA basic constraints
            if (
                cert.basic_constraints.get("ca")
                and "path_length" not in cert.basic_constraints
                and chain_res
                and any(e.code == "INVALID_CA_CERT" for e in chain_res.errors)
            ):
                r = C4_RULES["ca_no_basic_constraints"]
                p4_sum += r.penalty
                provenance.append(
                    ProvenanceItem(
                        "certificate",
                        r.rule_id,
                        r.penalty,
                        "CA missing basicConstraints",
                        r.standards_ref,
                    )
                )

            # SAN extension
            if not cert.san_dns and not cert.san_ip:
                r = C4_RULES["no_san"]
                p4_sum += r.penalty
                provenance.append(
                    ProvenanceItem(
                        "certificate",
                        r.rule_id,
                        r.penalty,
                        "Certificate missing SAN extension",
                        r.standards_ref,
                    )
                )

            # SCT count
            if cert.sct_count == 0:
                r = C4_RULES["no_sct"]
                p4_sum += r.penalty
                provenance.append(
                    ProvenanceItem(
                        "certificate",
                        r.rule_id,
                        r.penalty,
                        "Zero SCT timestamps in certificate",
                        r.standards_ref,
                    )
                )

        p4_raw = min(100, p4_sum)

        # ---------------------------------------------------------------------
        # 7. Component C5: session_hygiene (Sum capped at 100)
        # ---------------------------------------------------------------------
        p5_sum = 0
        if (
            not params.secure_renegotiation
            and "TLS 1.3" not in proto_norm
            and proto_norm not in {"NONE", "PLAINTEXT", ""}
        ):
            r = C5_RULES["reneg_insecure"]
            p5_sum += r.penalty
            provenance.append(
                ProvenanceItem(
                    "session_hygiene",
                    r.rule_id,
                    r.penalty,
                    "Insecure renegotiation without RFC 5746",
                    r.standards_ref,
                )
            )

        if not params.extended_master_secret and (
            "TLS 1.2" in proto_norm or "TLSV1.2" in proto_norm
        ):
            r = C5_RULES["no_ems"]
            p5_sum += r.penalty
            provenance.append(
                ProvenanceItem(
                    "session_hygiene",
                    r.rule_id,
                    r.penalty,
                    "TLS 1.2 without Extended Master Secret",
                    r.standards_ref,
                )
            )

        if params.compression_method != 0:
            r = C5_RULES["compression"]
            p5_sum += r.penalty
            provenance.append(
                ProvenanceItem(
                    "session_hygiene",
                    r.rule_id,
                    r.penalty,
                    f"TLS compression enabled (method={params.compression_method})",
                    r.standards_ref,
                )
            )

        if params.ticket_lifetime_seconds and params.ticket_lifetime_seconds > 604800:
            r = C5_RULES["long_ticket"]
            p5_sum += r.penalty
            provenance.append(
                ProvenanceItem(
                    "session_hygiene",
                    r.rule_id,
                    r.penalty,
                    f"Session ticket lifetime {params.ticket_lifetime_seconds}s (> 7d)",
                    r.standards_ref,
                )
            )

        if params.zero_rtt_used and params.dst_port in {465, 587}:
            r = C5_RULES["zero_rtt_submission"]
            p5_sum += r.penalty
            provenance.append(
                ProvenanceItem(
                    "session_hygiene",
                    r.rule_id,
                    r.penalty,
                    f"0-RTT early data on submission port {params.dst_port}",
                    r.standards_ref,
                )
            )

        if not params.handshake_completed and proto_norm not in {"NONE", "PLAINTEXT", ""}:
            r = C5_RULES["incomplete_handshake"]
            p5_sum += r.penalty
            provenance.append(
                ProvenanceItem(
                    "session_hygiene",
                    r.rule_id,
                    r.penalty,
                    "TLS handshake never completed",
                    r.standards_ref,
                )
            )

        p5_raw = min(100, p5_sum)

        # ---------------------------------------------------------------------
        # 8. Effective Strength Gate (S_eff)
        # S_eff = min(S_sym, S_kex, S_auth, S_hash // 2)
        # ---------------------------------------------------------------------
        s_sym = (
            cipher_info.enc_bits
            if cipher_info
            else (0 if proto_norm in {"NONE", "PLAINTEXT", ""} else 128)
        )

        # KEX strength
        if kex == "RSA":
            s_kex = (
                rsa_security_bits(cert.public_key_bits)
                if cert and cert.public_key_algorithm == "RSA"
                else 80
            )
        elif kex == "DHE":
            s_kex = rsa_security_bits(params.dh_key_bits or 1024)
        elif kex == "ECDHE":
            s_kex = ecc_security_bits(params.ec_bits or 256)
        elif proto_norm in {"NONE", "PLAINTEXT", ""}:
            s_kex = 0
        else:
            s_kex = 128

        # Auth strength
        if cipher_info and cipher_info.anon:
            s_auth = 0
        elif cert:
            if cert.public_key_algorithm == "RSA":
                s_auth = rsa_security_bits(cert.public_key_bits)
            elif cert.public_key_algorithm == "ECDSA":
                s_auth = ecc_security_bits(cert.public_key_bits)
            else:
                s_auth = 112
        elif proto_norm in {"NONE", "PLAINTEXT", ""}:
            s_auth = 0
        else:
            s_auth = 128

        # Hash strength
        hash_name = cipher_info.hash if cipher_info else "SHA256"
        s_hash_coll = hash_security_bits(hash_name)

        s_eff = min(s_sym, s_kex, s_auth, s_hash_coll)

        if s_eff < 112 and proto_norm not in {"NONE", "PLAINTEXT", ""}:
            r = RULE_MIN_STRENGTH
            vetoes.append(
                VetoFinding(
                    r.rule_id,
                    r.penalty,
                    f"Effective strength S_eff={s_eff} bits (< 112 bits)",
                    r.standards_ref,
                )
            )
            provenance.append(
                ProvenanceItem(
                    "strength_gate",
                    r.rule_id,
                    r.penalty,
                    f"S_eff={s_eff} bits (< 112 bits threshold)",
                    r.standards_ref,
                )
            )

        # ---------------------------------------------------------------------
        # 9. Weight Resolution & Redistribution
        # ---------------------------------------------------------------------
        weight_redistributed = False
        if params.cert_analysis_possible:
            applied_weights = dict(BASE_WEIGHTS)
            raw_scores = {
                "protocol_version": p1_raw,
                "cipher_hash": p2_raw,
                "key_exchange": p3_raw,
                "certificate": p4_raw,
                "session_hygiene": p5_raw,
            }
        else:
            # TLS 1.3: C4 dropped, redistributed across C1, C2, C3, C5
            weight_redistributed = True
            applied_weights = dict(TLS13_REDISTRIBUTED_WEIGHTS)
            raw_scores = {
                "protocol_version": p1_raw,
                "cipher_hash": p2_raw,
                "key_exchange": p3_raw,
                "session_hygiene": p5_raw,
            }

        # ---------------------------------------------------------------------
        # 10. Formula Calculation with Exact Decimal Rounding
        # R = min(100, max( max(veto_i), OMEGA * sum(w_c * p_c) ))
        # ---------------------------------------------------------------------
        weighted_sum = sum(
            applied_weights[comp] * Decimal(str(score)) for comp, score in raw_scores.items()
        )
        calculated_raw = omega * weighted_sum
        calculated_int = int(calculated_raw.quantize(Decimal("1"), rounding=ROUND_HALF_EVEN))

        max_veto = max((v.floor_score for v in vetoes), default=0)
        final_score = min(100, max(max_veto, calculated_int))

        # ---------------------------------------------------------------------
        # 11. Bands: 0-19 SECURE, 20-39 ACCEPTABLE, 40-59 WEAK, 60-79 HIGH, 80-100 CRITICAL
        # ---------------------------------------------------------------------
        if final_score <= 19:
            band = "SECURE"
        elif final_score <= 39:
            band = "ACCEPTABLE"
        elif final_score <= 59:
            band = "WEAK"
        elif final_score <= 79:
            band = "HIGH"
        else:
            band = "CRITICAL"

        # Deterministic sort for provenance items and vetoes
        sorted_provenance = sorted(provenance, key=lambda x: (x.component, x.rule_id, x.penalty))
        sorted_vetoes = sorted(vetoes, key=lambda x: (x.rule_id, x.floor_score))

        return RiskResult(
            score=final_score,
            band=band,
            context_multiplier=float(omega),
            component_scores=raw_scores,
            component_weights={k: float(v) for k, v in applied_weights.items()},
            vetoes=sorted_vetoes,
            effective_security_bits=s_eff,
            weight_redistributed=weight_redistributed,
            provenance=sorted_provenance,
        )
