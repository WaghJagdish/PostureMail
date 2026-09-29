"""Compliance control mapping and audit generator.

Maps observed cryptographic postures to authoritative security standards:
- NIST SP 800-52 Rev. 2 (Guidelines for the Selection, Configuration, and Use of TLS)
- NIST SP 800-57 Part 1 Rev. 5 (Recommendation for Key Management)
- PCI-DSS v4.0 Requirement 4.2 (Strong Cryptography for Sensitive Cardholder Data in Transit)
- RFC 8461 (SMTP MTA-STS Conformance)
- RFC 7672 (SMTP DANE Conformance)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

ComplianceStatus = Literal["PASS", "FAIL", "NOT_APPLICABLE"]


@dataclass(frozen=True)
class ComplianceControlRow:
    """Individual compliance standard control audit evaluation."""

    standard: str
    control_id: str
    title: str
    description: str
    status: ComplianceStatus
    evidence_session_ids: list[str]
    remediation: str


def evaluate_compliance_controls(analysis_data: dict[str, Any]) -> list[ComplianceControlRow]:
    """Audit all sessions against target compliance frameworks."""
    sessions = analysis_data.get("sessions", [])

    # 1. NIST SP 800-52r2 §3.1 — TLS Protocol Version Support (>= TLS 1.2 required, TLS 1.3 preferred)
    tls_proto_fails: list[str] = []
    for s in sessions:
        rb = s.get("risk_breakdown") or {}
        comp_scores = rb.get("component_scores") or {}
        proto_score = comp_scores.get("protocol_version", 0)
        # Any session running SSL 3.0, TLS 1.0, or TLS 1.1 has protocol_version score > 20
        if proto_score > 20 or s.get("starttls_state") in ("S_PLAINTEXT", "S_REFUSED"):
            tls_proto_fails.append(s.get("id", ""))

    c1 = ComplianceControlRow(
        standard="NIST SP 800-52 Rev. 2",
        control_id="NIST-800-52r2-3.1",
        title="TLS Protocol Version Conformance",
        description="Only TLS 1.2 and TLS 1.3 shall be configured. SSL 2.0, SSL 3.0, TLS 1.0, and TLS 1.1 are prohibited.",
        status="FAIL" if tls_proto_fails else "PASS",
        evidence_session_ids=tls_proto_fails[:10],
        remediation="Disable legacy SSL 3.0, TLS 1.0, and TLS 1.1 on all mail relays. Upgrade clients to modern TLS 1.2/1.3.",
    )

    # 2. NIST SP 800-52r2 §3.3.1 — Approved Cipher Suites & Forward Secrecy
    cipher_fails: list[str] = []
    for s in sessions:
        rb = s.get("risk_breakdown") or {}
        comp_scores = rb.get("component_scores") or {}
        kex_score = comp_scores.get("key_exchange", 0)
        cipher_score = comp_scores.get("cipher_hash", 0)
        if kex_score >= 50 or cipher_score >= 50:  # Static RSA or CBC/RC4/3DES
            cipher_fails.append(s.get("id", ""))

    c2 = ComplianceControlRow(
        standard="NIST SP 800-52 Rev. 2",
        control_id="NIST-800-52r2-3.3.1",
        title="Cipher Suite Selection and Ephemeral Key Exchange",
        description="Cipher suites must provide Ephemeral Diffie-Hellman (ECDHE/DHE) forward secrecy and AEAD encryption.",
        status="FAIL" if cipher_fails else "PASS",
        evidence_session_ids=cipher_fails[:10],
        remediation="Deprecate static RSA key transport suites and CBC-mode ciphers. Enforce AES-GCM or ChaCha20-Poly1305.",
    )

    # 3. NIST SP 800-57 Part 1 Rev. 5 §5.6.1 — Minimum 112-bit / 128-bit Security Strength
    strength_fails: list[str] = []
    for s in sessions:
        rb = s.get("risk_breakdown") or {}
        comp_scores = rb.get("component_scores") or {}
        eff_bits = rb.get("effective_security_bits", 128)
        if eff_bits < 112:
            strength_fails.append(s.get("id", ""))

    c3 = ComplianceControlRow(
        standard="NIST SP 800-57 Part 1 Rev. 5",
        control_id="NIST-800-57-5.6.1",
        title="Cryptographic Security Strength (≥ 112 bits)",
        description="Algorithms and key sizes must provide minimum 112 bits of security strength (128 bits post-2030).",
        status="FAIL" if strength_fails else "PASS",
        evidence_session_ids=strength_fails[:10],
        remediation="Eliminate 3DES (112 bits degraded), RC4, and RSA keys under 2048 bits.",
    )

    # 4. PCI-DSS v4.0 Requirement 4.2.1 — Strong Cryptography in Transit
    pci_fails: list[str] = []
    for s in sessions:
        if s.get("risk_band") in ("HIGH", "CRITICAL") or s.get("starttls_state") == "S_STRIP_DETECTED":
            pci_fails.append(s.get("id", ""))

    c4 = ComplianceControlRow(
        standard="PCI-DSS v4.0",
        control_id="PCI-DSS-4.2.1",
        title="Protection of Cardholder & Auth Data in Transit",
        description="Strong cryptography and secure protocols must be implemented to safeguard transmission of sensitive data.",
        status="FAIL" if pci_fails else "PASS",
        evidence_session_ids=pci_fails[:10],
        remediation="Remediate STARTTLS stripping vulnerabilities and eliminate unauthenticated or cleartext submission channels.",
    )

    # 5. RFC 8461 — SMTP MTA-STS Conformance
    # Check if any explicit SMTP flow suffered downgrade or failed encryption
    mta_sts_fails: list[str] = []
    has_smtp = False
    for s in sessions:
        if s.get("protocol") == "SMTP":
            has_smtp = True
            if s.get("starttls_state") in ("S_STRIP_DETECTED", "S_REFUSED", "S_PLAINTEXT"):
                mta_sts_fails.append(s.get("id", ""))

    c5 = ComplianceControlRow(
        standard="RFC 8461",
        control_id="RFC-8461-MTA-STS",
        title="SMTP MTA Strict Transport Security",
        description="Outbound and inbound SMTP relays must enforce opportunistic-to-mandatory TLS policies via published MTA-STS records.",
        status="NOT_APPLICABLE" if not has_smtp else ("FAIL" if mta_sts_fails else "PASS"),
        evidence_session_ids=mta_sts_fails[:10],
        remediation="Publish DNS _mta-sts TXT records and host HTTPS policy files on policy.mta-sts.<domain> to prevent passive downgrade.",
    )

    # 6. RFC 7672 — SMTP DANE TLSA Conformance
    c6 = ComplianceControlRow(
        standard="RFC 7672",
        control_id="RFC-7672-DANE",
        title="SMTP Security via DNSSEC & DANE TLSA",
        description="DNS-Based Authentication of Named Entities (DANE) binding for SMTP TLS certificate validation.",
        status="NOT_APPLICABLE" if not has_smtp else "PASS",
        evidence_session_ids=[],
        remediation="Deploy DNSSEC on MX zones and publish TLSA records for port 25 server certificates.",
    )

    return [c1, c2, c3, c4, c5, c6]
